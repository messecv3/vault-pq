//! Dead-man switch / canary system.
//!
//! Creates vault files with a time-based canary mechanism:
//!
//! - A canary file contains an encrypted payload + a check-in schedule
//! - The owner must periodically "check in" by re-signing the canary
//! - If the check-in deadline passes, the canary is considered "dead"
//! - External systems can verify canary liveness without decrypting
//!
//! # Use Cases
//!
//! - Warrant canary: proves no government order has been received
//! - Dead-man switch: release information if the owner becomes unreachable
//! - Proof of life: cryptographic evidence the owner is still active
//!
//! # Design
//!
//! The canary file contains:
//! - A signed timestamp of the last check-in
//! - The check-in interval (e.g., "every 7 days")
//! - A public verifying key (anyone can verify the canary is alive)
//! - The actual encrypted payload (only released when canary dies)

use std::time::{SystemTime, UNIX_EPOCH};
use crate::crypto::sig::{SigningKeyPair, FileSignature};
use crate::error::VaultError;

/// A canary record — the publicly visible part.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CanaryRecord {
    /// Unix timestamp of last check-in
    pub last_checkin: u64,
    /// Check-in interval in seconds
    pub interval_secs: u64,
    /// Ed25519 verifying key of the canary owner
    pub verifying_key: [u8; 32],
    /// Signature over (last_checkin || interval_secs || verifying_key)
    pub signature: FileSignature,
    /// Optional message (plaintext, publicly visible)
    pub message: Option<String>,
}

impl CanaryRecord {
    /// Check if the canary is still alive (check-in not expired).
    pub fn is_alive(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now < self.last_checkin + self.interval_secs
    }

    /// Seconds until the canary expires. Returns 0 if already expired.
    pub fn seconds_remaining(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let deadline = self.last_checkin + self.interval_secs;
        deadline.saturating_sub(now)
    }

    /// Verify the signature is valid.
    pub fn verify(&self) -> Result<(), VaultError> {
        let msg = self.signed_message();
        self.signature.verify(&msg)
    }

    /// Build the message that was signed.
    fn signed_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"vault-canary-v1");
        msg.extend_from_slice(&self.last_checkin.to_le_bytes());
        msg.extend_from_slice(&self.interval_secs.to_le_bytes());
        msg.extend_from_slice(&self.verifying_key);
        if let Some(ref m) = self.message {
            msg.extend_from_slice(m.as_bytes());
        }
        msg
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, VaultError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| VaultError::InvalidFormat(format!("canary serialization: {}", e)))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, VaultError> {
        serde_json::from_str(json)
            .map_err(|e| VaultError::InvalidFormat(format!("canary deserialization: {}", e)))
    }
}

/// Create a new canary.
///
/// - `interval_secs`: how often the owner must check in (e.g., 7*86400 for weekly)
/// - `message`: optional public message (e.g., "No government orders received")
pub fn create_canary(
    signing_key: &SigningKeyPair,
    interval_secs: u64,
    message: Option<String>,
) -> CanaryRecord {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut record = CanaryRecord {
        last_checkin: now,
        interval_secs,
        verifying_key: signing_key.verifying.to_bytes(),
        signature: FileSignature {
            ed25519: vec![0; 64], // placeholder
            verifying_key: signing_key.verifying.to_bytes(),
        },
        message,
    };

    // Sign
    let msg = record.signed_message();
    record.signature = signing_key.sign(&msg);

    record
}

/// Check in — refresh the canary with a new timestamp.
///
/// Requires the signing key (proves the owner is still active).
pub fn checkin(
    signing_key: &SigningKeyPair,
    existing: &CanaryRecord,
) -> Result<CanaryRecord, VaultError> {
    // Verify the signing key matches the canary's verifying key
    if signing_key.verifying.to_bytes() != existing.verifying_key {
        return Err(VaultError::InvalidKey(
            "signing key does not match canary owner".into()
        ));
    }

    Ok(create_canary(
        signing_key,
        existing.interval_secs,
        existing.message.clone(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify() {
        let kp = SigningKeyPair::generate();
        let canary = create_canary(&kp, 86400, Some("All clear.".into()));

        assert!(canary.is_alive());
        assert!(canary.verify().is_ok());
        assert!(canary.seconds_remaining() > 86000);
    }

    #[test]
    fn test_expired_canary() {
        let kp = SigningKeyPair::generate();
        let mut canary = create_canary(&kp, 1, None); // 1 second interval

        // Backdate to make it expired
        canary.last_checkin = 0; // Unix epoch — definitely expired
        // Re-sign with the backdated timestamp
        let msg = canary.signed_message();
        canary.signature = kp.sign(&msg);

        assert!(!canary.is_alive());
        assert_eq!(canary.seconds_remaining(), 0);
        // Signature should still verify (it's correctly signed, just expired)
        assert!(canary.verify().is_ok());
    }

    #[test]
    fn test_tampered_canary_fails_verify() {
        let kp = SigningKeyPair::generate();
        let mut canary = create_canary(&kp, 86400, None);

        // Tamper: extend the deadline
        canary.interval_secs = 999999999;

        // Signature verification should fail (message changed)
        assert!(canary.verify().is_err());
    }

    #[test]
    fn test_checkin_refreshes() {
        let kp = SigningKeyPair::generate();
        let canary = create_canary(&kp, 86400, Some("OK".into()));
        let old_checkin = canary.last_checkin;

        // Small sleep to ensure timestamp differs
        std::thread::sleep(std::time::Duration::from_millis(10));

        let refreshed = checkin(&kp, &canary).unwrap();
        assert!(refreshed.last_checkin >= old_checkin);
        assert!(refreshed.verify().is_ok());
        assert!(refreshed.is_alive());
    }

    #[test]
    fn test_wrong_key_checkin_fails() {
        let kp1 = SigningKeyPair::generate();
        let kp2 = SigningKeyPair::generate();

        let canary = create_canary(&kp1, 86400, None);
        let result = checkin(&kp2, &canary);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_round_trip() {
        let kp = SigningKeyPair::generate();
        let canary = create_canary(&kp, 604800, Some("No warrants received.".into()));

        let json = canary.to_json().unwrap();
        let restored = CanaryRecord::from_json(&json).unwrap();

        assert_eq!(restored.last_checkin, canary.last_checkin);
        assert_eq!(restored.interval_secs, canary.interval_secs);
        assert_eq!(restored.message, canary.message);
        assert!(restored.verify().is_ok());
    }
}
