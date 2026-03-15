//! License key generation and validation.
//!
//! A license key is a signed JSON document containing:
//! - Licensee info (name, email, organization)
//! - License tier (Community, Professional, Enterprise)
//! - Machine fingerprint (binds to one machine)
//! - Issue date and expiry date
//! - Ed25519 signature from the project's signing key
//!
//! # Key Format
//!
//! The license file is `~/.vault/license.json`:
//! ```json
//! {
//!   "licensee": { "name": "Alice", "email": "alice@example.com", "org": "ACME" },
//!   "tier": "community",
//!   "machine_id": "a1b2c3d4e5f6a7b8",
//!   "issued_at": 1710000000,
//!   "expires_at": 0,
//!   "features": ["core", "search", "panel"],
//!   "signature": "base64..."
//! }
//! ```
//!
//! Community licenses never expire (expires_at = 0).
//! The signature covers all fields except itself.

use crate::crypto::sig::SigningKeyPair;
use crate::license::fingerprint::MachineFingerprint;
use crate::error::VaultError;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// License tiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    /// Free, full functionality, no expiry.
    Community,
    /// Paid, additional support, annual renewal.
    Professional,
    /// Organization-wide, priority support, custom features.
    Enterprise,
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Community => write!(f, "Community"),
            Self::Professional => write!(f, "Professional"),
            Self::Enterprise => write!(f, "Enterprise"),
        }
    }
}

/// Licensee information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Licensee {
    pub name: String,
    pub email: String,
    #[serde(default)]
    pub organization: Option<String>,
}

/// A complete license.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct License {
    pub licensee: Licensee,
    pub tier: LicenseTier,
    /// Machine fingerprint (short hex ID).
    pub machine_id: String,
    /// Unix timestamp of issue.
    pub issued_at: u64,
    /// Unix timestamp of expiry (0 = never).
    pub expires_at: u64,
    /// Enabled feature keys.
    pub features: Vec<String>,
    /// Ed25519 signature over all fields above (base64).
    pub signature: String,
}

impl License {
    /// Check if the license is expired.
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false; // Never expires
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Check if the license is valid for the current machine.
    pub fn is_valid_machine(&self) -> bool {
        let current = MachineFingerprint::current();
        self.machine_id == current.short_id()
    }

    /// Verify the signature using the project's public key.
    pub fn verify_signature(&self, verifying_key: &[u8; 32]) -> Result<(), VaultError> {
        let msg = self.signable_message();

        let sig_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            &self.signature,
        ).map_err(|_| VaultError::InvalidKey("invalid license signature encoding".into()))?;

        let file_sig = crate::crypto::sig::FileSignature {
            ed25519: sig_bytes,
            verifying_key: *verifying_key,
        };

        file_sig.verify(&msg)
    }

    /// Check if a specific feature is enabled.
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// Build the message that is signed (all fields except signature).
    fn signable_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"vault-license-v1");
        msg.extend_from_slice(self.licensee.name.as_bytes());
        msg.extend_from_slice(self.licensee.email.as_bytes());
        if let Some(ref org) = self.licensee.organization {
            msg.extend_from_slice(org.as_bytes());
        }
        msg.extend_from_slice(format!("{:?}", self.tier).as_bytes());
        msg.extend_from_slice(self.machine_id.as_bytes());
        msg.extend_from_slice(&self.issued_at.to_le_bytes());
        msg.extend_from_slice(&self.expires_at.to_le_bytes());
        for feature in &self.features {
            msg.extend_from_slice(feature.as_bytes());
        }
        msg
    }

    /// Full validation: signature + machine + expiry.
    pub fn validate(&self, verifying_key: &[u8; 32]) -> LicenseValidation {
        // Check signature
        if let Err(_) = self.verify_signature(verifying_key) {
            return LicenseValidation {
                valid: false,
                reason: "Invalid signature — license may be tampered".into(),
                tier: self.tier.clone(),
                days_remaining: None,
            };
        }

        // Check machine
        if !self.is_valid_machine() {
            return LicenseValidation {
                valid: false,
                reason: format!(
                    "Machine mismatch — licensed for '{}', running on '{}'",
                    self.machine_id,
                    MachineFingerprint::current().short_id()
                ),
                tier: self.tier.clone(),
                days_remaining: None,
            };
        }

        // Check expiry
        if self.is_expired() {
            return LicenseValidation {
                valid: false,
                reason: "License expired".into(),
                tier: self.tier.clone(),
                days_remaining: Some(0),
            };
        }

        let days_remaining = if self.expires_at == 0 {
            None // Perpetual
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Some(((self.expires_at - now) / 86400) as u32)
        };

        LicenseValidation {
            valid: true,
            reason: "License valid".into(),
            tier: self.tier.clone(),
            days_remaining,
        }
    }
}

/// Result of license validation.
#[derive(Clone, Debug)]
pub struct LicenseValidation {
    pub valid: bool,
    pub reason: String,
    pub tier: LicenseTier,
    pub days_remaining: Option<u32>,
}

impl std::fmt::Display for LicenseValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.valid {
            write!(f, "Valid ({}", self.tier)?;
            if let Some(days) = self.days_remaining {
                write!(f, ", {} days remaining", days)?;
            } else {
                write!(f, ", perpetual")?;
            }
            write!(f, ")")
        } else {
            write!(f, "Invalid: {}", self.reason)
        }
    }
}

/// Generate a new license and sign it.
pub fn generate_license(
    signing_key: &SigningKeyPair,
    licensee: Licensee,
    tier: LicenseTier,
    duration_days: Option<u32>,
) -> License {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expires_at = match duration_days {
        Some(days) => now + (days as u64 * 86400),
        None => 0, // Perpetual
    };

    let features = match tier {
        LicenseTier::Community => vec![
            "core".into(), "search".into(), "panel".into(),
            "audit".into(), "bench".into(), "probes".into(),
        ],
        LicenseTier::Professional => vec![
            "core".into(), "search".into(), "panel".into(),
            "audit".into(), "bench".into(), "probes".into(),
            "deniable".into(), "honeypot".into(), "canary".into(),
            "archive".into(), "armor".into(), "priority-support".into(),
        ],
        LicenseTier::Enterprise => vec![
            "core".into(), "search".into(), "panel".into(),
            "audit".into(), "bench".into(), "probes".into(),
            "deniable".into(), "honeypot".into(), "canary".into(),
            "archive".into(), "armor".into(), "priority-support".into(),
            "custom-branding".into(), "multi-machine".into(),
            "api-access".into(), "sla".into(),
        ],
    };

    let machine_id = MachineFingerprint::current().short_id();

    let mut license = License {
        licensee,
        tier,
        machine_id,
        issued_at: now,
        expires_at,
        features,
        signature: String::new(),
    };

    // Sign
    let msg = license.signable_message();
    let sig = signing_key.sign(&msg);
    license.signature = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &sig.ed25519,
    );

    license
}

/// Default features for Community tier (no license required).
pub fn community_features() -> Vec<String> {
    vec![
        "core".into(), "search".into(), "panel".into(),
        "audit".into(), "bench".into(), "probes".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key() -> SigningKeyPair {
        SigningKeyPair::generate()
    }

    #[test]
    fn test_generate_community_license() {
        let sk = test_signing_key();
        let license = generate_license(
            &sk,
            Licensee {
                name: "Test User".into(),
                email: "test@example.com".into(),
                organization: None,
            },
            LicenseTier::Community,
            None, // perpetual
        );

        assert_eq!(license.tier, LicenseTier::Community);
        assert_eq!(license.expires_at, 0);
        assert!(license.has_feature("core"));
        assert!(license.has_feature("search"));
        assert!(!license.has_feature("deniable")); // Pro only
    }

    #[test]
    fn test_license_signature_valid() {
        let sk = test_signing_key();
        let vk = sk.verifying.to_bytes();

        let license = generate_license(
            &sk,
            Licensee {
                name: "Alice".into(),
                email: "alice@example.com".into(),
                organization: Some("ACME Corp".into()),
            },
            LicenseTier::Professional,
            Some(365),
        );

        assert!(license.verify_signature(&vk).is_ok());
    }

    #[test]
    fn test_tampered_license_fails() {
        let sk = test_signing_key();
        let vk = sk.verifying.to_bytes();

        let mut license = generate_license(
            &sk,
            Licensee { name: "Bob".into(), email: "bob@test.com".into(), organization: None },
            LicenseTier::Community,
            None,
        );

        // Tamper: change the tier
        license.tier = LicenseTier::Enterprise;
        assert!(license.verify_signature(&vk).is_err());
    }

    #[test]
    fn test_machine_binding() {
        let sk = test_signing_key();
        let license = generate_license(
            &sk,
            Licensee { name: "Test".into(), email: "t@t.com".into(), organization: None },
            LicenseTier::Community,
            None,
        );

        // License was generated on this machine — should match
        assert!(license.is_valid_machine());
    }

    #[test]
    fn test_wrong_machine_fails() {
        let sk = test_signing_key();
        let mut license = generate_license(
            &sk,
            Licensee { name: "Test".into(), email: "t@t.com".into(), organization: None },
            LicenseTier::Community,
            None,
        );

        // Tamper machine ID
        license.machine_id = "0000000000000000".into();
        assert!(!license.is_valid_machine());
    }

    #[test]
    fn test_expired_license() {
        let sk = test_signing_key();
        let mut license = generate_license(
            &sk,
            Licensee { name: "Test".into(), email: "t@t.com".into(), organization: None },
            LicenseTier::Professional,
            Some(365),
        );

        // Backdate to make expired
        license.expires_at = 1; // 1 second after epoch — definitely expired
        assert!(license.is_expired());
    }

    #[test]
    fn test_perpetual_never_expires() {
        let sk = test_signing_key();
        let license = generate_license(
            &sk,
            Licensee { name: "Test".into(), email: "t@t.com".into(), organization: None },
            LicenseTier::Community,
            None,
        );

        assert!(!license.is_expired());
    }

    #[test]
    fn test_full_validation() {
        let sk = test_signing_key();
        let vk = sk.verifying.to_bytes();

        let license = generate_license(
            &sk,
            Licensee { name: "Valid".into(), email: "v@v.com".into(), organization: None },
            LicenseTier::Community,
            None,
        );

        let validation = license.validate(&vk);
        assert!(validation.valid, "validation failed: {}", validation.reason);
        assert_eq!(validation.tier, LicenseTier::Community);
    }

    #[test]
    fn test_tier_features() {
        let sk = test_signing_key();

        let community = generate_license(
            &sk,
            Licensee { name: "C".into(), email: "c@c.com".into(), organization: None },
            LicenseTier::Community, None,
        );
        assert!(community.has_feature("core"));
        assert!(!community.has_feature("honeypot"));

        let pro = generate_license(
            &sk,
            Licensee { name: "P".into(), email: "p@p.com".into(), organization: None },
            LicenseTier::Professional, Some(365),
        );
        assert!(pro.has_feature("core"));
        assert!(pro.has_feature("honeypot"));
        assert!(!pro.has_feature("custom-branding"));

        let ent = generate_license(
            &sk,
            Licensee { name: "E".into(), email: "e@e.com".into(), organization: Some("Corp".into()) },
            LicenseTier::Enterprise, Some(365),
        );
        assert!(ent.has_feature("custom-branding"));
        assert!(ent.has_feature("sla"));
    }
}
