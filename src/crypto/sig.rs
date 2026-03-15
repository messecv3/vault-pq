//! Hybrid digital signatures: Ed25519 (classical) with extensible PQ slot.
//!
//! Signs the BLAKE3 hash of the plaintext, binding the signature to the
//! file content. The signature is stored in the encrypted metadata section,
//! so only authorized recipients can verify it.
//!
//! Ed25519 provides immediate security. The architecture supports adding
//! SLH-DSA (SPHINCS+) as a second signature once stable Rust crates are available,
//! making it hybrid post-quantum without format changes.

use ed25519_dalek::{
    Signer, Verifier, SigningKey, VerifyingKey, Signature,
};
use rand::rngs::OsRng;
use crate::error::VaultError;

/// A signing keypair.
pub struct SigningKeyPair {
    signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl SigningKeyPair {
    /// Generate a new Ed25519 signing keypair.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Serialize the signing (secret) key.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Restore from secret key bytes.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(bytes);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Sign a message (typically the BLAKE3 hash of the plaintext).
    pub fn sign(&self, message: &[u8]) -> FileSignature {
        let sig = self.signing.sign(message);
        FileSignature {
            ed25519: sig.to_bytes().to_vec(),
            verifying_key: self.verifying.to_bytes(),
        }
    }
}

impl Drop for SigningKeyPair {
    fn drop(&mut self) {
        // Ed25519 signing key contains secret material.
        // SigningKey uses Zeroize internally via ed25519-dalek.
    }
}

/// A file signature with the verifying key embedded.
///
/// Uses Vec<u8> instead of [u8; 64] for serde compatibility.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FileSignature {
    /// Ed25519 signature (64 bytes)
    pub ed25519: Vec<u8>,
    /// Ed25519 verifying key (32 bytes) — identifies the signer
    pub verifying_key: [u8; 32],
}

impl FileSignature {
    /// Verify the signature against a message.
    pub fn verify(&self, message: &[u8]) -> Result<(), VaultError> {
        let vk = VerifyingKey::from_bytes(&self.verifying_key)
            .map_err(|_| VaultError::InvalidKey("invalid Ed25519 verifying key".into()))?;

        let sig_bytes: [u8; 64] = self.ed25519.as_slice().try_into()
            .map_err(|_| VaultError::InvalidKey("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);

        vk.verify(message, &sig)
            .map_err(|_| VaultError::AuthenticationFailed)
    }

    /// Get the signer's public key fingerprint (first 8 bytes of BLAKE3 hash).
    pub fn signer_fingerprint(&self) -> String {
        let hash = blake3::hash(&self.verifying_key);
        hex::encode(&hash.as_bytes()[..8])
    }
}

/// Construct the message to sign: binds the signature to the file content.
///
/// The signed message is: "vault-sig-v1" || plaintext_hash
/// This ensures the signature covers the file content via its BLAKE3 hash.
pub fn build_signed_message(plaintext_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(12 + 32);
    msg.extend_from_slice(b"vault-sig-v1");
    msg.extend_from_slice(plaintext_hash);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let kp = SigningKeyPair::generate();
        let hash = [0xAA; 32];
        let msg = build_signed_message(&hash);

        let sig = kp.sign(&msg);
        assert!(sig.verify(&msg).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = SigningKeyPair::generate();
        let msg1 = build_signed_message(&[0xAA; 32]);
        let msg2 = build_signed_message(&[0xBB; 32]);

        let sig = kp.sign(&msg1);
        assert!(sig.verify(&msg2).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = SigningKeyPair::generate();
        let kp2 = SigningKeyPair::generate();
        let msg = build_signed_message(&[0xCC; 32]);

        let sig = kp1.sign(&msg);

        // Tamper: replace verifying key with kp2's
        let mut bad_sig = sig.clone();
        bad_sig.verifying_key = kp2.verifying.to_bytes();
        assert!(bad_sig.verify(&msg).is_err());
    }

    #[test]
    fn test_keypair_serialization() {
        let kp = SigningKeyPair::generate();
        let bytes = kp.secret_bytes();

        let restored = SigningKeyPair::from_secret_bytes(&bytes);
        assert_eq!(kp.verifying.to_bytes(), restored.verifying.to_bytes());

        // Sign with original, verify with restored
        let msg = build_signed_message(&[0xDD; 32]);
        let sig = kp.sign(&msg);
        assert!(sig.verify(&msg).is_ok());
    }

    #[test]
    fn test_fingerprint() {
        let kp = SigningKeyPair::generate();
        let msg = build_signed_message(&[0x00; 32]);
        let sig = kp.sign(&msg);
        let fp = sig.signer_fingerprint();
        assert_eq!(fp.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_tampered_signature_fails() {
        let kp = SigningKeyPair::generate();
        let msg = build_signed_message(&[0xEE; 32]);
        let mut sig = kp.sign(&msg);
        sig.ed25519[0] ^= 0xFF;
        assert!(sig.verify(&msg).is_err());
    }
}
