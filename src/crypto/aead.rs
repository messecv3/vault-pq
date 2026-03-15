//! Authenticated Encryption with Associated Data (AEAD).
//!
//! Supports two algorithms:
//! - XChaCha20-Poly1305: Default. 192-bit nonce (safe with random nonces). Fast in software.
//! - AES-256-GCM: Hardware-accelerated path when AES-NI is available.
//!
//! Both provide 256-bit keys and 128-bit authentication tags.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce as AesNonce;
use crate::error::VaultError;
use crate::memory::SecureBuf;

/// Supported AEAD algorithms.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum AeadAlgorithm {
    XChaCha20Poly1305 = 0x01,
    Aes256Gcm = 0x02,
}

impl AeadAlgorithm {
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            Self::Aes256Gcm => 12,
        }
    }

    pub fn tag_size(&self) -> usize {
        16 // Both use 128-bit Poly1305/GHASH tags
    }

    pub fn key_size(&self) -> usize {
        32 // Both use 256-bit keys
    }

    pub fn from_byte(b: u8) -> Result<Self, VaultError> {
        match b {
            0x01 => Ok(Self::XChaCha20Poly1305),
            0x02 => Ok(Self::Aes256Gcm),
            _ => Err(VaultError::InvalidFormat(format!("unknown AEAD algorithm: 0x{:02x}", b))),
        }
    }
}

/// Select the best AEAD algorithm for this platform.
pub fn select_algorithm() -> AeadAlgorithm {
    if has_aes_ni() {
        AeadAlgorithm::Aes256Gcm
    } else {
        AeadAlgorithm::XChaCha20Poly1305
    }
}

/// Detect AES-NI hardware support.
fn has_aes_ni() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("ssse3")
    }
    #[cfg(target_arch = "x86")]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("ssse3")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

/// Encrypt plaintext with the selected AEAD algorithm.
///
/// - `key`: exactly 32 bytes
/// - `nonce`: correct size for algorithm (24 for XChaCha20, 12 for AES-GCM)
/// - `aad`: additional authenticated data (integrity-protected but not encrypted)
/// - Returns: ciphertext || tag
pub fn encrypt(
    algorithm: AeadAlgorithm,
    key: &SecureBuf,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    debug_assert_eq!(key.len(), 32);
    debug_assert_eq!(nonce.len(), algorithm.nonce_size());

    match algorithm {
        AeadAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
                .map_err(|_| VaultError::CipherInit)?;
            let n = XNonce::from_slice(nonce);
            cipher
                .encrypt(n, Payload { msg: plaintext, aad })
                .map_err(|_| VaultError::EncryptionFailed)
        }
        AeadAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.expose())
                .map_err(|_| VaultError::CipherInit)?;
            let n = AesNonce::from_slice(nonce);
            cipher
                .encrypt(n, Payload { msg: plaintext, aad })
                .map_err(|_| VaultError::EncryptionFailed)
        }
    }
}

/// Decrypt ciphertext with the selected AEAD algorithm.
///
/// Returns plaintext on success.
/// Returns `VaultError::AuthenticationFailed` if the tag is invalid
/// (tampered ciphertext, wrong key, or wrong nonce).
pub fn decrypt(
    algorithm: AeadAlgorithm,
    key: &SecureBuf,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    debug_assert_eq!(key.len(), 32);
    debug_assert_eq!(nonce.len(), algorithm.nonce_size());

    match algorithm {
        AeadAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
                .map_err(|_| VaultError::CipherInit)?;
            let n = XNonce::from_slice(nonce);
            cipher
                .decrypt(n, Payload { msg: ciphertext, aad })
                .map_err(|_| VaultError::AuthenticationFailed)
        }
        AeadAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.expose())
                .map_err(|_| VaultError::CipherInit)?;
            let n = AesNonce::from_slice(nonce);
            cipher
                .decrypt(n, Payload { msg: ciphertext, aad })
                .map_err(|_| VaultError::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20_round_trip() {
        let key = SecureBuf::random(32).unwrap();
        let nonce = [0x42u8; 24];
        let aad = b"test-aad";
        let plaintext = b"hello, post-quantum world!";

        let ct = encrypt(AeadAlgorithm::XChaCha20Poly1305, &key, &nonce, aad, plaintext).unwrap();
        let pt = decrypt(AeadAlgorithm::XChaCha20Poly1305, &key, &nonce, aad, &ct).unwrap();

        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_aes_gcm_round_trip() {
        let key = SecureBuf::random(32).unwrap();
        let nonce = [0x42u8; 12];
        let aad = b"test-aad";
        let plaintext = b"hello, hardware-accelerated world!";

        let ct = encrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, aad, plaintext).unwrap();
        let pt = decrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, aad, &ct).unwrap();

        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = SecureBuf::random(32).unwrap();
        let key2 = SecureBuf::random(32).unwrap();
        let nonce = [0x42u8; 24];
        let plaintext = b"secret data";

        let ct = encrypt(AeadAlgorithm::XChaCha20Poly1305, &key1, &nonce, b"", plaintext).unwrap();
        let result = decrypt(AeadAlgorithm::XChaCha20Poly1305, &key2, &nonce, b"", &ct);

        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = SecureBuf::random(32).unwrap();
        let nonce = [0x42u8; 24];
        let plaintext = b"secret data";

        let mut ct = encrypt(AeadAlgorithm::XChaCha20Poly1305, &key, &nonce, b"", plaintext).unwrap();
        ct[0] ^= 0xFF; // Flip a byte

        let result = decrypt(AeadAlgorithm::XChaCha20Poly1305, &key, &nonce, b"", &ct);
        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = SecureBuf::random(32).unwrap();
        let nonce = [0x42u8; 24];
        let plaintext = b"secret data";

        let ct = encrypt(AeadAlgorithm::XChaCha20Poly1305, &key, &nonce, b"aad1", plaintext).unwrap();
        let result = decrypt(AeadAlgorithm::XChaCha20Poly1305, &key, &nonce, b"aad2", &ct);

        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));
    }

    #[test]
    fn test_algorithm_detection() {
        let algo = select_algorithm();
        // Just verify it returns something valid
        assert!(algo.key_size() == 32);
        assert!(algo.tag_size() == 16);
    }
}
