//! Key Derivation Function — Argon2id with enforced minimums.
//!
//! Argon2id is a memory-hard KDF that resists GPU/ASIC attacks.
//! We enforce minimum parameters because weaker parameters create a
//! false sense of security.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;
use crate::error::VaultError;
use crate::memory::SecureBuf;

/// Argon2id parameters with enforced minimums.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB. Minimum: 65536 (64 MB). Default: 524288 (512 MB).
    pub memory_kib: u32,
    /// Number of iterations. Minimum: 3. Default: 8.
    pub iterations: u32,
    /// Degree of parallelism. Minimum: 1. Default: 4.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 524_288, // 512 MB
            iterations: 8,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    /// Lower-security parameters for testing or low-memory systems.
    pub fn low() -> Self {
        Self {
            memory_kib: 65_536, // 64 MB
            iterations: 3,
            parallelism: 2,
        }
    }

    /// Validate parameters against minimum security requirements.
    pub fn validate(&self) -> Result<(), VaultError> {
        if self.memory_kib < 65_536 {
            return Err(VaultError::KdfParamsTooWeak(
                "memory must be >= 64 MB (65536 KiB)".into(),
            ));
        }
        if self.iterations < 3 {
            return Err(VaultError::KdfParamsTooWeak(
                "iterations must be >= 3".into(),
            ));
        }
        if self.parallelism < 1 {
            return Err(VaultError::KdfParamsTooWeak(
                "parallelism must be >= 1".into(),
            ));
        }
        Ok(())
    }

    /// Serialize to bytes for storage in file header.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.memory_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.iterations.to_le_bytes());
        out[8..12].copy_from_slice(&self.parallelism.to_le_bytes());
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8; 12]) -> Self {
        Self {
            memory_kib: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            iterations: u32::from_le_bytes(data[4..8].try_into().unwrap()),
            parallelism: u32::from_le_bytes(data[8..12].try_into().unwrap()),
        }
    }
}

/// Derive a 32-byte key from a passphrase using Argon2id.
///
/// The passphrase is consumed and zeroed after use.
pub fn derive_key(
    mut passphrase: Vec<u8>,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<SecureBuf, VaultError> {
    params.validate()?;

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32), // 256-bit output
    )
    .map_err(|e| VaultError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = SecureBuf::new(32)?;
    argon2
        .hash_password_into(&passphrase, salt, output.expose_mut())
        .map_err(|e| VaultError::KdfError(e.to_string()))?;

    // Zero the passphrase immediately
    passphrase.zeroize();

    Ok(output)
}

/// Generate a random 32-byte salt for Argon2id.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use minimal params for test speed
    fn test_params() -> KdfParams {
        KdfParams {
            memory_kib: 65_536, // 64 MB — minimum allowed
            iterations: 3,
            parallelism: 1,
        }
    }

    #[test]
    fn test_derive_key_deterministic() {
        let pass = b"test passphrase".to_vec();
        let salt = [0x42u8; 32];
        let params = test_params();

        let key1 = derive_key(pass.clone(), &salt, &params).unwrap();
        let key2 = derive_key(b"test passphrase".to_vec(), &salt, &params).unwrap();

        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [0x42u8; 32];
        let params = test_params();

        let key1 = derive_key(b"password1".to_vec(), &salt, &params).unwrap();
        let key2 = derive_key(b"password2".to_vec(), &salt, &params).unwrap();

        assert_ne!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let params = test_params();

        let key1 = derive_key(b"password".to_vec(), &[0x01u8; 32], &params).unwrap();
        let key2 = derive_key(b"password".to_vec(), &[0x02u8; 32], &params).unwrap();

        assert_ne!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_params_too_weak() {
        let params = KdfParams {
            memory_kib: 1024, // Way too low
            iterations: 1,
            parallelism: 1,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_params_serialization() {
        let params = KdfParams::default();
        let bytes = params.to_bytes();
        let restored = KdfParams::from_bytes(&bytes);
        assert_eq!(params.memory_kib, restored.memory_kib);
        assert_eq!(params.iterations, restored.iterations);
        assert_eq!(params.parallelism, restored.parallelism);
    }
}
