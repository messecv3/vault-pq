//! HKDF-SHA256 key derivation utility.
//!
//! Used for:
//! - Combining classical + post-quantum shared secrets
//! - Deriving per-chunk nonces
//! - Deriving sub-keys from a master file key

use hkdf::Hkdf;
use sha2::Sha256;
use crate::error::VaultError;
use crate::memory::SecureBuf;

/// Extract-then-expand: derive `len` bytes of key material.
///
/// - `ikm`: input key material (shared secrets, etc.)
/// - `salt`: optional salt (public, non-secret)
/// - `info`: context string (must be unique per derivation purpose)
/// - `len`: desired output length in bytes
pub fn derive(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<SecureBuf, VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = SecureBuf::new(len)?;

    hk.expand(info, output.expose_mut())
        .map_err(|_| VaultError::HkdfError)?;

    Ok(output)
}

/// Derive a per-chunk nonce from the file key and chunk index.
///
/// Each chunk gets a unique, deterministic nonce derived via HKDF.
/// This is safe because: same key + same index = same nonce,
/// and each chunk index is unique within a file.
pub fn derive_chunk_nonce(
    file_key: &SecureBuf,
    chunk_index: u64,
    nonce_len: usize,
) -> Result<SecureBuf, VaultError> {
    derive(
        file_key.expose(),
        &chunk_index.to_le_bytes(),
        b"vault-chunk-nonce-v1",
        nonce_len,
    )
}

/// Combine two shared secrets (classical + post-quantum) into a single key.
pub fn combine_shared_secrets(
    classical: &[u8],
    post_quantum: &[u8],
    salt: &[u8],
) -> Result<SecureBuf, VaultError> {
    let mut ikm = Vec::with_capacity(classical.len() + post_quantum.len());
    ikm.extend_from_slice(classical);
    ikm.extend_from_slice(post_quantum);

    let result = derive(&ikm, salt, b"vault-hybrid-kem-v1", 32)?;

    // Zero the combined ikm
    use zeroize::Zeroize;
    ikm.zeroize();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_deterministic() {
        let ikm = b"input key material";
        let salt = b"salt value";
        let info = b"context";

        let k1 = derive(ikm, salt, info, 32).unwrap();
        let k2 = derive(ikm, salt, info, 32).unwrap();

        assert_eq!(k1.expose(), k2.expose());
    }

    #[test]
    fn test_different_info_different_output() {
        let ikm = b"same ikm";
        let salt = b"same salt";

        let k1 = derive(ikm, salt, b"context-1", 32).unwrap();
        let k2 = derive(ikm, salt, b"context-2", 32).unwrap();

        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn test_chunk_nonces_unique() {
        let key = SecureBuf::random(32).unwrap();

        let n0 = derive_chunk_nonce(&key, 0, 24).unwrap();
        let n1 = derive_chunk_nonce(&key, 1, 24).unwrap();

        assert_ne!(n0.expose(), n1.expose());
    }

    #[test]
    fn test_combine_shared_secrets() {
        let classical = [0x01u8; 32];
        let pq = [0x02u8; 32];
        let salt = [0x03u8; 64];

        let combined = combine_shared_secrets(&classical, &pq, &salt).unwrap();
        assert_eq!(combined.len(), 32);
        // Should not be trivially related to inputs
        assert_ne!(combined.expose(), &classical);
        assert_ne!(combined.expose(), &pq);
    }
}
