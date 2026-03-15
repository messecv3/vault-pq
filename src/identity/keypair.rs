//! Key pair generation, encoding, and encrypted storage.
//!
//! Secret keys are NEVER written to disk in plaintext. They are always
//! encrypted with a passphrase-derived key before storage.
//!
//! # Identity File Format
//!
//! ```text
//! VKEY\x00\x01  (6 bytes: magic + version)
//! salt          (32 bytes: Argon2id salt)
//! params        (12 bytes: KDF parameters)
//! nonce         (24 bytes: XChaCha20-Poly1305 nonce)
//! ct_len        (4 bytes: u32 LE ciphertext length)
//! ciphertext    (variable: encrypted secret key material + tag)
//! ```

use crate::crypto::{aead, kdf, kem};
use crate::error::VaultError;
use base64::Engine;
use pqcrypto_traits::kem::{PublicKey as PkTrait, SecretKey as SkTrait};

const PUBLIC_KEY_PREFIX: &str = "vault-pub-";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD_NO_PAD;

const IDENTITY_MAGIC: [u8; 6] = *b"VKEY\x00\x01";

/// Generate a new Vault identity (hybrid encryption keypair).
pub fn generate() -> (kem::HybridPublicKey, kem::HybridSecretKey) {
    kem::generate_keypair()
}

/// Encode a public key as a human-readable string.
pub fn encode_public_key(pk: &kem::HybridPublicKey) -> String {
    let bytes = pk.to_bytes();
    format!("{}{}", PUBLIC_KEY_PREFIX, B64.encode(&bytes))
}

/// Decode a public key from a human-readable string.
pub fn decode_public_key(s: &str) -> Result<kem::HybridPublicKey, VaultError> {
    let encoded = s
        .strip_prefix(PUBLIC_KEY_PREFIX)
        .ok_or_else(|| {
            VaultError::InvalidKey(format!("public key must start with '{}'", PUBLIC_KEY_PREFIX))
        })?;

    let bytes = B64
        .decode(encoded)
        .map_err(|e| VaultError::InvalidKey(format!("invalid base64: {}", e)))?;

    kem::HybridPublicKey::from_bytes(&bytes)
}

/// Save a secret key to a file, encrypted with a passphrase.
///
/// The secret key is serialized, then encrypted with Argon2id + XChaCha20-Poly1305.
/// The passphrase is zeroed after use.
pub fn save_secret_key(
    path: &std::path::Path,
    sk: &kem::HybridSecretKey,
    pk: &kem::HybridPublicKey,
    passphrase: &[u8],
) -> Result<(), VaultError> {
    // Serialize secret key material
    let mut sk_bytes = Vec::new();
    // X25519 secret (32 bytes) + ML-KEM secret key + X25519 public (32) + ML-KEM public
    sk_bytes.extend_from_slice(&sk.x25519.to_bytes());
    sk_bytes.extend_from_slice(sk.mlkem.as_bytes());
    sk_bytes.extend_from_slice(pk.x25519.as_bytes());
    sk_bytes.extend_from_slice(pk.mlkem.as_bytes());

    // Derive encryption key from passphrase
    let salt = kdf::generate_salt();
    let params = kdf::KdfParams {
        memory_kib: 262_144, // 256 MB for identity files
        iterations: 4,
        parallelism: std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(4)
            .min(8),
    };

    let derived = kdf::derive_key(passphrase.to_vec(), &salt, &params)?;

    // Encrypt
    let mut nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = aead::encrypt(
        aead::AeadAlgorithm::XChaCha20Poly1305,
        &derived,
        &nonce,
        &IDENTITY_MAGIC,
        &sk_bytes,
    )?;

    // Zero plaintext secret key bytes
    use zeroize::Zeroize;
    sk_bytes.zeroize();

    // Write file
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&IDENTITY_MAGIC);
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&params.to_bytes());
    file_data.extend_from_slice(&nonce);
    file_data.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    file_data.extend_from_slice(&ciphertext);

    std::fs::write(path, &file_data)?;

    Ok(())
}

/// Load a secret key from an encrypted identity file.
///
/// Returns (public_key, secret_key).
pub fn load_secret_key(
    path: &std::path::Path,
    passphrase: &[u8],
) -> Result<(kem::HybridPublicKey, kem::HybridSecretKey), VaultError> {
    use pqcrypto_kyber::kyber768;

    let data = std::fs::read(path)
        .map_err(|_| VaultError::FileNotFound(path.display().to_string()))?;

    // Parse header
    if data.len() < 6 + 32 + 12 + 24 + 4 {
        return Err(VaultError::InvalidFormat("identity file too short".into()));
    }
    if data[..6] != IDENTITY_MAGIC {
        return Err(VaultError::InvalidFormat("not a vault identity file".into()));
    }

    let mut pos = 6;

    let mut salt = [0u8; 32];
    salt.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    let params = kdf::KdfParams::from_bytes(&data[pos..pos + 12].try_into().unwrap());
    pos += 12;

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[pos..pos + 24]);
    pos += 24;

    let ct_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    if pos + ct_len > data.len() {
        return Err(VaultError::InvalidFormat("identity file truncated".into()));
    }
    let ciphertext = &data[pos..pos + ct_len];

    // Derive key and decrypt
    let derived = kdf::derive_key(passphrase.to_vec(), &salt, &params)?;

    let sk_bytes = aead::decrypt(
        aead::AeadAlgorithm::XChaCha20Poly1305,
        &derived,
        &nonce,
        &IDENTITY_MAGIC,
        ciphertext,
    )?;

    // Parse secret key material
    let x25519_sk_len = 32;
    let mlkem_sk_len = kyber768::secret_key_bytes();
    let x25519_pk_len = 32;
    let mlkem_pk_len = kyber768::public_key_bytes();
    let expected_len = x25519_sk_len + mlkem_sk_len + x25519_pk_len + mlkem_pk_len;

    if sk_bytes.len() != expected_len {
        return Err(VaultError::InvalidFormat(format!(
            "identity key data wrong size: expected {}, got {}",
            expected_len,
            sk_bytes.len()
        )));
    }

    let mut p = 0;

    let mut x25519_sk_arr = [0u8; 32];
    x25519_sk_arr.copy_from_slice(&sk_bytes[p..p + 32]);
    let x25519_sk = x25519_dalek::StaticSecret::from(x25519_sk_arr);
    p += 32;

    let mlkem_sk = kyber768::SecretKey::from_bytes(&sk_bytes[p..p + mlkem_sk_len])
        .map_err(|_| VaultError::InvalidKey("corrupted ML-KEM secret key".into()))?;
    p += mlkem_sk_len;

    let mut x25519_pk_arr = [0u8; 32];
    x25519_pk_arr.copy_from_slice(&sk_bytes[p..p + 32]);
    let x25519_pk = x25519_dalek::PublicKey::from(x25519_pk_arr);
    p += 32;

    let mlkem_pk = kyber768::PublicKey::from_bytes(&sk_bytes[p..p + mlkem_pk_len])
        .map_err(|_| VaultError::InvalidKey("corrupted ML-KEM public key".into()))?;

    Ok((
        kem::HybridPublicKey {
            x25519: x25519_pk,
            mlkem: mlkem_pk,
        },
        kem::HybridSecretKey {
            x25519: x25519_sk,
            mlkem: mlkem_sk,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_and_encode() {
        let (pk, _sk) = generate();
        let encoded = encode_public_key(&pk);
        assert!(encoded.starts_with("vault-pub-"));

        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(pk.x25519.as_bytes(), decoded.x25519.as_bytes());
    }

    #[test]
    fn test_invalid_prefix_rejected() {
        let result = decode_public_key("bad-prefix-AAAA");
        assert!(result.is_err());
    }

    #[test]
    fn test_save_load_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_identity.vkey");
        let passphrase = b"test passphrase for identity";

        let (pk, sk) = generate();
        save_secret_key(&path, &sk, &pk, passphrase).unwrap();

        // File should exist and not be empty
        let file_data = std::fs::read(&path).unwrap();
        assert!(file_data.len() > 100);
        assert_eq!(&file_data[..6], &IDENTITY_MAGIC);

        // Load with correct passphrase
        let (loaded_pk, loaded_sk) = load_secret_key(&path, passphrase).unwrap();
        assert_eq!(pk.x25519.as_bytes(), loaded_pk.x25519.as_bytes());

        // Verify the loaded key works: encrypt with original pk, decrypt with loaded sk
        let (ss1, encap) = kem::encapsulate(&pk).unwrap();
        let ss2 = kem::decapsulate(&loaded_sk, &encap).unwrap();
        assert_eq!(ss1.expose(), ss2.expose());
    }

    #[test]
    fn test_wrong_passphrase_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_identity2.vkey");

        let (pk, sk) = generate();
        save_secret_key(&path, &sk, &pk, b"correct").unwrap();

        let result = load_secret_key(&path, b"wrong");
        assert!(result.is_err());
    }
}
