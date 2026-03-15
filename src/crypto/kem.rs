//! Hybrid Key Encapsulation Mechanism: X25519 + ML-KEM-768.
//!
//! Provides post-quantum-resistant key exchange by combining classical
//! elliptic curve Diffie-Hellman (X25519) with lattice-based KEM (ML-KEM-768).
//! Both must be broken simultaneously to compromise the shared secret.

use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PkTrait,
    SharedSecret as SsTrait,
};
use rand::rngs::OsRng;
use zeroize::Zeroize;
use crate::crypto::hkdf_util;
use crate::error::VaultError;
use crate::memory::SecureBuf;

/// Hybrid public key: X25519 (32 bytes) + ML-KEM-768 (1184 bytes).
pub struct HybridPublicKey {
    pub x25519: X25519Public,
    pub mlkem: kyber768::PublicKey,
}

impl HybridPublicKey {
    /// Serialize to bytes: x25519_pk || mlkem_pk
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + kyber768::public_key_bytes());
        out.extend_from_slice(self.x25519.as_bytes());
        out.extend_from_slice(self.mlkem.as_bytes());
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        let x25519_len = 32;
        let mlkem_len = kyber768::public_key_bytes();

        if data.len() != x25519_len + mlkem_len {
            return Err(VaultError::InvalidKey(format!(
                "expected {} bytes, got {}",
                x25519_len + mlkem_len,
                data.len()
            )));
        }

        let x25519 = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&data[..32]);
            X25519Public::from(buf)
        };

        let mlkem = kyber768::PublicKey::from_bytes(&data[32..])
            .map_err(|_| VaultError::InvalidKey("invalid ML-KEM-768 public key".into()))?;

        Ok(Self { x25519, mlkem })
    }
}

/// Hybrid secret key: X25519 + ML-KEM-768.
pub struct HybridSecretKey {
    pub x25519: StaticSecret,
    pub mlkem: kyber768::SecretKey,
}

/// Data needed by the recipient to decapsulate the shared secret.
pub struct EncapsulationData {
    /// Ephemeral X25519 public key (32 bytes)
    pub eph_x25519_pk: X25519Public,
    /// ML-KEM-768 ciphertext (1088 bytes)
    pub mlkem_ciphertext: kyber768::Ciphertext,
}

impl EncapsulationData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + kyber768::ciphertext_bytes());
        out.extend_from_slice(self.eph_x25519_pk.as_bytes());
        out.extend_from_slice(self.mlkem_ciphertext.as_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        let x25519_len = 32;
        let ct_len = kyber768::ciphertext_bytes();

        if data.len() != x25519_len + ct_len {
            return Err(VaultError::InvalidKey("invalid encapsulation data size".into()));
        }

        let eph_pk = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&data[..32]);
            X25519Public::from(buf)
        };

        let ct = kyber768::Ciphertext::from_bytes(&data[32..])
            .map_err(|_| VaultError::InvalidKey("invalid ML-KEM ciphertext".into()))?;

        Ok(Self {
            eph_x25519_pk: eph_pk,
            mlkem_ciphertext: ct,
        })
    }
}

/// Generate a new hybrid keypair.
pub fn generate_keypair() -> (HybridPublicKey, HybridSecretKey) {
    // Classical: X25519
    let x25519_sk = StaticSecret::random_from_rng(OsRng);
    let x25519_pk = X25519Public::from(&x25519_sk);

    // Post-quantum: ML-KEM-768
    let (mlkem_pk, mlkem_sk) = kyber768::keypair();

    (
        HybridPublicKey {
            x25519: x25519_pk,
            mlkem: mlkem_pk,
        },
        HybridSecretKey {
            x25519: x25519_sk,
            mlkem: mlkem_sk,
        },
    )
}

/// Encapsulate: generate a shared secret for a recipient's public key.
///
/// Returns (shared_secret, encapsulation_data).
/// The caller encrypts the file key with the shared secret, and sends
/// the encapsulation data in the recipient stanza.
pub fn encapsulate(
    recipient_pk: &HybridPublicKey,
) -> Result<(SecureBuf, EncapsulationData), VaultError> {
    // Classical: ephemeral X25519 DH
    let eph_sk = EphemeralSecret::random_from_rng(OsRng);
    let eph_pk = X25519Public::from(&eph_sk);
    let ss_classical = eph_sk.diffie_hellman(&recipient_pk.x25519);

    // Post-quantum: ML-KEM-768 encapsulation
    let (ss_pq, ct_pq) = kyber768::encapsulate(&recipient_pk.mlkem);

    // Combine via HKDF
    let mut salt = Vec::with_capacity(32 + kyber768::ciphertext_bytes());
    salt.extend_from_slice(eph_pk.as_bytes());
    salt.extend_from_slice(ct_pq.as_bytes());

    let combined = hkdf_util::combine_shared_secrets(
        ss_classical.as_bytes(),
        ss_pq.as_bytes(),
        &salt,
    )?;

    salt.zeroize();

    Ok((
        combined,
        EncapsulationData {
            eph_x25519_pk: eph_pk,
            mlkem_ciphertext: ct_pq,
        },
    ))
}

/// Decapsulate: recover the shared secret using our secret key.
pub fn decapsulate(
    our_sk: &HybridSecretKey,
    encap: &EncapsulationData,
) -> Result<SecureBuf, VaultError> {
    // Classical: X25519 DH
    let ss_classical = our_sk.x25519.diffie_hellman(&encap.eph_x25519_pk);

    // Post-quantum: ML-KEM-768 decapsulation
    let ss_pq = kyber768::decapsulate(&encap.mlkem_ciphertext, &our_sk.mlkem);

    // Combine (same HKDF as encapsulation)
    let mut salt = Vec::with_capacity(32 + kyber768::ciphertext_bytes());
    salt.extend_from_slice(encap.eph_x25519_pk.as_bytes());
    salt.extend_from_slice(encap.mlkem_ciphertext.as_bytes());

    let combined = hkdf_util::combine_shared_secrets(
        ss_classical.as_bytes(),
        ss_pq.as_bytes(),
        &salt,
    )?;

    salt.zeroize();

    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (pk, _sk) = generate_keypair();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 32 + kyber768::public_key_bytes());
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let (pk, sk) = generate_keypair();

        let (ss_sender, encap) = encapsulate(&pk).unwrap();
        let ss_receiver = decapsulate(&sk, &encap).unwrap();

        assert_eq!(ss_sender.expose(), ss_receiver.expose());
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let (pk1, _sk1) = generate_keypair();
        let (_pk2, sk2) = generate_keypair();

        let (ss_sender, encap) = encapsulate(&pk1).unwrap();
        // Decapsulating with wrong secret key should produce different result
        // (ML-KEM decapsulation with wrong key produces a pseudorandom output,
        // not an error — this is by design to prevent chosen-ciphertext attacks)
        let ss_wrong = decapsulate(&sk2, &encap).unwrap();

        assert_ne!(ss_sender.expose(), ss_wrong.expose());
    }

    #[test]
    fn test_public_key_serialization() {
        let (pk, _sk) = generate_keypair();
        let bytes = pk.to_bytes();
        let restored = HybridPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk.x25519.as_bytes(), restored.x25519.as_bytes());
    }

    #[test]
    fn test_encapsulation_data_serialization() {
        let (pk, sk) = generate_keypair();
        let (_ss, encap) = encapsulate(&pk).unwrap();

        let bytes = encap.to_bytes();
        let restored = EncapsulationData::from_bytes(&bytes).unwrap();

        // Verify decapsulation still works with restored data
        let ss1 = decapsulate(&sk, &encap).unwrap();
        let ss2 = decapsulate(&sk, &restored).unwrap();
        assert_eq!(ss1.expose(), ss2.expose());
    }
}
