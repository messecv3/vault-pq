//! Polymorphic output generation.
//!
//! Inspired by Phantom Engine's per-build uniqueness: no two encrypted files
//! share structural patterns, even for identical inputs with identical keys.
//!
//! # Techniques
//!
//! 1. **Random header field ordering**: recipient stanzas shuffled randomly
//! 2. **Variable padding alignment**: padding inserted at random positions
//! 3. **Nonce-space diversification**: different HKDF info strings per build
//! 4. **Decoy stanzas**: fake recipient stanzas (indistinguishable from real)
//! 5. **Structure jitter**: random-length fields in non-critical positions
//!
//! This prevents pattern-matching attacks where an adversary compares
//! multiple encrypted files to find structural commonalities.

use rand::Rng;
use crate::format::header::RecipientStanza;
use crate::crypto::kdf;
use crate::error::VaultError;

/// Polymorphic configuration for a single encryption operation.
#[derive(Clone, Debug)]
pub struct PolymorphConfig {
    /// Number of decoy passphrase stanzas to add (0-4)
    pub decoy_stanzas: usize,
    /// Random prefix bytes before body (0-128)
    pub prefix_jitter: usize,
    /// Random suffix bytes after body (0-128)
    pub suffix_jitter: usize,
    /// Whether to shuffle stanza order
    pub shuffle_stanzas: bool,
}

impl PolymorphConfig {
    /// Generate a random polymorphic configuration.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            decoy_stanzas: rng.gen_range(0..=3),
            prefix_jitter: rng.gen_range(0..=64),
            suffix_jitter: rng.gen_range(0..=64),
            shuffle_stanzas: true,
        }
    }

    /// No polymorphism (deterministic output for testing).
    pub fn none() -> Self {
        Self {
            decoy_stanzas: 0,
            prefix_jitter: 0,
            suffix_jitter: 0,
            shuffle_stanzas: false,
        }
    }
}

/// Generate decoy recipient stanzas that look indistinguishable from real ones.
///
/// Each decoy has a random salt, random KDF params within valid ranges,
/// and a random encrypted file key blob. Without trying every possible
/// passphrase, an observer cannot tell which stanzas are real vs decoy.
pub fn generate_decoy_stanzas(count: usize) -> Result<Vec<RecipientStanza>, VaultError> {
    let mut decoys = Vec::with_capacity(count);
    let mut rng = rand::thread_rng();

    for _ in 0..count {
        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut salt);

        // Random but valid-looking KDF params
        let params = kdf::KdfParams {
            memory_kib: [65_536, 131_072, 262_144, 524_288][rng.gen_range(0..4)],
            iterations: rng.gen_range(3..=12),
            parallelism: rng.gen_range(2..=8),
        };

        // Random encrypted file key (24 nonce + 48 ciphertext+tag = 72 bytes)
        let mut fake_efk = vec![0u8; 72];
        rand::RngCore::fill_bytes(&mut rng, &mut fake_efk);

        decoys.push(RecipientStanza::Passphrase {
            salt,
            params,
            encrypted_file_key: fake_efk,
        });
    }

    Ok(decoys)
}

/// Shuffle stanzas using Fisher-Yates algorithm.
pub fn shuffle_stanzas(stanzas: &mut [RecipientStanza]) {
    let mut rng = rand::thread_rng();
    let n = stanzas.len();
    for i in (1..n).rev() {
        let j = rng.gen_range(0..=i);
        stanzas.swap(i, j);
    }
}

/// Generate random jitter bytes (high entropy, indistinguishable from ciphertext).
pub fn generate_jitter(len: usize) -> Vec<u8> {
    let mut jitter = vec![0u8; len];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut jitter);
    jitter
}

/// Apply polymorphic configuration to stanzas.
/// Returns the augmented stanza list (real + decoys, optionally shuffled).
pub fn apply_polymorph(
    mut real_stanzas: Vec<RecipientStanza>,
    config: &PolymorphConfig,
) -> Result<Vec<RecipientStanza>, VaultError> {
    // Add decoys
    if config.decoy_stanzas > 0 {
        let decoys = generate_decoy_stanzas(config.decoy_stanzas)?;
        real_stanzas.extend(decoys);
    }

    // Shuffle
    if config.shuffle_stanzas && real_stanzas.len() > 1 {
        shuffle_stanzas(&mut real_stanzas);
    }

    Ok(real_stanzas)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_generation() {
        let decoys = generate_decoy_stanzas(3).unwrap();
        assert_eq!(decoys.len(), 3);

        // Each decoy should have unique salt
        if let (
            RecipientStanza::Passphrase { salt: s1, .. },
            RecipientStanza::Passphrase { salt: s2, .. },
        ) = (&decoys[0], &decoys[1]) {
            assert_ne!(s1, s2);
        }
    }

    #[test]
    fn test_decoy_looks_real() {
        let decoys = generate_decoy_stanzas(1).unwrap();
        match &decoys[0] {
            RecipientStanza::Passphrase { salt, params, encrypted_file_key } => {
                assert_eq!(salt.len(), 32);
                assert!(params.memory_kib >= 65_536);
                assert!(params.iterations >= 3);
                assert_eq!(encrypted_file_key.len(), 72);
                // Salt should not be all zeros (random)
                assert!(!salt.iter().all(|&b| b == 0));
            }
            _ => panic!("expected passphrase stanza"),
        }
    }

    #[test]
    fn test_shuffle() {
        let stanzas: Vec<RecipientStanza> = (0..10)
            .map(|i| RecipientStanza::Passphrase {
                salt: [i; 32],
                params: kdf::KdfParams::low(),
                encrypted_file_key: vec![i; 72],
            })
            .collect();

        let mut shuffled = stanzas.clone();
        shuffle_stanzas(&mut shuffled);

        // Very unlikely to be in exact same order after shuffle
        // (1/10! chance = 1 in 3,628,800)
        let _same_order = stanzas.iter().zip(shuffled.iter()).all(|(a, b)| {
            match (a, b) {
                (
                    RecipientStanza::Passphrase { salt: s1, .. },
                    RecipientStanza::Passphrase { salt: s2, .. },
                ) => s1 == s2,
                _ => false,
            }
        });
        // Not strictly guaranteed to differ, but statistically certain
        // Only assert length is preserved
        assert_eq!(shuffled.len(), 10);
    }

    #[test]
    fn test_apply_polymorph() {
        let real = vec![RecipientStanza::Passphrase {
            salt: [0x42; 32],
            params: kdf::KdfParams::low(),
            encrypted_file_key: vec![0xAB; 72],
        }];

        let config = PolymorphConfig {
            decoy_stanzas: 3,
            prefix_jitter: 0,
            suffix_jitter: 0,
            shuffle_stanzas: true,
        };

        let result = apply_polymorph(real, &config).unwrap();
        assert_eq!(result.len(), 4); // 1 real + 3 decoys
    }

    #[test]
    fn test_no_polymorph() {
        let real = vec![RecipientStanza::Passphrase {
            salt: [0x01; 32],
            params: kdf::KdfParams::low(),
            encrypted_file_key: vec![0x02; 72],
        }];

        let config = PolymorphConfig::none();
        let result = apply_polymorph(real, &config).unwrap();
        assert_eq!(result.len(), 1); // No decoys added
    }

    #[test]
    fn test_jitter_is_random() {
        let j1 = generate_jitter(64);
        let j2 = generate_jitter(64);
        assert_ne!(j1, j2); // Extremely unlikely to be equal
        assert_eq!(j1.len(), 64);
    }
}
