//! Shannon entropy analysis.
//!
//! Measures the information density of byte sequences. Useful for:
//! - Verifying encrypted output looks like random data (entropy ≈ 8.0)
//! - Detecting improperly encrypted or compressed data
//! - Auditing vault files without decrypting them
//!
//! Based on the entropy calculation from Phantom Engine's obfuscation_engine.h.

/// Calculate Shannon entropy of a byte sequence.
///
/// Returns a value between 0.0 (all identical bytes) and 8.0 (perfectly random).
/// Well-encrypted data should score > 7.9.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Classify entropy level for human-readable output.
pub fn classify_entropy(entropy: f64) -> &'static str {
    if entropy >= 7.95 {
        "excellent (indistinguishable from random)"
    } else if entropy >= 7.5 {
        "good (typical of encrypted/compressed data)"
    } else if entropy >= 6.0 {
        "moderate (may contain structure)"
    } else if entropy >= 4.0 {
        "low (significant patterns present)"
    } else if entropy >= 2.0 {
        "poor (highly structured data)"
    } else {
        "minimal (near-constant data)"
    }
}

/// Per-section entropy analysis of a byte sequence.
/// Splits data into `num_sections` equal parts and reports entropy of each.
pub fn section_entropy(data: &[u8], num_sections: usize) -> Vec<(usize, usize, f64)> {
    if data.is_empty() || num_sections == 0 {
        return Vec::new();
    }

    let section_size = data.len() / num_sections;
    if section_size == 0 {
        return vec![(0, data.len(), shannon_entropy(data))];
    }

    let mut results = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let start = i * section_size;
        let end = if i == num_sections - 1 { data.len() } else { start + section_size };
        let entropy = shannon_entropy(&data[start..end]);
        results.push((start, end, entropy));
    }

    results
}

/// Byte frequency distribution — counts of each byte value.
pub fn byte_distribution(data: &[u8]) -> [u64; 256] {
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    freq
}

/// Chi-squared test statistic against uniform distribution.
/// Lower values = more uniform (closer to random).
/// For 256 categories and N bytes, expected count = N/256.
/// A truly random sequence of 65536 bytes has χ² ≈ 256 ± 23.
pub fn chi_squared(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let freq = byte_distribution(data);
    let expected = data.len() as f64 / 256.0;
    let mut chi2 = 0.0;

    for &count in &freq {
        let diff = count as f64 - expected;
        chi2 += (diff * diff) / expected;
    }

    chi2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let data = vec![0x42u8; 1000];
        let e = shannon_entropy(&data);
        assert!(e < 0.01, "constant data should have ~0 entropy, got {}", e);
    }

    #[test]
    fn test_max_entropy() {
        // Pseudo-random data (not truly random, but high entropy)
        let mut data = Vec::with_capacity(65536);
        for i in 0u32..65536 {
            data.push((i.wrapping_mul(2654435761) >> 24) as u8);
        }
        let e = shannon_entropy(&data);
        assert!(e > 7.5, "pseudo-random data should have high entropy, got {}", e);
    }

    #[test]
    fn test_encrypted_data_high_entropy() {
        use crate::crypto::aead;
        use crate::memory::SecureBuf;

        let key = SecureBuf::random(32).unwrap();
        let nonce = [0x42u8; 24];
        let plaintext = vec![0x00u8; 4096]; // zero plaintext

        let ct = aead::encrypt(
            aead::AeadAlgorithm::XChaCha20Poly1305,
            &key, &nonce, b"", &plaintext,
        ).unwrap();

        let e = shannon_entropy(&ct);
        assert!(e > 7.9, "encrypted data should have entropy > 7.9, got {}", e);
    }

    #[test]
    fn test_classification() {
        assert_eq!(classify_entropy(7.99), "excellent (indistinguishable from random)");
        assert_eq!(classify_entropy(7.6), "good (typical of encrypted/compressed data)");
        assert_eq!(classify_entropy(6.5), "moderate (may contain structure)");
        assert_eq!(classify_entropy(4.5), "low (significant patterns present)");
        assert_eq!(classify_entropy(2.5), "poor (highly structured data)");
        assert_eq!(classify_entropy(1.0), "minimal (near-constant data)");
    }

    #[test]
    fn test_section_entropy() {
        let mut data = Vec::new();
        data.extend(vec![0x00u8; 1000]); // low entropy section
        // High entropy section
        for i in 0..1000 {
            data.push((i as u8).wrapping_mul(137));
        }

        let sections = section_entropy(&data, 2);
        assert_eq!(sections.len(), 2);
        assert!(sections[0].2 < sections[1].2, "first section should have lower entropy");
    }

    #[test]
    fn test_chi_squared_uniform() {
        // A perfectly uniform distribution (each byte appears 256 times)
        let mut data = Vec::with_capacity(65536);
        for _ in 0..256 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let chi2 = chi_squared(&data);
        assert!(chi2 < 0.01, "uniform distribution should have χ² ≈ 0, got {}", chi2);
    }

    #[test]
    fn test_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(chi_squared(&[]), 0.0);
        assert!(section_entropy(&[], 4).is_empty());
    }
}
