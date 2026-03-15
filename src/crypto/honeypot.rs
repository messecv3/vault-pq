//! Honeypot/tripwire vault files.
//!
//! Generates vault files that look identical to real encrypted files but
//! contain a hidden fingerprint that identifies the decryptor. When a
//! honeypot file is decrypted, the "plaintext" contains:
//!
//! 1. Decoy content (looks real — a document, spreadsheet, etc.)
//! 2. An invisible fingerprint embedded in the decoy content
//!
//! The fingerprint is derived from the passphrase used to decrypt,
//! so different passphrases produce different fingerprints — you can
//! determine WHICH credential was compromised.
//!
//! # Use Cases
//!
//! - Place honeypot files in sensitive directories to detect unauthorized access
//! - Distribute different passphrases to different people to identify leaks
//! - Canary files that prove a breach occurred
//!
//! # Properties
//!
//! - Indistinguishable from real vault files (same format, same entropy)
//! - Fingerprint survives copy/paste of the decrypted content
//! - Multiple passphrases can decrypt to different-looking decoy content
//!   with different embedded fingerprints

use crate::crypto::{aead, kdf, stream};
use crate::format::header;
use crate::memory::SecureBuf;
use crate::error::VaultError;

/// A honeypot configuration.
pub struct HoneypotConfig {
    /// Decoy content that the decryptor will see
    pub decoy_content: Vec<u8>,
    /// Passphrase for this honeypot
    pub passphrase: Vec<u8>,
    /// Human-readable label for this credential (e.g., "given_to_alice")
    pub label: String,
}

/// Result of honeypot creation.
pub struct HoneypotResult {
    /// The encrypted vault file bytes
    pub file_data: Vec<u8>,
    /// Per-credential fingerprints for later identification
    pub fingerprints: Vec<HoneypotFingerprint>,
}

/// A fingerprint record — store these securely to identify which credential was used.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HoneypotFingerprint {
    /// Human label (e.g., "given_to_alice")
    pub label: String,
    /// BLAKE3 hash of the fingerprint marker embedded in the decoy content
    pub marker_hash: [u8; 32],
    /// The fingerprint marker itself (hidden in content)
    pub marker: Vec<u8>,
}

/// Generate a unique fingerprint marker derived from the passphrase.
/// This marker is embedded invisibly in the decoy content.
fn generate_marker(passphrase: &[u8], label: &str) -> Vec<u8> {
    // Derive a deterministic marker from passphrase + label
    // Using BLAKE3 keyed hash so the marker is unique per credential
    let mut key = [0u8; 32];
    let hash = blake3::hash(passphrase);
    key.copy_from_slice(hash.as_bytes());

    let marker_input = format!("vault-honeypot-marker-{}", label);
    let marker_hash = blake3::keyed_hash(&key, marker_input.as_bytes());

    // Use first 16 bytes as the marker — enough to be unique, small enough to hide
    marker_hash.as_bytes()[..16].to_vec()
}

/// Embed a fingerprint marker into text content using zero-width Unicode characters.
///
/// The marker is encoded as a sequence of zero-width spaces (U+200B) and
/// zero-width non-joiners (U+200C) inserted between words. This is invisible
/// in most text renderers but survives copy/paste.
fn embed_marker_in_text(content: &str, marker: &[u8]) -> String {
    let zwsp = '\u{200B}'; // zero-width space = 0 bit
    let zwnj = '\u{200C}'; // zero-width non-joiner = 1 bit

    // Encode marker as binary using zero-width characters
    let mut encoded = String::new();
    for byte in marker {
        for bit in (0..8).rev() {
            if (byte >> bit) & 1 == 1 {
                encoded.push(zwnj);
            } else {
                encoded.push(zwsp);
            }
        }
    }

    // Insert the encoded marker after the first space in the content
    if let Some(first_space) = content.find(' ') {
        let (before, after) = content.split_at(first_space + 1);
        format!("{}{}{}", before, encoded, after)
    } else {
        // No space — append to end
        format!("{}{}", content, encoded)
    }
}

/// Extract a fingerprint marker from text content.
pub fn extract_marker_from_text(content: &str) -> Option<Vec<u8>> {
    let zwsp = '\u{200B}';
    let zwnj = '\u{200C}';

    // Collect all zero-width characters
    let bits: Vec<u8> = content
        .chars()
        .filter_map(|c| {
            if c == zwsp { Some(0) }
            else if c == zwnj { Some(1) }
            else { None }
        })
        .collect();

    if bits.len() < 8 {
        return None;
    }

    // Decode bits to bytes
    let num_bytes = bits.len() / 8;
    let mut marker = Vec::with_capacity(num_bytes);
    for chunk in bits.chunks_exact(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            byte |= bit << (7 - i);
        }
        marker.push(byte);
    }

    Some(marker)
}

/// Create a honeypot vault file with embedded fingerprints.
pub fn create_honeypot(
    configs: &[HoneypotConfig],
    algorithm: aead::AeadAlgorithm,
) -> Result<HoneypotResult, VaultError> {
    if configs.is_empty() {
        return Err(VaultError::InvalidFormat("at least one honeypot config required".into()));
    }

    let kdf_params = kdf::KdfParams::low(); // Use low for honeypots (faster generation)
    let mut fingerprints = Vec::new();
    let mut stanzas = Vec::new();
    // All configs use the same file key — each stanza wraps it differently
    let primary_file_key = SecureBuf::random(32)?;

    for config in configs {
        let marker = generate_marker(&config.passphrase, &config.label);
        let marker_hash = *blake3::hash(&marker).as_bytes();

        fingerprints.push(HoneypotFingerprint {
            label: config.label.clone(),
            marker_hash,
            marker: marker.clone(),
        });

        // Create passphrase stanza
        let salt = kdf::generate_salt();
        let derived = kdf::derive_key(config.passphrase.clone(), &salt, &kdf_params)?;
        let encrypted_fk = header::wrap_file_key_passphrase(&derived, &primary_file_key)?;

        stanzas.push(header::RecipientStanza::Passphrase {
            salt,
            params: kdf_params,
            encrypted_file_key: encrypted_fk,
        });
    }

    // Embed marker from first config into the decoy content
    let marker = &fingerprints[0].marker;
    let decoy_str = String::from_utf8_lossy(&configs[0].decoy_content);
    let marked_content = embed_marker_in_text(&decoy_str, marker);
    let marked_bytes = marked_content.into_bytes();

    // Encrypt the marked content
    let mut body = Vec::new();
    let hash = stream::encrypt_stream(
        &mut marked_bytes.as_slice(),
        &mut body,
        &primary_file_key,
        algorithm,
        stream::DEFAULT_CHUNK_SIZE,
    )?;

    let metadata = header::EncryptedMetadata {
        algorithm,
        chunk_size: stream::DEFAULT_CHUNK_SIZE as u32,
        original_filename: Some("confidential_report.txt".into()),
        original_size: marked_bytes.len() as u64,
        padding_bucket: 0xFF,
        plaintext_hash: Some(hash),
        signature: None,
    };

    let mut file_data = Vec::new();
    header::write_file_header(&mut file_data, &stanzas, &metadata, &primary_file_key)?;
    file_data.extend_from_slice(&body);

    Ok(HoneypotResult {
        file_data,
        fingerprints,
    })
}

/// Check decrypted content for a honeypot fingerprint.
/// Returns the matching fingerprint if found.
pub fn check_for_fingerprint<'a>(
    content: &str,
    known_fingerprints: &'a [HoneypotFingerprint],
) -> Option<&'a HoneypotFingerprint> {
    let extracted = extract_marker_from_text(content)?;
    let extracted_hash = *blake3::hash(&extracted).as_bytes();

    known_fingerprints.iter().find(|fp| {
        crate::memory::constant_time_eq(&fp.marker_hash, &extracted_hash)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_generation_deterministic() {
        let m1 = generate_marker(b"password", "alice");
        let m2 = generate_marker(b"password", "alice");
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_different_passphrases_different_markers() {
        let m1 = generate_marker(b"pass1", "label");
        let m2 = generate_marker(b"pass2", "label");
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_different_labels_different_markers() {
        let m1 = generate_marker(b"pass", "alice");
        let m2 = generate_marker(b"pass", "bob");
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_embed_extract_marker() {
        let marker = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let content = "This is a secret document with important information.";

        let marked = embed_marker_in_text(content, &marker);

        // Visible text should be preserved
        let visible: String = marked.chars()
            .filter(|c| *c != '\u{200B}' && *c != '\u{200C}')
            .collect();
        assert_eq!(visible, content);

        // Extract should recover the marker
        let extracted = extract_marker_from_text(&marked).unwrap();
        assert_eq!(extracted, marker);
    }

    #[test]
    fn test_marker_survives_in_content() {
        let marker = generate_marker(b"secret_pass", "suspect_alice");
        let content = "Q3 Revenue Report - Confidential - Do Not Distribute";

        let marked = embed_marker_in_text(content, &marker);
        let extracted = extract_marker_from_text(&marked).unwrap();

        assert_eq!(extracted, marker);
    }

    #[test]
    fn test_honeypot_creation() {
        let configs = vec![
            HoneypotConfig {
                decoy_content: b"Employee salary data for 2026 Q1".to_vec(),
                passphrase: b"leaked_password_1".to_vec(),
                label: "given_to_hr_team".into(),
            },
            HoneypotConfig {
                decoy_content: b"Board meeting notes - confidential".to_vec(),
                passphrase: b"leaked_password_2".to_vec(),
                label: "given_to_exec_team".into(),
            },
        ];

        let result = create_honeypot(
            &configs,
            aead::AeadAlgorithm::XChaCha20Poly1305,
        ).unwrap();

        assert_eq!(result.fingerprints.len(), 2);
        assert_ne!(result.fingerprints[0].marker, result.fingerprints[1].marker);

        // The vault file should be decryptable with either passphrase
        let mut cursor = std::io::Cursor::new(&result.file_data);
        let (stanzas, _) = header::read_stanzas(&mut cursor).unwrap();
        assert_eq!(stanzas.len(), 2);

        assert!(stanzas[0].try_unwrap_passphrase(b"leaked_password_1").is_ok());
        assert!(stanzas[1].try_unwrap_passphrase(b"leaked_password_2").is_ok());
    }

    #[test]
    fn test_fingerprint_identification() {
        let fingerprints = vec![
            HoneypotFingerprint {
                label: "alice".into(),
                marker_hash: *blake3::hash(&[0xAA; 16]).as_bytes(),
                marker: vec![0xAA; 16],
            },
            HoneypotFingerprint {
                label: "bob".into(),
                marker_hash: *blake3::hash(&[0xBB; 16]).as_bytes(),
                marker: vec![0xBB; 16],
            },
        ];

        let content = embed_marker_in_text("test content here", &[0xBB; 16]);
        let found = check_for_fingerprint(&content, &fingerprints);
        assert!(found.is_some());
        assert_eq!(found.unwrap().label, "bob");
    }
}
