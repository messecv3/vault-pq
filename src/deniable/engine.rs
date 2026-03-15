//! Deniable encryption engine.
//!
//! # Design
//!
//! Each "layer" has its own passphrase, content, and file key. The encrypted
//! file contains one passphrase stanza per layer and a body section per layer.
//! Each body section is a complete streaming AEAD encryption of that layer's
//! content, concatenated sequentially.
//!
//! The metadata section (encrypted with each layer's file key) contains a
//! `body_offset` and `body_length` indicating where that layer's encrypted
//! body starts and ends within the file.
//!
//! An observer sees: N passphrase stanzas + one blob of encrypted data.
//! Without trying passphrases, they cannot determine how many layers exist
//! or which stanza maps to which body region.

use crate::crypto::{aead, kdf, stream};
use crate::format::header;
use crate::memory::SecureBuf;
use crate::error::VaultError;

/// A layer in a deniable encryption scheme.
pub struct DeniableLayer {
    /// Passphrase for this layer
    pub passphrase: Vec<u8>,
    /// Plaintext content for this layer
    pub content: Vec<u8>,
}

/// Result of deniable encryption — ready to write to a file.
pub struct DeniableOutput {
    /// All recipient stanzas (one per layer)
    pub stanzas: Vec<header::RecipientStanza>,
    /// Per-layer encrypted metadata, each encrypted with its own file key.
    /// Stored as: (nonce, ciphertext) pairs, concatenated after all stanzas.
    pub metadata_sections: Vec<Vec<u8>>,
    /// Concatenated encrypted bodies.
    pub body: Vec<u8>,
}

/// Encrypt multiple layers deniably.
///
/// Each layer gets its own file key, stanza, metadata, and body section.
/// The output looks like a normal multi-recipient vault file.
pub fn encrypt_deniable(
    layers: &[DeniableLayer],
    algorithm: aead::AeadAlgorithm,
    kdf_params: &kdf::KdfParams,
) -> Result<DeniableOutput, VaultError> {
    if layers.is_empty() {
        return Err(VaultError::InvalidFormat("at least one layer required".into()));
    }
    if layers.len() > 8 {
        return Err(VaultError::InvalidFormat("maximum 8 deniable layers".into()));
    }

    let mut stanzas = Vec::new();
    let mut body_parts: Vec<Vec<u8>> = Vec::new();
    let mut file_keys: Vec<SecureBuf> = Vec::new();

    // Encrypt each layer's body independently
    for layer in layers {
        let file_key = SecureBuf::random(32)?;

        let mut encrypted_body = Vec::new();
        let _plaintext_hash = stream::encrypt_stream(
            &mut layer.content.as_slice(),
            &mut encrypted_body,
            &file_key,
            algorithm,
            stream::DEFAULT_CHUNK_SIZE,
        )?;

        // Create passphrase stanza
        let salt = kdf::generate_salt();
        let derived = kdf::derive_key(layer.passphrase.clone(), &salt, kdf_params)?;
        let encrypted_fk = header::wrap_file_key_passphrase(&derived, &file_key)?;

        stanzas.push(header::RecipientStanza::Passphrase {
            salt,
            params: *kdf_params,
            encrypted_file_key: encrypted_fk,
        });

        file_keys.push(file_key);
        body_parts.push(encrypted_body);
    }

    // Concatenate all body parts, recording offsets
    let mut combined_body = Vec::new();
    let mut offsets = Vec::new();

    for part in &body_parts {
        offsets.push((combined_body.len() as u64, part.len() as u64));
        combined_body.extend_from_slice(part);
    }

    // Build per-layer metadata sections
    let mut metadata_sections = Vec::new();
    for (i, (file_key, (offset, length))) in file_keys.iter().zip(offsets.iter()).enumerate() {
        let meta = DeniableMetadata {
            algorithm,
            chunk_size: stream::DEFAULT_CHUNK_SIZE as u32,
            original_size: layers[i].content.len() as u64,
            body_offset: *offset,
            body_length: *length,
        };

        let meta_bytes = bincode::serialize(&meta)
            .map_err(|e| VaultError::InvalidFormat(format!("deniable metadata: {}", e)))?;

        let mut nonce = [0u8; 24];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);

        let encrypted_meta = aead::encrypt(
            aead::AeadAlgorithm::XChaCha20Poly1305,
            file_key,
            &nonce,
            b"vault-deniable-meta",
            &meta_bytes,
        )?;

        let mut section = Vec::new();
        section.extend_from_slice(&nonce);
        section.extend_from_slice(&(encrypted_meta.len() as u32).to_le_bytes());
        section.extend_from_slice(&encrypted_meta);
        metadata_sections.push(section);
    }

    Ok(DeniableOutput {
        stanzas,
        metadata_sections,
        body: combined_body,
    })
}

/// Decrypt a specific layer from a deniable file.
///
/// Given the file key (recovered from a stanza), this finds and decrypts
/// the corresponding body section.
pub fn decrypt_deniable_layer(
    file_key: &SecureBuf,
    metadata_sections: &[Vec<u8>],
    combined_body: &[u8],
) -> Result<Vec<u8>, VaultError> {
    // Try each metadata section to find one that decrypts with this key
    for section in metadata_sections {
        if section.len() < 24 + 4 {
            continue;
        }

        let nonce = &section[..24];
        let ct_len = u32::from_le_bytes(section[24..28].try_into().unwrap()) as usize;
        if 28 + ct_len > section.len() {
            continue;
        }
        let ct = &section[28..28 + ct_len];

        match aead::decrypt(
            aead::AeadAlgorithm::XChaCha20Poly1305,
            file_key,
            nonce,
            b"vault-deniable-meta",
            ct,
        ) {
            Ok(meta_bytes) => {
                let meta: DeniableMetadata = bincode::deserialize(&meta_bytes)
                    .map_err(|e| VaultError::InvalidFormat(format!("deniable metadata: {}", e)))?;

                // Extract this layer's body
                let start = meta.body_offset as usize;
                let end = start + meta.body_length as usize;
                if end > combined_body.len() {
                    return Err(VaultError::InvalidFormat("body section out of bounds".into()));
                }
                let layer_body = &combined_body[start..end];

                // Decrypt
                let mut decrypted = Vec::new();
                stream::decrypt_stream(
                    &mut &layer_body[..],
                    &mut decrypted,
                    file_key,
                    meta.algorithm,
                    meta.chunk_size as usize,
                )?;

                // Strip to original size
                decrypted.truncate(meta.original_size as usize);
                return Ok(decrypted);
            }
            Err(_) => continue, // Wrong key for this section
        }
    }

    Err(VaultError::AuthenticationFailed)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DeniableMetadata {
    algorithm: aead::AeadAlgorithm,
    chunk_size: u32,
    original_size: u64,
    body_offset: u64,
    body_length: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> kdf::KdfParams {
        kdf::KdfParams::low()
    }

    #[test]
    fn test_two_layer_deniable() {
        let layers = vec![
            DeniableLayer {
                passphrase: b"decoy-pass".to_vec(),
                content: b"This is my grocery list.".to_vec(),
            },
            DeniableLayer {
                passphrase: b"real-pass".to_vec(),
                content: b"This is my actual secret data.".to_vec(),
            },
        ];

        let output = encrypt_deniable(
            &layers,
            aead::AeadAlgorithm::XChaCha20Poly1305,
            &test_params(),
        ).unwrap();

        assert_eq!(output.stanzas.len(), 2);

        // Recover file key for layer 0 (decoy)
        let fk0 = output.stanzas[0].try_unwrap_passphrase(b"decoy-pass").unwrap();
        let decrypted0 = decrypt_deniable_layer(&fk0, &output.metadata_sections, &output.body).unwrap();
        assert_eq!(decrypted0, b"This is my grocery list.");

        // Recover file key for layer 1 (real)
        let fk1 = output.stanzas[1].try_unwrap_passphrase(b"real-pass").unwrap();
        let decrypted1 = decrypt_deniable_layer(&fk1, &output.metadata_sections, &output.body).unwrap();
        assert_eq!(decrypted1, b"This is my actual secret data.");
    }

    #[test]
    fn test_wrong_passphrase_no_layer() {
        let layers = vec![DeniableLayer {
            passphrase: b"correct".to_vec(),
            content: b"secret".to_vec(),
        }];

        let output = encrypt_deniable(
            &layers,
            aead::AeadAlgorithm::XChaCha20Poly1305,
            &test_params(),
        ).unwrap();

        let result = output.stanzas[0].try_unwrap_passphrase(b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_three_layers() {
        let layers = vec![
            DeniableLayer { passphrase: b"one".to_vec(), content: b"layer one content".to_vec() },
            DeniableLayer { passphrase: b"two".to_vec(), content: b"layer two content".to_vec() },
            DeniableLayer { passphrase: b"three".to_vec(), content: b"layer three".to_vec() },
        ];

        let output = encrypt_deniable(
            &layers,
            aead::AeadAlgorithm::XChaCha20Poly1305,
            &test_params(),
        ).unwrap();

        for (i, layer) in layers.iter().enumerate() {
            let fk = output.stanzas[i].try_unwrap_passphrase(&layer.passphrase).unwrap();
            let dec = decrypt_deniable_layer(&fk, &output.metadata_sections, &output.body).unwrap();
            assert_eq!(dec, layer.content);
        }
    }

    #[test]
    fn test_cross_key_isolation() {
        let layers = vec![
            DeniableLayer { passphrase: b"alpha".to_vec(), content: b"alpha data".to_vec() },
            DeniableLayer { passphrase: b"beta".to_vec(), content: b"beta data".to_vec() },
        ];

        let output = encrypt_deniable(
            &layers,
            aead::AeadAlgorithm::XChaCha20Poly1305,
            &test_params(),
        ).unwrap();

        // Alpha's key should NOT decrypt beta's content
        let fk_alpha = output.stanzas[0].try_unwrap_passphrase(b"alpha").unwrap();
        let dec_alpha = decrypt_deniable_layer(&fk_alpha, &output.metadata_sections, &output.body).unwrap();
        assert_eq!(dec_alpha, b"alpha data");
        assert_ne!(dec_alpha, b"beta data");
    }
}
