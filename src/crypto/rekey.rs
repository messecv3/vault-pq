//! Key rotation without re-encryption.
//!
//! The body is encrypted with a random `file_key`. Recipient stanzas wrap
//! copies of that `file_key` for each authorized recipient.
//!
//! Re-keying = replacing the stanza section without touching the body.
//! This is O(stanzas) instead of O(file_size), enabling instant key rotation
//! on multi-gigabyte files.
//!
//! # Security
//!
//! - The file key itself never changes (body stays the same)
//! - Old stanzas are overwritten/removed (old recipients lose access)
//! - New stanzas are added (new recipients gain access)
//! - The metadata section is re-encrypted with the same file key
//! - Forward secrecy: old recipients cannot derive the file key from new stanzas

use crate::crypto::{kdf, kem};
use crate::format::header;
use crate::memory::SecureBuf;
use crate::error::VaultError;

/// Descriptor for a new recipient to add during re-keying.
pub enum NewRecipient {
    Passphrase {
        passphrase: Vec<u8>,
        params: kdf::KdfParams,
    },
    PublicKey {
        public_key: kem::HybridPublicKey,
    },
}

/// Re-key a vault file: replace all recipient stanzas without re-encrypting the body.
///
/// Requires the current file key (recovered from an existing stanza).
/// Returns the new file contents.
pub fn rekey(
    file_data: &[u8],
    current_file_key: &SecureBuf,
    new_recipients: &[NewRecipient],
) -> Result<Vec<u8>, VaultError> {
    if new_recipients.is_empty() {
        return Err(VaultError::NoRecipient);
    }

    // Parse original file to find where the body starts
    let mut cursor = std::io::Cursor::new(file_data);
    let (_old_stanzas, magic) = header::read_stanzas(&mut cursor)?;

    // Verify we can decrypt the metadata with this key
    let metadata = header::read_metadata(&mut cursor, current_file_key, &magic)?;
    let body_start = cursor.position() as usize;
    let body = &file_data[body_start..];

    // Build new stanzas
    let mut new_stanzas = Vec::new();
    for recipient in new_recipients {
        match recipient {
            NewRecipient::Passphrase { passphrase, params } => {
                let salt = kdf::generate_salt();
                let derived = kdf::derive_key(passphrase.clone(), &salt, params)?;
                let encrypted_fk = header::wrap_file_key_passphrase(&derived, current_file_key)?;
                new_stanzas.push(header::RecipientStanza::Passphrase {
                    salt,
                    params: *params,
                    encrypted_file_key: encrypted_fk,
                });
            }
            NewRecipient::PublicKey { public_key } => {
                let (shared_secret, encap) = kem::encapsulate(public_key)?;
                let encrypted_fk = header::wrap_file_key_public(&shared_secret, current_file_key)?;
                new_stanzas.push(header::RecipientStanza::PublicKey {
                    encap_data: encap.to_bytes(),
                    encrypted_file_key: encrypted_fk,
                });
            }
        }
    }

    // Rebuild the file: new header + same metadata (re-encrypted) + same body
    let mut output = Vec::new();
    header::write_file_header(&mut output, &new_stanzas, &metadata, current_file_key)?;
    output.extend_from_slice(body);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead;

    #[test]
    fn test_rekey_passphrase_to_passphrase() {
        // Encrypt with passphrase A
        let file_key = SecureBuf::random(32).unwrap();
        let salt = kdf::generate_salt();
        let params = kdf::KdfParams::low();
        let derived_a = kdf::derive_key(b"passA".to_vec(), &salt, &params).unwrap();
        let efk_a = header::wrap_file_key_passphrase(&derived_a, &file_key).unwrap();

        let stanza_a = header::RecipientStanza::Passphrase {
            salt, params, encrypted_file_key: efk_a,
        };

        let metadata = header::EncryptedMetadata {
            algorithm: aead::AeadAlgorithm::XChaCha20Poly1305,
            chunk_size: 65536,
            original_filename: Some("test.txt".into()),
            original_size: 5,
            padding_bucket: 0xFF,
            plaintext_hash: None,
            signature: None,
        };

        // Create encrypted body
        let mut body = Vec::new();
        crate::crypto::stream::encrypt_stream(
            &mut &b"hello"[..], &mut body, &file_key,
            aead::AeadAlgorithm::XChaCha20Poly1305, 65536,
        ).unwrap();

        // Build original file
        let mut original = Vec::new();
        header::write_file_header(&mut original, &[stanza_a], &metadata, &file_key).unwrap();
        original.extend_from_slice(&body);

        // Re-key: passA -> passB
        let rekeyed = rekey(
            &original,
            &file_key,
            &[NewRecipient::Passphrase {
                passphrase: b"passB".to_vec(),
                params,
            }],
        ).unwrap();

        // Old passphrase should NOT work
        let mut cursor = std::io::Cursor::new(&rekeyed);
        let (stanzas, _) = header::read_stanzas(&mut cursor).unwrap();
        assert!(stanzas[0].try_unwrap_passphrase(b"passA").is_err());

        // New passphrase SHOULD work
        let fk = stanzas[0].try_unwrap_passphrase(b"passB").unwrap();
        assert_eq!(fk.expose(), file_key.expose());
    }

    #[test]
    fn test_rekey_add_recipient() {
        let file_key = SecureBuf::random(32).unwrap();
        let params = kdf::KdfParams::low();

        let salt = kdf::generate_salt();
        let derived = kdf::derive_key(b"original".to_vec(), &salt, &params).unwrap();
        let efk = header::wrap_file_key_passphrase(&derived, &file_key).unwrap();
        let stanza = header::RecipientStanza::Passphrase {
            salt, params, encrypted_file_key: efk,
        };

        let metadata = header::EncryptedMetadata {
            algorithm: aead::AeadAlgorithm::XChaCha20Poly1305,
            chunk_size: 65536, original_filename: None, original_size: 0,
            padding_bucket: 0xFF, plaintext_hash: None, signature: None,
        };

        let mut body = Vec::new();
        crate::crypto::stream::encrypt_stream(
            &mut &b""[..], &mut body, &file_key,
            aead::AeadAlgorithm::XChaCha20Poly1305, 65536,
        ).unwrap();

        let mut original = Vec::new();
        header::write_file_header(&mut original, &[stanza], &metadata, &file_key).unwrap();
        original.extend_from_slice(&body);

        // Re-key: replace with TWO new recipients
        let (pk, sk) = kem::generate_keypair();
        let rekeyed = rekey(
            &original,
            &file_key,
            &[
                NewRecipient::Passphrase { passphrase: b"new_pass".to_vec(), params },
                NewRecipient::PublicKey { public_key: pk },
            ],
        ).unwrap();

        let mut cursor = std::io::Cursor::new(&rekeyed);
        let (stanzas, _) = header::read_stanzas(&mut cursor).unwrap();
        assert_eq!(stanzas.len(), 2);

        // Both should work
        assert!(stanzas[0].try_unwrap_passphrase(b"new_pass").is_ok());
        assert!(stanzas[1].try_unwrap_public_key(&sk).is_ok());
    }
}
