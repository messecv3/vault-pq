//! Vault file format: two-layer header with plaintext stanzas + encrypted metadata.
//!
//! # Format Layout
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ Magic (8 bytes): b"VAULT\x00\x01\x00"                   │
//! ├──────────────────────────────────────────────────────────┤
//! │ Stanza count (2 bytes): u16 LE                           │
//! ├──────────────────────────────────────────────────────────┤
//! │ Recipient Stanzas (plaintext, repeated):                 │
//! │   Type (1 byte): 0x01=public-key, 0x02=passphrase       │
//! │   Stanza length (2 bytes): u16 LE                        │
//! │   Stanza data (variable)                                 │
//! ├──────────────────────────────────────────────────────────┤
//! │ Metadata nonce (24 bytes): random                        │
//! │ Encrypted metadata (variable): XChaCha20-Poly1305        │
//! │   Contains: algorithm, chunk_size, filename, size, etc.  │
//! │ Metadata tag (16 bytes): included in ciphertext          │
//! ├──────────────────────────────────────────────────────────┤
//! │ Encrypted body (chunked AEAD)                            │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! The key insight: recipient stanzas are in plaintext so we can recover
//! the file key WITHOUT already having the file key. The file key then
//! decrypts the metadata section.

use serde::{Deserialize, Serialize};
use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::kdf::KdfParams;
use crate::error::VaultError;
use crate::memory::SecureBuf;

/// Magic bytes: "VAULT\0" + format version 1.0
pub const MAGIC: [u8; 8] = *b"VAULT\x00\x01\x00";

/// Recipient stanza types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StanzaType {
    PublicKey = 0x01,
    Passphrase = 0x02,
}

impl StanzaType {
    pub fn from_byte(b: u8) -> Result<Self, VaultError> {
        match b {
            0x01 => Ok(Self::PublicKey),
            0x02 => Ok(Self::Passphrase),
            _ => Err(VaultError::InvalidFormat(format!("unknown stanza type: 0x{:02x}", b))),
        }
    }
}

/// A recipient stanza — stored in plaintext in the file header.
///
/// Each stanza contains everything needed to recover the file key
/// given the appropriate secret (private key or passphrase).
#[derive(Clone, Debug)]
pub enum RecipientStanza {
    /// Public key: hybrid X25519 + ML-KEM-768
    PublicKey {
        /// Encapsulation data: ephemeral X25519 pk (32) + ML-KEM ciphertext (1088)
        encap_data: Vec<u8>,
        /// File key encrypted with derived shared secret.
        /// Format: nonce (24) + ciphertext+tag (32+16=48)
        encrypted_file_key: Vec<u8>,
    },
    /// Passphrase: Argon2id KDF
    Passphrase {
        /// Random salt (32 bytes)
        salt: [u8; 32],
        /// KDF parameters
        params: KdfParams,
        /// File key encrypted with derived key.
        /// Format: nonce (24) + ciphertext+tag (32+16=48)
        encrypted_file_key: Vec<u8>,
    },
}

impl RecipientStanza {
    /// Serialize a stanza to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::PublicKey { encap_data, encrypted_file_key } => {
                let mut out = Vec::new();
                // Encap data length + data
                out.extend_from_slice(&(encap_data.len() as u16).to_le_bytes());
                out.extend_from_slice(encap_data);
                // Encrypted file key length + data
                out.extend_from_slice(&(encrypted_file_key.len() as u16).to_le_bytes());
                out.extend_from_slice(encrypted_file_key);
                out
            }
            Self::Passphrase { salt, params, encrypted_file_key } => {
                let mut out = Vec::new();
                out.extend_from_slice(salt);
                out.extend_from_slice(&params.to_bytes());
                out.extend_from_slice(&(encrypted_file_key.len() as u16).to_le_bytes());
                out.extend_from_slice(encrypted_file_key);
                out
            }
        }
    }

    /// Deserialize a stanza from bytes given its type.
    pub fn from_bytes(stanza_type: StanzaType, data: &[u8]) -> Result<Self, VaultError> {
        let mut pos = 0;

        match stanza_type {
            StanzaType::PublicKey => {
                if data.len() < 4 {
                    return Err(VaultError::InvalidFormat("public key stanza too short".into()));
                }
                let encap_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                if pos + encap_len > data.len() {
                    return Err(VaultError::InvalidFormat("encap data truncated".into()));
                }
                let encap_data = data[pos..pos + encap_len].to_vec();
                pos += encap_len;

                if pos + 2 > data.len() {
                    return Err(VaultError::InvalidFormat("encrypted file key length missing".into()));
                }
                let efk_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                if pos + efk_len > data.len() {
                    return Err(VaultError::InvalidFormat("encrypted file key truncated".into()));
                }
                let encrypted_file_key = data[pos..pos + efk_len].to_vec();

                Ok(Self::PublicKey { encap_data, encrypted_file_key })
            }
            StanzaType::Passphrase => {
                // salt (32) + params (12) + efk_len (2) + efk (variable)
                if data.len() < 46 {
                    return Err(VaultError::InvalidFormat("passphrase stanza too short".into()));
                }
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&data[pos..pos + 32]);
                pos += 32;

                let params = KdfParams::from_bytes(&data[pos..pos + 12].try_into().unwrap());
                pos += 12;

                let efk_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                if pos + efk_len > data.len() {
                    return Err(VaultError::InvalidFormat("encrypted file key truncated".into()));
                }
                let encrypted_file_key = data[pos..pos + efk_len].to_vec();

                Ok(Self::Passphrase { salt, params, encrypted_file_key })
            }
        }
    }

    /// Try to unwrap the file key using a passphrase.
    /// Returns the file key on success, or error if wrong passphrase.
    pub fn try_unwrap_passphrase(&self, passphrase: &[u8]) -> Result<SecureBuf, VaultError> {
        match self {
            Self::Passphrase { salt, params, encrypted_file_key } => {
                use crate::crypto::{aead, kdf};

                let derived = kdf::derive_key(passphrase.to_vec(), salt, params)?;

                // encrypted_file_key = nonce (24) + ciphertext+tag (48)
                if encrypted_file_key.len() < 24 {
                    return Err(VaultError::InvalidFormat("encrypted file key too short".into()));
                }
                let nonce = &encrypted_file_key[..24];
                let ct = &encrypted_file_key[24..];

                let file_key_bytes = aead::decrypt(
                    AeadAlgorithm::XChaCha20Poly1305,
                    &derived,
                    nonce,
                    b"vault-file-key-wrap",
                    ct,
                )?;

                SecureBuf::from_slice(&file_key_bytes)
            }
            _ => Err(VaultError::AuthenticationFailed),
        }
    }

    /// Try to unwrap the file key using a hybrid secret key.
    pub fn try_unwrap_public_key(
        &self,
        secret_key: &crate::crypto::kem::HybridSecretKey,
    ) -> Result<SecureBuf, VaultError> {
        match self {
            Self::PublicKey { encap_data, encrypted_file_key } => {
                use crate::crypto::{aead, kem};

                let encap = kem::EncapsulationData::from_bytes(encap_data)?;
                let shared_secret = kem::decapsulate(secret_key, &encap)?;

                if encrypted_file_key.len() < 24 {
                    return Err(VaultError::InvalidFormat("encrypted file key too short".into()));
                }
                let nonce = &encrypted_file_key[..24];
                let ct = &encrypted_file_key[24..];

                let file_key_bytes = aead::decrypt(
                    AeadAlgorithm::XChaCha20Poly1305,
                    &shared_secret,
                    nonce,
                    b"vault-file-key-wrap",
                    ct,
                )?;

                SecureBuf::from_slice(&file_key_bytes)
            }
            _ => Err(VaultError::AuthenticationFailed),
        }
    }
}

/// Encrypted metadata — the sensitive part of the header, encrypted with file key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMetadata {
    /// AEAD algorithm used for body encryption
    pub algorithm: AeadAlgorithm,
    /// Chunk size for streaming encryption
    pub chunk_size: u32,
    /// Original filename (if metadata protection is enabled)
    pub original_filename: Option<String>,
    /// Original file size before padding
    pub original_size: u64,
    /// Padding bucket ID
    pub padding_bucket: u8,
    /// BLAKE3 hash of original plaintext (for integrity check after decrypt)
    pub plaintext_hash: Option<[u8; 32]>,
    /// Ed25519 signature over the plaintext hash (optional)
    pub signature: Option<crate::crypto::sig::FileSignature>,
}

impl EncryptedMetadata {
    pub fn serialize(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self)
            .map_err(|e| VaultError::InvalidFormat(format!("metadata serialization: {}", e)))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, VaultError> {
        bincode::deserialize(data)
            .map_err(|e| VaultError::InvalidFormat(format!("metadata deserialization: {}", e)))
    }
}

/// Write a complete vault file header.
///
/// Layout: magic | stanza_count | stanzas... | metadata_nonce | encrypted_metadata
pub fn write_file_header<W: std::io::Write>(
    writer: &mut W,
    stanzas: &[RecipientStanza],
    metadata: &EncryptedMetadata,
    file_key: &SecureBuf,
) -> Result<(), VaultError> {
    use crate::crypto::aead;
    use rand::RngCore;

    // 1. Magic
    writer.write_all(&MAGIC)?;

    // 2. Stanza count
    let stanza_count = stanzas.len() as u16;
    writer.write_all(&stanza_count.to_le_bytes())?;

    // 3. Each stanza: type (1) + data_len (2) + data (variable)
    for stanza in stanzas {
        let (type_byte, data) = match stanza {
            RecipientStanza::PublicKey { .. } => (StanzaType::PublicKey as u8, stanza.to_bytes()),
            RecipientStanza::Passphrase { .. } => (StanzaType::Passphrase as u8, stanza.to_bytes()),
        };
        writer.write_all(&[type_byte])?;
        writer.write_all(&(data.len() as u16).to_le_bytes())?;
        writer.write_all(&data)?;
    }

    // 4. Encrypted metadata
    let meta_bytes = metadata.serialize()?;
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let encrypted_meta = aead::encrypt(
        AeadAlgorithm::XChaCha20Poly1305,
        file_key,
        &nonce,
        &MAGIC, // AAD binds metadata to format version
        &meta_bytes,
    )?;

    writer.write_all(&nonce)?;
    writer.write_all(&(encrypted_meta.len() as u32).to_le_bytes())?;
    writer.write_all(&encrypted_meta)?;

    Ok(())
}

/// Read recipient stanzas from a vault file (plaintext section).
/// Returns the stanzas and the remaining reader positioned at the metadata section.
pub fn read_stanzas<R: std::io::Read>(
    reader: &mut R,
) -> Result<(Vec<RecipientStanza>, [u8; 8]), VaultError> {
    // 1. Magic
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if magic[..5] != MAGIC[..5] {
        return Err(VaultError::InvalidFormat("not a vault file".into()));
    }
    if magic[6] != 0x01 {
        return Err(VaultError::UnsupportedVersion(magic[6], magic[7]));
    }

    // 2. Stanza count
    let mut count_buf = [0u8; 2];
    reader.read_exact(&mut count_buf)?;
    let count = u16::from_le_bytes(count_buf) as usize;

    if count == 0 {
        return Err(VaultError::InvalidFormat("no recipient stanzas".into()));
    }
    if count > 64 {
        return Err(VaultError::InvalidFormat("too many recipient stanzas".into()));
    }

    // 3. Read each stanza
    let mut stanzas = Vec::with_capacity(count);
    for _ in 0..count {
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)?;
        let stanza_type = StanzaType::from_byte(type_buf[0])?;

        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf)?;
        let data_len = u16::from_le_bytes(len_buf) as usize;

        if data_len > 65535 {
            return Err(VaultError::InvalidFormat("stanza data too large".into()));
        }

        let mut data = vec![0u8; data_len];
        reader.read_exact(&mut data)?;

        stanzas.push(RecipientStanza::from_bytes(stanza_type, &data)?);
    }

    Ok((stanzas, magic))
}

/// Read and decrypt the metadata section using the file key.
pub fn read_metadata<R: std::io::Read>(
    reader: &mut R,
    file_key: &SecureBuf,
    magic: &[u8; 8],
) -> Result<EncryptedMetadata, VaultError> {
    use crate::crypto::aead;

    // Nonce
    let mut nonce = [0u8; 24];
    reader.read_exact(&mut nonce)?;

    // Encrypted metadata length
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let encrypted_len = u32::from_le_bytes(len_buf) as usize;

    if encrypted_len > 1_048_576 {
        return Err(VaultError::InvalidFormat("metadata section too large".into()));
    }

    // Encrypted metadata
    let mut encrypted = vec![0u8; encrypted_len];
    reader.read_exact(&mut encrypted)?;

    // Decrypt
    let meta_bytes = aead::decrypt(
        AeadAlgorithm::XChaCha20Poly1305,
        file_key,
        &nonce,
        magic,
        &encrypted,
    ).map_err(|_| VaultError::HeaderCorrupted)?;

    EncryptedMetadata::deserialize(&meta_bytes)
}

/// Encrypt a file key for a passphrase recipient.
pub fn wrap_file_key_passphrase(
    derived_key: &SecureBuf,
    file_key: &SecureBuf,
) -> Result<Vec<u8>, VaultError> {
    use crate::crypto::aead;
    use rand::RngCore;

    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ct = aead::encrypt(
        AeadAlgorithm::XChaCha20Poly1305,
        derived_key,
        &nonce,
        b"vault-file-key-wrap",
        file_key.expose(),
    )?;

    // nonce || ciphertext+tag
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Encrypt a file key for a public-key recipient.
pub fn wrap_file_key_public(
    shared_secret: &SecureBuf,
    file_key: &SecureBuf,
) -> Result<Vec<u8>, VaultError> {
    // Same wrapping mechanism, different AAD could be used but we keep it consistent
    wrap_file_key_passphrase(shared_secret, file_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::SecureBuf;

    #[test]
    fn test_passphrase_stanza_round_trip() {
        let stanza = RecipientStanza::Passphrase {
            salt: [0x42; 32],
            params: KdfParams::default(),
            encrypted_file_key: vec![0xAB; 72], // nonce(24) + ct+tag(48)
        };

        let bytes = stanza.to_bytes();
        let restored = RecipientStanza::from_bytes(StanzaType::Passphrase, &bytes).unwrap();

        match restored {
            RecipientStanza::Passphrase { salt, params, encrypted_file_key } => {
                assert_eq!(salt, [0x42; 32]);
                assert_eq!(params.memory_kib, KdfParams::default().memory_kib);
                assert_eq!(encrypted_file_key.len(), 72);
            }
            _ => panic!("wrong stanza type"),
        }
    }

    #[test]
    fn test_public_key_stanza_round_trip() {
        let stanza = RecipientStanza::PublicKey {
            encap_data: vec![0x01; 1120], // 32 + 1088
            encrypted_file_key: vec![0x02; 72],
        };

        let bytes = stanza.to_bytes();
        let restored = RecipientStanza::from_bytes(StanzaType::PublicKey, &bytes).unwrap();

        match restored {
            RecipientStanza::PublicKey { encap_data, encrypted_file_key } => {
                assert_eq!(encap_data.len(), 1120);
                assert_eq!(encrypted_file_key.len(), 72);
            }
            _ => panic!("wrong stanza type"),
        }
    }

    #[test]
    fn test_metadata_serialization() {
        let meta = EncryptedMetadata {
            algorithm: AeadAlgorithm::XChaCha20Poly1305,
            chunk_size: 65536,
            original_filename: Some("secret.txt".into()),
            original_size: 1234,
            padding_bucket: 0x03,
            plaintext_hash: Some([0xAA; 32]),
            signature: None,
        };

        let bytes = meta.serialize().unwrap();
        let restored = EncryptedMetadata::deserialize(&bytes).unwrap();

        assert_eq!(restored.original_filename, Some("secret.txt".into()));
        assert_eq!(restored.original_size, 1234);
        assert_eq!(restored.chunk_size, 65536);
        assert_eq!(restored.plaintext_hash, Some([0xAA; 32]));
    }

    #[test]
    fn test_full_header_round_trip() {
        let file_key = SecureBuf::random(32).unwrap();

        let stanzas = vec![RecipientStanza::Passphrase {
            salt: [0x42; 32],
            params: KdfParams::low(),
            encrypted_file_key: vec![0xAB; 72],
        }];

        let metadata = EncryptedMetadata {
            algorithm: AeadAlgorithm::XChaCha20Poly1305,
            chunk_size: 65536,
            original_filename: Some("test.txt".into()),
            original_size: 42,
            padding_bucket: 0x01,
            plaintext_hash: None,
            signature: None,
        };

        // Write
        let mut buf = Vec::new();
        write_file_header(&mut buf, &stanzas, &metadata, &file_key).unwrap();

        // Read stanzas
        let mut cursor = std::io::Cursor::new(&buf);
        let (read_stanzas, magic) = read_stanzas(&mut cursor).unwrap();
        assert_eq!(read_stanzas.len(), 1);

        // Read metadata
        let read_meta = read_metadata(&mut cursor, &file_key, &magic).unwrap();
        assert_eq!(read_meta.original_filename, Some("test.txt".into()));
        assert_eq!(read_meta.original_size, 42);
    }

    #[test]
    fn test_wrong_file_key_fails_metadata() {
        let file_key = SecureBuf::random(32).unwrap();
        let wrong_key = SecureBuf::random(32).unwrap();

        let stanzas = vec![RecipientStanza::Passphrase {
            salt: [0x01; 32],
            params: KdfParams::low(),
            encrypted_file_key: vec![0x00; 72],
        }];

        let metadata = EncryptedMetadata {
            algorithm: AeadAlgorithm::XChaCha20Poly1305,
            chunk_size: 65536,
            original_filename: None,
            original_size: 0,
            padding_bucket: 0xFF,
            plaintext_hash: None,
            signature: None,
        };

        let mut buf = Vec::new();
        write_file_header(&mut buf, &stanzas, &metadata, &file_key).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let (_, magic) = read_stanzas(&mut cursor).unwrap();
        let result = read_metadata(&mut cursor, &wrong_key, &magic);
        assert!(result.is_err());
    }

    #[test]
    fn test_passphrase_wrap_unwrap() {
        let file_key = SecureBuf::random(32).unwrap();
        let passphrase = b"correct horse battery staple";
        let salt = crate::crypto::kdf::generate_salt();
        let params = KdfParams::low();

        let derived = crate::crypto::kdf::derive_key(
            passphrase.to_vec(), &salt, &params
        ).unwrap();

        let encrypted_fk = wrap_file_key_passphrase(&derived, &file_key).unwrap();

        let stanza = RecipientStanza::Passphrase {
            salt,
            params,
            encrypted_file_key: encrypted_fk,
        };

        // Correct passphrase
        let recovered = stanza.try_unwrap_passphrase(passphrase).unwrap();
        assert_eq!(recovered.expose(), file_key.expose());

        // Wrong passphrase
        let result = stanza.try_unwrap_passphrase(b"wrong passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_wrap_unwrap() {
        let file_key = SecureBuf::random(32).unwrap();
        let (pk, sk) = crate::crypto::kem::generate_keypair();

        let (shared_secret, encap) = crate::crypto::kem::encapsulate(&pk).unwrap();
        let encrypted_fk = wrap_file_key_public(&shared_secret, &file_key).unwrap();

        let stanza = RecipientStanza::PublicKey {
            encap_data: encap.to_bytes(),
            encrypted_file_key: encrypted_fk,
        };

        let recovered = stanza.try_unwrap_public_key(&sk).unwrap();
        assert_eq!(recovered.expose(), file_key.expose());
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let data = b"NOT_VAULT_FILE_AT_ALL";
        let mut cursor = std::io::Cursor::new(&data[..]);
        let result = read_stanzas(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_recipient_header() {
        let file_key = SecureBuf::random(32).unwrap();

        let stanzas = vec![
            RecipientStanza::Passphrase {
                salt: [0x01; 32],
                params: KdfParams::low(),
                encrypted_file_key: vec![0xAA; 72],
            },
            RecipientStanza::Passphrase {
                salt: [0x02; 32],
                params: KdfParams::low(),
                encrypted_file_key: vec![0xBB; 72],
            },
        ];

        let metadata = EncryptedMetadata {
            algorithm: AeadAlgorithm::Aes256Gcm,
            chunk_size: 32768,
            original_filename: None,
            original_size: 0,
            padding_bucket: 0xFF,
            plaintext_hash: None,
            signature: None,
        };

        let mut buf = Vec::new();
        write_file_header(&mut buf, &stanzas, &metadata, &file_key).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let (read_stanzas, magic) = read_stanzas(&mut cursor).unwrap();
        assert_eq!(read_stanzas.len(), 2);

        let read_meta = read_metadata(&mut cursor, &file_key, &magic).unwrap();
        assert_eq!(read_meta.chunk_size, 32768);
    }
}
