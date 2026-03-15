//! Encrypted append-only audit log.
//!
//! Each entry is independently encrypted and hash-chained to the previous
//! entry, creating a tamper-evident log. You can add entries without reading
//! previous ones, and each entry can only be decrypted with the log key.
//!
//! # Properties
//!
//! - **Append-only**: entries are hash-chained; insertion/deletion detectable
//! - **Forward integrity**: each entry's nonce is derived from the previous
//!   entry's hash, so reordering is impossible
//! - **Independent decryption**: each entry decrypts independently
//! - **Tamper-evident**: BLAKE3 chain; any modification breaks the chain
//!
//! # Wire Format (per entry)
//!
//! ```text
//! prev_hash     (32 bytes): BLAKE3 hash of previous entry (zeros for first)
//! timestamp     (8 bytes):  Unix timestamp, u64 LE
//! nonce         (24 bytes): derived from prev_hash + entry_index
//! ct_len        (4 bytes):  u32 LE ciphertext length
//! ciphertext    (variable): XChaCha20-Poly1305 encrypted payload + tag
//! entry_hash    (32 bytes): BLAKE3(prev_hash || timestamp || ciphertext)
//! ```

use std::io::{Read, Write, Seek, SeekFrom};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::crypto::aead;
use crate::crypto::hkdf_util;
use crate::memory::SecureBuf;
use crate::error::VaultError;

const LOG_MAGIC: [u8; 8] = *b"VLOG\x00\x01\x00\x00";
const ZERO_HASH: [u8; 32] = [0u8; 32];

/// An audit log entry (decrypted).
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: u64,
    pub payload: Vec<u8>,
    pub entry_index: u64,
}

/// Append an entry to an encrypted audit log file.
///
/// If the file doesn't exist, creates it with the magic header.
/// The entry is encrypted with the log key and hash-chained.
pub fn append_entry(
    path: &std::path::Path,
    log_key: &SecureBuf,
    payload: &[u8],
) -> Result<u64, VaultError> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    // Check if file is new
    let file_len = file.metadata()?.len();
    let (prev_hash, entry_index) = if file_len == 0 {
        // Write magic
        file.write_all(&LOG_MAGIC)?;
        (ZERO_HASH, 0u64)
    } else {
        // Read magic
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if magic != LOG_MAGIC {
            return Err(VaultError::InvalidFormat("not a vault audit log".into()));
        }

        // Find the last entry's hash by scanning to the end
        file.seek(SeekFrom::End(-32))?;
        let mut last_hash = [0u8; 32];
        file.read_exact(&mut last_hash)?;

        // Count entries (scan the file)
        let count = count_entries(&mut file)?;

        // Seek to end for appending
        file.seek(SeekFrom::End(0))?;

        (last_hash, count)
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Derive nonce from prev_hash + entry_index (deterministic, unique per entry)
    let nonce = derive_entry_nonce(log_key, &prev_hash, entry_index)?;

    // Encrypt payload
    let mut aad = Vec::new();
    aad.extend_from_slice(&prev_hash);
    aad.extend_from_slice(&timestamp.to_le_bytes());
    aad.extend_from_slice(&entry_index.to_le_bytes());

    let ciphertext = aead::encrypt(
        aead::AeadAlgorithm::XChaCha20Poly1305,
        log_key,
        nonce.expose(),
        &aad,
        payload,
    )?;

    // Compute entry hash
    let entry_hash = compute_entry_hash(&prev_hash, timestamp, &ciphertext);

    // Write entry
    file.write_all(&prev_hash)?;
    file.write_all(&timestamp.to_le_bytes())?;
    file.write_all(nonce.expose())?;
    file.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
    file.write_all(&ciphertext)?;
    file.write_all(&entry_hash)?;

    file.sync_all()?;

    Ok(entry_index)
}

/// Read and decrypt all entries from an audit log.
pub fn read_entries(
    path: &std::path::Path,
    log_key: &SecureBuf,
) -> Result<Vec<LogEntry>, VaultError> {
    let data = std::fs::read(path)
        .map_err(|_| VaultError::FileNotFound(path.display().to_string()))?;

    if data.len() < 8 || data[..8] != LOG_MAGIC {
        return Err(VaultError::InvalidFormat("not a vault audit log".into()));
    }

    let mut entries = Vec::new();
    let mut pos = 8; // skip magic
    let mut expected_prev_hash = ZERO_HASH;
    let mut entry_index = 0u64;

    while pos < data.len() {
        // prev_hash (32)
        if pos + 32 > data.len() { break; }
        let prev_hash: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
        pos += 32;

        // Verify chain
        if prev_hash != expected_prev_hash {
            return Err(VaultError::InvalidFormat(format!(
                "hash chain broken at entry {}", entry_index
            )));
        }

        // timestamp (8)
        if pos + 8 > data.len() { break; }
        let timestamp = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // nonce (24)
        if pos + 24 > data.len() { break; }
        let nonce = &data[pos..pos + 24];
        pos += 24;

        // ct_len (4)
        if pos + 4 > data.len() { break; }
        let ct_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        // ciphertext
        if pos + ct_len > data.len() { break; }
        let ciphertext = &data[pos..pos + ct_len];
        pos += ct_len;

        // entry_hash (32)
        if pos + 32 > data.len() { break; }
        let stored_hash: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
        pos += 32;

        // Verify entry hash
        let computed_hash = compute_entry_hash(&prev_hash, timestamp, ciphertext);
        if !crate::memory::constant_time_eq(&stored_hash, &computed_hash) {
            return Err(VaultError::InvalidFormat(format!(
                "entry {} hash mismatch — tampered", entry_index
            )));
        }

        // Decrypt
        let mut aad = Vec::new();
        aad.extend_from_slice(&prev_hash);
        aad.extend_from_slice(&timestamp.to_le_bytes());
        aad.extend_from_slice(&entry_index.to_le_bytes());

        let payload = aead::decrypt(
            aead::AeadAlgorithm::XChaCha20Poly1305,
            log_key,
            nonce,
            &aad,
            ciphertext,
        )?;

        entries.push(LogEntry {
            timestamp,
            payload,
            entry_index,
        });

        expected_prev_hash = stored_hash;
        entry_index += 1;
    }

    Ok(entries)
}

/// Verify the integrity of an audit log without decrypting entries.
/// Returns the number of valid entries.
pub fn verify_chain(path: &std::path::Path) -> Result<u64, VaultError> {
    let data = std::fs::read(path)
        .map_err(|_| VaultError::FileNotFound(path.display().to_string()))?;

    if data.len() < 8 || data[..8] != LOG_MAGIC {
        return Err(VaultError::InvalidFormat("not a vault audit log".into()));
    }

    let mut pos = 8;
    let mut expected_prev = ZERO_HASH;
    let mut count = 0u64;

    while pos + 32 + 8 + 24 + 4 <= data.len() {
        let prev: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
        if prev != expected_prev {
            return Err(VaultError::InvalidFormat(format!(
                "chain broken at entry {}", count
            )));
        }
        pos += 32;

        let timestamp = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8 + 24; // skip nonce

        let ct_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if pos + ct_len + 32 > data.len() { break; }
        let ct = &data[pos..pos + ct_len];
        pos += ct_len;

        let stored: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
        let computed = compute_entry_hash(&prev, timestamp, ct);

        if !crate::memory::constant_time_eq(&stored, &computed) {
            return Err(VaultError::InvalidFormat(format!(
                "entry {} hash mismatch", count
            )));
        }

        expected_prev = stored;
        pos += 32;
        count += 1;
    }

    Ok(count)
}

fn compute_entry_hash(prev_hash: &[u8; 32], timestamp: u64, ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_hash);
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(ciphertext);
    *hasher.finalize().as_bytes()
}

fn derive_entry_nonce(
    log_key: &SecureBuf,
    prev_hash: &[u8; 32],
    entry_index: u64,
) -> Result<SecureBuf, VaultError> {
    let mut salt = Vec::new();
    salt.extend_from_slice(prev_hash);
    salt.extend_from_slice(&entry_index.to_le_bytes());

    hkdf_util::derive(log_key.expose(), &salt, b"vault-auditlog-nonce-v1", 24)
}

fn count_entries(file: &mut std::fs::File) -> Result<u64, VaultError> {
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(8))?; // skip magic

    let mut count = 0u64;
    let mut pos = 8u64;

    while pos + 32 + 8 + 24 + 4 <= len {
        pos += 32 + 8 + 24; // prev_hash + timestamp + nonce

        let mut ct_len_buf = [0u8; 4];
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(&mut ct_len_buf)?;
        let ct_len = u32::from_le_bytes(ct_len_buf) as u64;

        pos += 4 + ct_len + 32; // ct_len + ciphertext + entry_hash
        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vlog");
        let key = SecureBuf::random(32).unwrap();

        // Append 3 entries
        append_entry(&path, &key, b"first entry").unwrap();
        append_entry(&path, &key, b"second entry").unwrap();
        append_entry(&path, &key, b"third entry").unwrap();

        // Read all
        let entries = read_entries(&path, &key).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].payload, b"first entry");
        assert_eq!(entries[1].payload, b"second entry");
        assert_eq!(entries[2].payload, b"third entry");
        assert_eq!(entries[0].entry_index, 0);
        assert_eq!(entries[2].entry_index, 2);
    }

    #[test]
    fn test_verify_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test2.vlog");
        let key = SecureBuf::random(32).unwrap();

        append_entry(&path, &key, b"entry a").unwrap();
        append_entry(&path, &key, b"entry b").unwrap();

        let count = verify_chain(&path).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_tampered_entry_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test3.vlog");
        let key = SecureBuf::random(32).unwrap();

        append_entry(&path, &key, b"real data").unwrap();

        // Tamper with the file
        let mut data = std::fs::read(&path).unwrap();
        if data.len() > 50 {
            data[50] ^= 0xFF;
        }
        std::fs::write(&path, &data).unwrap();

        // Verification should fail
        let result = verify_chain(&path);
        assert!(result.is_err() || read_entries(&path, &key).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test4.vlog");
        let key1 = SecureBuf::random(32).unwrap();
        let key2 = SecureBuf::random(32).unwrap();

        append_entry(&path, &key1, b"secret").unwrap();

        let result = read_entries(&path, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamps_increasing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test5.vlog");
        let key = SecureBuf::random(32).unwrap();

        append_entry(&path, &key, b"a").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        append_entry(&path, &key, b"b").unwrap();

        let entries = read_entries(&path, &key).unwrap();
        assert!(entries[1].timestamp >= entries[0].timestamp);
    }
}
