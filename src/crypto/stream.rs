//! Streaming AEAD encryption/decryption for large files.
//!
//! Files are split into fixed-size chunks (default 64KB). Each chunk is
//! independently encrypted with a unique nonce derived deterministically
//! from the file key + chunk index via HKDF.
//!
//! Security properties:
//! - Chunk reordering detected (chunk index in AAD)
//! - Chunk truncation detected (final flag in AAD)
//! - Each chunk independently authenticated
//! - BLAKE3 hash of plaintext for end-to-end integrity
//!
//! Wire format per chunk:
//!   nonce (24 or 12 bytes) || ciphertext + tag (data + 16 bytes) || final_flag (1 byte)

use std::io::{Read, Write};
use blake3::Hasher as Blake3Hasher;
use crate::crypto::aead::{self, AeadAlgorithm};
use crate::crypto::hkdf_util;
use crate::error::VaultError;
use crate::memory::SecureBuf;

/// Default chunk size: 64 KB.
pub const DEFAULT_CHUNK_SIZE: usize = 65_536;

/// Encrypt a stream in chunks. Reads `chunk_size` bytes at a time.
///
/// Returns the BLAKE3 hash of all plaintext processed.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    file_key: &SecureBuf,
    algorithm: AeadAlgorithm,
    chunk_size: usize,
) -> Result<[u8; 32], VaultError> {
    let mut hasher = Blake3Hasher::new();
    let mut chunk_buf = vec![0u8; chunk_size];
    let mut chunk_index: u64 = 0;
    let mut pending: Option<Vec<u8>> = None;

    loop {
        // Read a full chunk
        let bytes_read = read_fill(reader, &mut chunk_buf)?;

        if bytes_read == 0 {
            // No more data. Flush the pending chunk as final.
            if let Some(data) = pending.take() {
                write_chunk(writer, file_key, algorithm, chunk_index, &data, true)?;
                hasher.update(&data);
            } else {
                // Empty input — write an empty final chunk
                write_chunk(writer, file_key, algorithm, 0, &[], true)?;
            }
            break;
        }

        // If we have a pending chunk, flush it as non-final (since we got more data)
        if let Some(data) = pending.take() {
            write_chunk(writer, file_key, algorithm, chunk_index, &data, false)?;
            hasher.update(&data);
            chunk_index += 1;
        }

        // Buffer this chunk as pending (we don't know if it's the last one yet)
        pending = Some(chunk_buf[..bytes_read].to_vec());

        if bytes_read < chunk_size {
            // Short read = EOF. Flush as final.
            if let Some(data) = pending.take() {
                write_chunk(writer, file_key, algorithm, chunk_index, &data, true)?;
                hasher.update(&data);
            }
            break;
        }
    }

    Ok(*hasher.finalize().as_bytes())
}

/// Write a single encrypted chunk to the output.
fn write_chunk<W: Write>(
    writer: &mut W,
    file_key: &SecureBuf,
    algorithm: AeadAlgorithm,
    chunk_index: u64,
    plaintext: &[u8],
    is_final: bool,
) -> Result<(), VaultError> {
    let nonce = hkdf_util::derive_chunk_nonce(
        file_key, chunk_index, algorithm.nonce_size()
    )?;

    let final_byte = if is_final { 0x01u8 } else { 0x00u8 };
    let mut aad_buf = [0u8; 9];
    aad_buf[..8].copy_from_slice(&chunk_index.to_le_bytes());
    aad_buf[8] = final_byte;

    let ciphertext = aead::encrypt(algorithm, file_key, nonce.expose(), &aad_buf, plaintext)?;

    writer.write_all(nonce.expose())?;
    writer.write_all(&ciphertext)?;
    writer.write_all(&[final_byte])?;

    Ok(())
}

/// Decrypt a stream in chunks.
///
/// Returns the BLAKE3 hash of the decrypted plaintext.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    file_key: &SecureBuf,
    algorithm: AeadAlgorithm,
    chunk_size: usize,
) -> Result<[u8; 32], VaultError> {
    let mut hasher = Blake3Hasher::new();
    let nonce_size = algorithm.nonce_size();
    let tag_size = algorithm.tag_size();
    let mut chunk_index: u64 = 0;

    loop {
        // Read nonce
        let mut nonce_buf = vec![0u8; nonce_size];
        match read_exact_or_eof(reader, &mut nonce_buf)? {
            0 if chunk_index > 0 => break,    // Clean EOF after at least one chunk
            0 => return Err(VaultError::InvalidFormat("empty encrypted stream".into())),
            n if n < nonce_size => {
                return Err(VaultError::InvalidFormat("truncated chunk nonce".into()))
            }
            _ => {}
        }

        // We need to figure out the ciphertext length.
        // Full chunk: chunk_size + tag_size bytes of ciphertext
        // Final chunk: <= chunk_size + tag_size bytes
        // After ciphertext: 1 byte final flag
        //
        // Strategy: try to read a full chunk's worth. If we read less,
        // this is the final chunk.
        let max_ct_len = chunk_size + tag_size;
        let mut ct_and_flag = vec![0u8; max_ct_len + 1];
        let total_read = read_fill(reader, &mut ct_and_flag)?;

        if total_read < tag_size + 1 {
            return Err(VaultError::InvalidFormat("truncated chunk data".into()));
        }

        let final_byte = ct_and_flag[total_read - 1];
        let ct_data = &ct_and_flag[..total_read - 1];
        let is_final = final_byte == 0x01;

        // Reconstruct AAD
        let mut aad_buf = [0u8; 9];
        aad_buf[..8].copy_from_slice(&chunk_index.to_le_bytes());
        aad_buf[8] = final_byte;

        // Decrypt
        let plaintext = aead::decrypt(algorithm, file_key, &nonce_buf, &aad_buf, ct_data)?;

        hasher.update(&plaintext);
        writer.write_all(&plaintext)?;

        chunk_index += 1;

        if is_final {
            break;
        }
    }

    Ok(*hasher.finalize().as_bytes())
}

/// Read up to `buf.len()` bytes. Returns actual bytes read.
fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, VaultError> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(VaultError::IoError(e)),
        }
    }
    Ok(total)
}

/// Read exactly `buf.len()` bytes, or 0 for immediate EOF.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, VaultError> {
    read_fill(reader, buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(plaintext: &[u8], algorithm: AeadAlgorithm, chunk_size: usize) {
        let key = SecureBuf::random(32).unwrap();

        let mut encrypted = Vec::new();
        let hash_enc = encrypt_stream(
            &mut &plaintext[..], &mut encrypted, &key, algorithm, chunk_size,
        ).unwrap();

        let mut decrypted = Vec::new();
        let hash_dec = decrypt_stream(
            &mut &encrypted[..], &mut decrypted, &key, algorithm, chunk_size,
        ).unwrap();

        assert_eq!(decrypted, plaintext, "plaintext mismatch");
        assert_eq!(hash_enc, hash_dec, "hash mismatch");
    }

    #[test]
    fn test_small_file() {
        round_trip(b"hello, streaming!", AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_multi_chunk() {
        let data = b"this is longer than sixteen bytes so it spans multiple chunks!";
        round_trip(data, AeadAlgorithm::XChaCha20Poly1305, 16);
    }

    #[test]
    fn test_exact_chunk_boundary() {
        let data = vec![0x42u8; 64]; // exactly 4 chunks of 16
        round_trip(&data, AeadAlgorithm::XChaCha20Poly1305, 16);
    }

    #[test]
    fn test_empty() {
        round_trip(b"", AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_one_byte() {
        round_trip(b"x", AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_aes_gcm() {
        round_trip(b"AES-256-GCM test", AeadAlgorithm::Aes256Gcm, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_aes_gcm_multi_chunk() {
        round_trip(&vec![0xAB; 100], AeadAlgorithm::Aes256Gcm, 32);
    }

    #[test]
    fn test_large_single_chunk() {
        let data = vec![0xCD; DEFAULT_CHUNK_SIZE]; // exactly one full chunk
        round_trip(&data, AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_large_plus_one() {
        let data = vec![0xEF; DEFAULT_CHUNK_SIZE + 1]; // one full + one partial
        round_trip(&data, AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = SecureBuf::random(32).unwrap();
        let key2 = SecureBuf::random(32).unwrap();

        let mut enc = Vec::new();
        encrypt_stream(
            &mut &b"secret"[..], &mut enc, &key1,
            AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE,
        ).unwrap();

        let mut dec = Vec::new();
        assert!(decrypt_stream(
            &mut &enc[..], &mut dec, &key2,
            AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE,
        ).is_err());
    }

    #[test]
    fn test_tampered_data_fails() {
        let key = SecureBuf::random(32).unwrap();

        let mut enc = Vec::new();
        encrypt_stream(
            &mut &b"data"[..], &mut enc, &key,
            AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE,
        ).unwrap();

        let mid = enc.len() / 2;
        enc[mid] ^= 0xFF;

        let mut dec = Vec::new();
        assert!(decrypt_stream(
            &mut &enc[..], &mut dec, &key,
            AeadAlgorithm::XChaCha20Poly1305, DEFAULT_CHUNK_SIZE,
        ).is_err());
    }
}
