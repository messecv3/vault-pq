//! Compression before encryption using Zstandard (zstd).
//!
//! Compression MUST happen before encryption because encrypted data is
//! incompressible (indistinguishable from random). The compression ratio
//! provides significant size savings on text, documents, and structured data.
//!
//! Zstd is chosen for:
//! - Speed: 500+ MB/s compression, 1500+ MB/s decompression
//! - Ratio: competitive with gzip at 3-10x the speed
//! - Streaming: native streaming support for large files
//!
//! # Security Note
//!
//! Compression before encryption can leak information about plaintext content
//! through output size changes (CRIME/BREACH style attacks). This is mitigated
//! by our bucket-based padding which rounds output to fixed sizes.

use crate::error::VaultError;

/// Default zstd compression level (3 = good balance of speed/ratio).
pub const DEFAULT_LEVEL: i32 = 3;

/// Compress data with zstd.
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>, VaultError> {
    zstd::encode_all(std::io::Cursor::new(data), level)
        .map_err(|e| VaultError::IoError(e))
}

/// Decompress zstd-compressed data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    zstd::decode_all(std::io::Cursor::new(data))
        .map_err(|e| VaultError::IoError(e))
}

/// Check if compression would be beneficial (ratio > 5% savings).
pub fn is_compressible(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false; // Too small to benefit
    }

    // Quick check: try compressing a sample
    let sample_size = data.len().min(4096);
    match compress(&data[..sample_size], 1) {
        Ok(compressed) => compressed.len() < sample_size * 95 / 100,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let data = b"Hello, compression! ".repeat(100);
        let compressed = compress(&data, DEFAULT_LEVEL).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_text_compresses_well() {
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(1000);
        let compressed = compress(text.as_bytes(), DEFAULT_LEVEL).unwrap();
        let ratio = compressed.len() as f64 / text.len() as f64;
        assert!(ratio < 0.1, "text should compress >90%, got {:.1}%", ratio * 100.0);
    }

    #[test]
    fn test_random_data_doesnt_compress() {
        let mut random = vec![0u8; 4096];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
        let compressed = compress(&random, DEFAULT_LEVEL).unwrap();
        // Random data shouldn't compress much (may even expand slightly)
        assert!(compressed.len() >= random.len() * 90 / 100);
    }

    #[test]
    fn test_empty() {
        let compressed = compress(b"", DEFAULT_LEVEL).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_is_compressible() {
        let text = "repetitive text content ".repeat(100);
        assert!(is_compressible(text.as_bytes()));

        let mut random = vec![0u8; 4096];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
        assert!(!is_compressible(&random));
    }
}
