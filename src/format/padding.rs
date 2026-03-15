//! Content padding to bucket sizes.
//!
//! Pads encrypted output to one of a fixed set of sizes so that the
//! original file size cannot be determined from the output size.
//! Padding is filled with CSPRNG output (indistinguishable from ciphertext).

use rand::RngCore;

/// Size buckets for padding.
const BUCKETS: &[(u8, u64)] = &[
    (0x01, 1_024),           // 1 KB
    (0x02, 4_096),           // 4 KB
    (0x03, 16_384),          // 16 KB
    (0x04, 65_536),          // 64 KB
    (0x05, 262_144),         // 256 KB
    (0x06, 1_048_576),       // 1 MB
    (0x07, 4_194_304),       // 4 MB
    (0x08, 16_777_216),      // 16 MB
    (0x09, 67_108_864),      // 64 MB
    (0x0A, 268_435_456),     // 256 MB
    (0x0B, 1_073_741_824),   // 1 GB
    (0x0C, 4_294_967_296),   // 4 GB
];

/// Select the smallest bucket that fits `original_size`.
/// Returns (bucket_id, padded_size).
pub fn select_bucket(original_size: u64) -> (u8, u64) {
    for &(id, size) in BUCKETS {
        if original_size <= size {
            return (id, size);
        }
    }
    // Files larger than 4GB: exact size (no padding)
    (0xFF, original_size)
}

/// Generate random padding bytes to fill from `data_len` to `padded_size`.
pub fn generate_padding(data_len: usize, padded_size: u64) -> Vec<u8> {
    let padding_len = padded_size as usize - data_len;
    if padding_len == 0 {
        return Vec::new();
    }
    let mut padding = vec![0u8; padding_len];
    rand::thread_rng().fill_bytes(&mut padding);
    padding
}

/// Get the padded size for a bucket ID.
pub fn bucket_size(bucket_id: u8) -> Option<u64> {
    if bucket_id == 0xFF {
        return None; // Exact size, no padding
    }
    BUCKETS.iter().find(|&&(id, _)| id == bucket_id).map(|&(_, size)| size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_bucket() {
        assert_eq!(select_bucket(100), (0x01, 1_024));
        assert_eq!(select_bucket(1_024), (0x01, 1_024));
        assert_eq!(select_bucket(1_025), (0x02, 4_096));
        assert_eq!(select_bucket(1_000_000), (0x06, 1_048_576));
    }

    #[test]
    fn test_large_file_no_padding() {
        let (id, size) = select_bucket(5_000_000_000);
        assert_eq!(id, 0xFF);
        assert_eq!(size, 5_000_000_000);
    }

    #[test]
    fn test_padding_generation() {
        let padding = generate_padding(100, 1024);
        assert_eq!(padding.len(), 924);
        // Should be random (not all zeros)
        assert!(!padding.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_bucket_size_lookup() {
        assert_eq!(bucket_size(0x01), Some(1_024));
        assert_eq!(bucket_size(0x06), Some(1_048_576));
        assert_eq!(bucket_size(0xFF), None);
        assert_eq!(bucket_size(0xFE), None); // Unknown
    }
}
