//! Secure file deletion: overwrite → truncate → rename → delete.
//!
//! NOTE: Best-effort on SSDs due to FTL/wear leveling.
//! For SSD security, use full-disk encryption as the base layer.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use rand::RngCore;
use uuid::Uuid;

/// Securely delete a file:
/// 1. Overwrite with random data (same size)
/// 2. Flush to disk
/// 3. Truncate to zero
/// 4. Rename to random name (pollutes NTFS journal)
/// 5. Delete
pub fn secure_delete(path: &Path) -> Result<(), std::io::Error> {
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();

    // Step 1: Overwrite with random data
    {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; 65_536];
        let mut remaining = file_size;

        while remaining > 0 {
            let chunk = std::cmp::min(remaining, buf.len() as u64) as usize;
            rng.fill_bytes(&mut buf[..chunk]);
            file.write_all(&buf[..chunk])?;
            remaining -= chunk as u64;
        }
        file.sync_all()?;
    }

    // Step 2: Truncate
    {
        let file = OpenOptions::new().write(true).open(path)?;
        file.set_len(0)?;
        file.sync_all()?;
    }

    // Step 3: Rename to random name
    let random_name = path.with_file_name(format!("{}.tmp", Uuid::new_v4()));
    fs::rename(path, &random_name)?;

    // Step 4: Delete
    fs::remove_file(&random_name)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_secure_delete() {
        // Create a temp file and persist it (no auto-cleanup)
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sensitive.txt");
        fs::write(&path, b"sensitive data here").unwrap();
        assert!(path.exists());

        secure_delete(&path).unwrap();
        assert!(!path.exists());
    }
}
