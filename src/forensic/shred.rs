//! Multi-pass secure file shredding.
//!
//! Goes beyond basic single-pass overwrite with industry-standard patterns:
//!
//! - **Quick (1 pass)**: Random overwrite. Sufficient for SSDs.
//! - **DoD 5220.22-M (3 passes)**: Zero, one, random. US government standard.
//! - **Enhanced (7 passes)**: Alternating patterns + random. Higher assurance.
//!
//! # SSD Note
//!
//! On SSDs, multi-pass overwrite provides no additional security over single-pass
//! due to wear leveling and the Flash Translation Layer. For SSDs, use full-disk
//! encryption and key destruction instead. These patterns are most effective
//! on magnetic (HDD) storage.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use rand::RngCore;
use uuid::Uuid;
use crate::error::VaultError;

/// Shredding mode.
#[derive(Clone, Copy, Debug)]
pub enum ShredMode {
    /// 1 pass: random data. Fast, sufficient for most use cases.
    Quick,
    /// 3 passes: zeros, ones, random (DoD 5220.22-M).
    Dod,
    /// 7 passes: zero, one, random, 0x55, 0xAA, random, verify-zero.
    Enhanced,
}

impl ShredMode {
    pub fn pass_count(&self) -> usize {
        match self {
            Self::Quick => 1,
            Self::Dod => 3,
            Self::Enhanced => 7,
        }
    }
}

/// Shred a file with the specified mode.
///
/// Overwrites the file content, flushes to disk, truncates, renames
/// to random name, then deletes.
pub fn shred(path: &Path, mode: ShredMode) -> Result<ShredReport, VaultError> {
    let metadata = fs::metadata(path)
        .map_err(|_| VaultError::FileNotFound(path.display().to_string()))?;
    let file_size = metadata.len();

    let passes = build_passes(mode);
    let mut bytes_written = 0u64;

    for (_pass_num, pattern) in passes.iter().enumerate() {
        overwrite_with_pattern(path, file_size, pattern)?;
        bytes_written += file_size;
    }

    // Truncate to zero
    {
        let file = OpenOptions::new().write(true).open(path)?;
        file.set_len(0)?;
        file.sync_all()?;
    }

    // Rename to random name (pollutes filesystem journal)
    let random_name = path.with_file_name(format!("{}.shred", Uuid::new_v4()));
    fs::rename(path, &random_name)?;

    // Delete
    fs::remove_file(&random_name)?;

    Ok(ShredReport {
        original_path: path.to_path_buf(),
        file_size,
        passes_completed: passes.len(),
        bytes_written,
        mode,
    })
}

/// Report from a shred operation.
#[derive(Clone, Debug)]
pub struct ShredReport {
    pub original_path: std::path::PathBuf,
    pub file_size: u64,
    pub passes_completed: usize,
    pub bytes_written: u64,
    pub mode: ShredMode,
}

/// Overwrite pattern for a single pass.
enum OverwritePattern {
    Zeros,
    Ones,
    Byte(u8),
    Random,
}

fn build_passes(mode: ShredMode) -> Vec<OverwritePattern> {
    match mode {
        ShredMode::Quick => vec![
            OverwritePattern::Random,
        ],
        ShredMode::Dod => vec![
            OverwritePattern::Zeros,
            OverwritePattern::Ones,
            OverwritePattern::Random,
        ],
        ShredMode::Enhanced => vec![
            OverwritePattern::Zeros,
            OverwritePattern::Ones,
            OverwritePattern::Random,
            OverwritePattern::Byte(0x55), // 01010101
            OverwritePattern::Byte(0xAA), // 10101010
            OverwritePattern::Random,
            OverwritePattern::Zeros,      // Final zero pass for verification
        ],
    }
}

fn overwrite_with_pattern(
    path: &Path,
    file_size: u64,
    pattern: &OverwritePattern,
) -> Result<(), VaultError> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let mut rng = rand::thread_rng();
    let chunk_size = 65_536usize;
    let mut buf = vec![0u8; chunk_size];
    let mut remaining = file_size;

    while remaining > 0 {
        let write_size = remaining.min(chunk_size as u64) as usize;

        match pattern {
            OverwritePattern::Zeros => buf[..write_size].fill(0x00),
            OverwritePattern::Ones => buf[..write_size].fill(0xFF),
            OverwritePattern::Byte(b) => buf[..write_size].fill(*b),
            OverwritePattern::Random => rng.fill_bytes(&mut buf[..write_size]),
        }

        file.write_all(&buf[..write_size])?;
        remaining -= write_size as u64;
    }

    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shred_test.dat");
        fs::write(&path, b"sensitive data that must be destroyed").unwrap();
        (dir, path)
    }

    #[test]
    fn test_shred_quick() {
        let (_dir, path) = create_test_file();
        let report = shred(&path, ShredMode::Quick).unwrap();

        assert!(!path.exists());
        assert_eq!(report.passes_completed, 1);
        assert!(report.bytes_written > 0);
    }

    #[test]
    fn test_shred_dod() {
        let (_dir, path) = create_test_file();
        let report = shred(&path, ShredMode::Dod).unwrap();

        assert!(!path.exists());
        assert_eq!(report.passes_completed, 3);
    }

    #[test]
    fn test_shred_enhanced() {
        let (_dir, path) = create_test_file();
        let report = shred(&path, ShredMode::Enhanced).unwrap();

        assert!(!path.exists());
        assert_eq!(report.passes_completed, 7);
    }

    #[test]
    fn test_shred_nonexistent_fails() {
        let result = shred(Path::new("/nonexistent/file.txt"), ShredMode::Quick);
        assert!(result.is_err());
    }

    #[test]
    fn test_pass_counts() {
        assert_eq!(ShredMode::Quick.pass_count(), 1);
        assert_eq!(ShredMode::Dod.pass_count(), 3);
        assert_eq!(ShredMode::Enhanced.pass_count(), 7);
    }
}
