//! Timestamp normalization — set all file timestamps to epoch.

use filetime::{set_file_mtime, set_file_atime, FileTime};
use std::path::Path;

/// Set access and modification timestamps to Unix epoch (Jan 1, 1970).
/// Prevents timeline analysis of encrypted files.
///
/// Note: On Windows, creation time normalization requires additional API calls.
/// NTFS stores creation time separately from mtime/atime.
pub fn normalize(path: &Path) -> std::io::Result<()> {
    let epoch = FileTime::from_unix_time(0, 0);
    set_file_mtime(path, epoch)?;
    set_file_atime(path, epoch)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_normalize_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_ts.txt");
        fs::write(&path, b"test data").unwrap();

        normalize(&path).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        let mtime = FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime.unix_seconds(), 0);
    }
}
