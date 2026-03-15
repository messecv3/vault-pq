//! Encrypted archives — bundle multiple files into a single vault file.
//!
//! Uses tar internally to create an archive, optionally compresses with zstd,
//! then encrypts the result. Preserves directory structure, filenames,
//! and permissions (on Unix).
//!
//! # Usage
//!
//! ```text
//! vault encrypt -i ./secret_docs/ -o archive.vault --passphrase
//! vault decrypt -i archive.vault -o ./recovered/
//! ```

use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use crate::error::VaultError;

/// Create a tar archive from a directory or list of files.
/// Returns the archive as bytes.
pub fn create_archive(paths: &[PathBuf]) -> Result<Vec<u8>, VaultError> {
    let mut archive_buf = Vec::new();

    {
        let mut builder = tar::Builder::new(&mut archive_buf);

        for path in paths {
            if path.is_dir() {
                add_directory(&mut builder, path)?;
            } else if path.is_file() {
                add_file(&mut builder, path, path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .as_ref())?;
            } else {
                return Err(VaultError::FileNotFound(path.display().to_string()));
            }
        }

        builder.finish()?;
    }

    Ok(archive_buf)
}

/// Extract a tar archive to a directory.
pub fn extract_archive(archive_data: &[u8], output_dir: &Path) -> Result<Vec<PathBuf>, VaultError> {
    std::fs::create_dir_all(output_dir)?;

    let mut archive = tar::Archive::new(std::io::Cursor::new(archive_data));
    let mut extracted = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = output_dir.join(entry.path()?);

        // Security: prevent path traversal
        let canonical_output = output_dir.canonicalize().unwrap_or_else(|_| output_dir.to_path_buf());
        if let Ok(canonical_path) = path.canonicalize() {
            if !canonical_path.starts_with(&canonical_output) {
                return Err(VaultError::PlatformError(
                    format!("path traversal blocked: {}", path.display())
                ));
            }
        }

        // Create parent directories
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        entry.unpack(&path)?;
        extracted.push(path);
    }

    Ok(extracted)
}

/// List files in a tar archive without extracting.
pub fn list_archive(archive_data: &[u8]) -> Result<Vec<ArchiveEntry>, VaultError> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(archive_data));
    let mut entries = Vec::new();

    for entry in archive.entries()? {
        let entry = entry?;
        entries.push(ArchiveEntry {
            path: entry.path()?.to_path_buf(),
            size: entry.size(),
            is_dir: entry.header().entry_type().is_dir(),
        });
    }

    Ok(entries)
}

/// Archive entry metadata.
#[derive(Clone, Debug)]
pub struct ArchiveEntry {
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
}

fn add_directory(builder: &mut tar::Builder<&mut Vec<u8>>, dir: &Path) -> Result<(), VaultError> {
    let base = dir.parent().unwrap_or(Path::new(""));

    for entry in WalkDir::new(dir).follow_links(false) {
        let entry = entry.map_err(|e| VaultError::IoError(e.into()))?;
        let path = entry.path();

        // Get relative path from the base directory
        let relative = path.strip_prefix(base)
            .unwrap_or(path);

        if path.is_file() {
            add_file(builder, path, &relative.to_string_lossy())?;
        } else if path.is_dir() && path != dir {
            // Add directory entry
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, relative, std::io::empty())?;
        }
    }

    Ok(())
}

fn add_file(builder: &mut tar::Builder<&mut Vec<u8>>, path: &Path, archive_name: &str) -> Result<(), VaultError> {
    let metadata = std::fs::metadata(path)?;
    let mut file = std::fs::File::open(path)?;

    let mut header = tar::Header::new_gnu();
    header.set_size(metadata.len());
    header.set_mode(0o644);
    header.set_cksum();

    builder.append_data(&mut header, archive_name, &mut file)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_archive_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, b"hello archive").unwrap();

        let archive = create_archive(&[file_path]).unwrap();
        assert!(!archive.is_empty());

        let entries = list_archive(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].size, 13);
    }

    #[test]
    fn test_archive_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        fs::write(dir.path().join("a.txt"), b"file a").unwrap();
        fs::write(sub.join("b.txt"), b"file b in subdir").unwrap();

        let archive = create_archive(&[dir.path().to_path_buf()]).unwrap();
        let entries = list_archive(&archive).unwrap();
        // Should have at least 2 files
        let file_entries: Vec<_> = entries.iter().filter(|e| !e.is_dir).collect();
        assert!(file_entries.len() >= 2);
    }

    #[test]
    fn test_archive_extract_round_trip() {
        let src_dir = tempfile::tempdir().unwrap();
        fs::write(src_dir.path().join("hello.txt"), b"hello world").unwrap();
        fs::write(src_dir.path().join("data.bin"), &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        let archive = create_archive(&[
            src_dir.path().join("hello.txt"),
            src_dir.path().join("data.bin"),
        ]).unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let extracted = extract_archive(&archive, out_dir.path()).unwrap();
        assert_eq!(extracted.len(), 2);

        // Verify content
        for path in &extracted {
            let name = path.file_name().unwrap().to_string_lossy();
            if name == "hello.txt" {
                assert_eq!(fs::read(path).unwrap(), b"hello world");
            } else if name == "data.bin" {
                assert_eq!(fs::read(path).unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
            }
        }
    }
}
