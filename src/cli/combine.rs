//! `vault combine` — reconstruct a secret key from Shamir shares.

use std::fs;
use std::path::PathBuf;
use crate::crypto::shamir;
use crate::error::VaultError;

pub fn run(share_files: Vec<PathBuf>, output: PathBuf) -> Result<(), VaultError> {
    if share_files.is_empty() {
        return Err(VaultError::InvalidShamirParams("no share files provided".into()));
    }

    eprintln!("Loading {} shares...", share_files.len());

    let mut shares = Vec::new();
    for path in &share_files {
        let data = fs::read(path)
            .map_err(|_| VaultError::FileNotFound(path.display().to_string()))?;
        eprintln!("  Loaded: {}", path.display());
        shares.push(data);
    }

    eprintln!("Reconstructing secret...");
    let secret = shamir::combine(&shares)?;

    fs::write(&output, secret.expose())?;
    eprintln!("Secret written to: {}", output.display());

    Ok(())
}
