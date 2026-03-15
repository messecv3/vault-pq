//! `vault split` — split a secret key into Shamir shares.

use std::fs;
use std::path::PathBuf;
use crate::crypto::shamir;
use crate::memory::SecureBuf;
use crate::error::VaultError;

pub fn run(
    input: PathBuf,
    threshold: u8,
    total: u8,
    output_dir: PathBuf,
) -> Result<(), VaultError> {
    // Read the identity file as raw bytes
    let data = fs::read(&input)
        .map_err(|_| VaultError::FileNotFound(input.display().to_string()))?;

    let secret = SecureBuf::from_slice(&data)?;

    eprintln!("Splitting into {} shares (threshold: {})...", total, threshold);

    let shares = shamir::split(&secret, threshold, total)?;

    fs::create_dir_all(&output_dir)?;

    for (i, share) in shares.iter().enumerate() {
        let share_path = output_dir.join(format!("share_{:02}.vshr", i + 1));
        fs::write(&share_path, share)?;
        eprintln!("  Written: {}", share_path.display());
    }

    eprintln!("\nAny {} of {} shares can reconstruct the secret.", threshold, total);
    eprintln!("Distribute shares to separate, trusted locations.");

    Ok(())
}
