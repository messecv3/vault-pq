//! `vault keygen` — generate a new identity keypair and save it encrypted.

use std::path::PathBuf;
use crate::identity::keypair;
use crate::error::VaultError;

/// Default identity file location.
fn default_identity_path() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".vault").join("identity.vkey")
}

pub fn run(output: Option<PathBuf>) -> Result<(), VaultError> {
    let (pk, sk) = keypair::generate();
    let encoded_pk = keypair::encode_public_key(&pk);

    let identity_path = output.unwrap_or_else(default_identity_path);

    // Ensure parent directory exists
    if let Some(parent) = identity_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Prompt for passphrase to encrypt the secret key
    let pass = rpassword::prompt_password("Passphrase to protect identity: ")
        .map_err(VaultError::IoError)?;
    let confirm = rpassword::prompt_password("Confirm: ")
        .map_err(VaultError::IoError)?;

    if pass != confirm {
        return Err(VaultError::PassphraseMismatch);
    }
    if pass.len() < 8 {
        eprintln!("warning: passphrase shorter than 8 characters");
    }

    eprintln!("Deriving key (Argon2id, 256MB)...");
    keypair::save_secret_key(&identity_path, &sk, &pk, pass.as_bytes())?;

    eprintln!("Identity saved: {}", identity_path.display());
    eprintln!("Public key:");
    println!("{}", encoded_pk);

    Ok(())
}
