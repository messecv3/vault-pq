//! `vault decrypt` — decrypt a vault file using passphrase or identity key.

use std::fs;
use std::path::PathBuf;
use crate::crypto::stream;
use crate::format::header;
use crate::identity::keypair;
use crate::memory::SecureBuf;
use crate::error::VaultError;

pub struct DecryptOptions {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub passphrase: bool,
    pub identity: Option<PathBuf>,
    pub delete_input: bool,
}

pub fn run(opts: DecryptOptions) -> Result<(), VaultError> {
    let file_data = fs::read(&opts.input)
        .map_err(|_| VaultError::FileNotFound(opts.input.display().to_string()))?;
    let mut cursor = std::io::Cursor::new(&file_data);

    // --- Read plaintext stanzas ---
    let (stanzas, magic) = header::read_stanzas(&mut cursor)?;

    let pass_count = stanzas.iter()
        .filter(|s| matches!(s, header::RecipientStanza::Passphrase { .. }))
        .count();
    let pk_count = stanzas.iter()
        .filter(|s| matches!(s, header::RecipientStanza::PublicKey { .. }))
        .count();

    eprintln!("Recipients: {} passphrase, {} public-key", pass_count, pk_count);

    // --- Recover file key ---
    let file_key = recover_file_key(&stanzas, &opts)?;

    // --- Read encrypted metadata ---
    let metadata = header::read_metadata(&mut cursor, &file_key, &magic)?;

    // --- Decrypt body ---
    let body_start = cursor.position() as usize;
    let body_data = &file_data[body_start..];

    let mut decrypted = Vec::new();
    let dec_hash = stream::decrypt_stream(
        &mut &body_data[..],
        &mut decrypted,
        &file_key,
        metadata.algorithm,
        metadata.chunk_size as usize,
    )?;

    // --- Verify integrity ---
    if let Some(expected) = metadata.plaintext_hash {
        if !crate::memory::constant_time_eq(&dec_hash, &expected) {
            return Err(VaultError::InvalidFormat(
                "integrity check failed — file may be corrupted".into(),
            ));
        }
    }

    // --- Strip padding ---
    let output_data = if metadata.original_size < decrypted.len() as u64 {
        &decrypted[..metadata.original_size as usize]
    } else {
        &decrypted
    };

    // --- Determine output path ---
    let output_path = match opts.output {
        Some(ref p) => p.clone(),
        None => {
            if let Some(ref name) = metadata.original_filename {
                opts.input.parent().unwrap_or(std::path::Path::new(".")).join(name)
            } else {
                let mut p = opts.input.clone();
                if p.extension().and_then(|e| e.to_str()) == Some("vault") {
                    p.set_extension("");
                } else {
                    p.set_extension("dec");
                }
                p
            }
        }
    };

    // --- Write output ---
    fs::write(&output_path, output_data)?;
    eprintln!("Decrypted: {} -> {} ({} bytes)",
        opts.input.display(), output_path.display(), output_data.len());

    // --- Secure delete ---
    if opts.delete_input {
        eprintln!("Securely deleting input...");
        crate::forensic::secure_delete::secure_delete(&opts.input)?;
    }

    Ok(())
}

/// Try each stanza to recover the file key.
fn recover_file_key(
    stanzas: &[header::RecipientStanza],
    opts: &DecryptOptions,
) -> Result<SecureBuf, VaultError> {
    let pass_stanzas: Vec<_> = stanzas.iter()
        .filter(|s| matches!(s, header::RecipientStanza::Passphrase { .. }))
        .collect();
    let pk_stanzas: Vec<_> = stanzas.iter()
        .filter(|s| matches!(s, header::RecipientStanza::PublicKey { .. }))
        .collect();

    // Try identity file first if provided
    if let Some(ref id_path) = opts.identity {
        if !pk_stanzas.is_empty() {
            let id_pass = rpassword::prompt_password("Identity passphrase: ")
                .map_err(VaultError::IoError)?;

            let (_pk, sk) = keypair::load_secret_key(id_path, id_pass.as_bytes())?;

            for stanza in &pk_stanzas {
                match stanza.try_unwrap_public_key(&sk) {
                    Ok(file_key) => return Ok(file_key),
                    Err(_) => continue,
                }
            }
            eprintln!("Identity did not match any public-key stanza.");
        }
    }

    // Try passphrase stanzas
    if !pass_stanzas.is_empty() {
        let passphrase = rpassword::prompt_password("Passphrase: ")
            .map_err(VaultError::IoError)?;

        for stanza in &pass_stanzas {
            match stanza.try_unwrap_passphrase(passphrase.as_bytes()) {
                Ok(file_key) => return Ok(file_key),
                Err(_) => continue,
            }
        }
    }

    Err(VaultError::AuthenticationFailed)
}
