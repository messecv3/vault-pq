//! `vault encrypt` — encrypt a file with passphrase or public key recipients.

use std::fs;
use std::path::PathBuf;
use crate::crypto::{aead, kdf, kem, stream};
use crate::format::{header, padding};
use crate::identity::keypair;
use crate::metadata;
use crate::memory::SecureBuf;
use crate::platform::whitelist::{PathWhitelist, Permission};
use crate::error::VaultError;

pub struct EncryptOptions {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub passphrase: bool,
    pub recipients: Vec<String>,
    pub no_padding: bool,
    pub no_metadata: bool,
    pub argon2_memory_mb: u32,
    pub argon2_time: u32,
    pub whitelist_rules: Vec<String>,
    pub no_whitelist: bool,
}

pub fn run(opts: EncryptOptions) -> Result<(), VaultError> {
    // --- Validation ---
    if opts.recipients.is_empty() && !opts.passphrase {
        return Err(VaultError::NoRecipient);
    }

    let whitelist = build_whitelist(&opts)?;
    if !whitelist.can_read(&opts.input) {
        return Err(VaultError::PlatformError(format!(
            "input path '{}' not in whitelist — use --whitelist or --no-whitelist",
            opts.input.display()
        )));
    }
    if let Some(ref out) = opts.output {
        if !whitelist.can_write(out) {
            return Err(VaultError::PlatformError(format!(
                "output path '{}' not in whitelist", out.display()
            )));
        }
    }

    // --- Read input ---
    let input_data = fs::read(&opts.input)
        .map_err(|_| VaultError::FileNotFound(opts.input.display().to_string()))?;

    let original_size = input_data.len() as u64;
    let original_filename = opts.input.file_name()
        .and_then(|n| n.to_str())
        .map(String::from);

    // --- Generate file key ---
    let file_key = SecureBuf::random(32)?;
    let algorithm = aead::select_algorithm();

    // --- Padding ---
    let (padding_bucket, padded_size) = if opts.no_padding {
        (0xFF, original_size)
    } else {
        padding::select_bucket(original_size)
    };

    // --- Build recipient stanzas ---
    let mut stanzas = Vec::new();

    if opts.passphrase {
        let pass = rpassword::prompt_password("Passphrase: ")
            .map_err(VaultError::IoError)?;
        let confirm = rpassword::prompt_password("Confirm: ")
            .map_err(VaultError::IoError)?;
        if pass != confirm {
            return Err(VaultError::PassphraseMismatch);
        }
        if pass.len() < 8 {
            eprintln!("warning: passphrase shorter than 8 characters");
        }

        let salt = kdf::generate_salt();
        let params = kdf::KdfParams {
            memory_kib: opts.argon2_memory_mb.saturating_mul(1024),
            iterations: opts.argon2_time,
            parallelism: num_cpus(),
        };

        eprintln!("Deriving key (Argon2id, {}MB, {} iterations)...",
            opts.argon2_memory_mb, opts.argon2_time);

        let derived = kdf::derive_key(pass.into_bytes(), &salt, &params)?;
        let encrypted_fk = header::wrap_file_key_passphrase(&derived, &file_key)?;

        stanzas.push(header::RecipientStanza::Passphrase {
            salt,
            params,
            encrypted_file_key: encrypted_fk,
        });
    }

    for recipient_str in &opts.recipients {
        let pk = keypair::decode_public_key(recipient_str)?;
        let (shared_secret, encap) = kem::encapsulate(&pk)?;
        let encrypted_fk = header::wrap_file_key_public(&shared_secret, &file_key)?;

        stanzas.push(header::RecipientStanza::PublicKey {
            encap_data: encap.to_bytes(),
            encrypted_file_key: encrypted_fk,
        });
    }

    // --- Pad input ---
    let padded_data = if padded_size > original_size {
        let mut padded = input_data;
        padded.extend(padding::generate_padding(padded.len(), padded_size));
        padded
    } else {
        input_data
    };

    // --- Determine output path ---
    let output_path = match opts.output {
        Some(ref p) => p.clone(),
        None if opts.no_metadata => {
            let mut p = opts.input.clone();
            p.set_extension(format!(
                "{}.vault",
                p.extension().and_then(|e| e.to_str()).unwrap_or("")
            ));
            p
        }
        None => {
            opts.input.parent().unwrap_or(std::path::Path::new("."))
                .join(metadata::filename::random_vault_filename())
        }
    };

    // Verify output path is whitelisted (for auto-generated paths)
    if opts.output.is_none() && !whitelist.can_write(&output_path) {
        return Err(VaultError::PlatformError(format!(
            "output path '{}' not in whitelist", output_path.display()
        )));
    }

    // --- Encrypt body to temp buffer ---
    let mut body_encrypted = Vec::new();
    let plaintext_hash = stream::encrypt_stream(
        &mut padded_data.as_slice(),
        &mut body_encrypted,
        &file_key,
        algorithm,
        stream::DEFAULT_CHUNK_SIZE,
    )?;

    // --- Build metadata ---
    let metadata = header::EncryptedMetadata {
        algorithm,
        chunk_size: stream::DEFAULT_CHUNK_SIZE as u32,
        original_filename: if opts.no_metadata { None } else { original_filename.clone() },
        original_size,
        padding_bucket,
        plaintext_hash: Some(plaintext_hash),
        signature: None, // TODO: --sign flag support
    };

    // --- Write output file ---
    let mut output_file = fs::File::create(&output_path)?;
    header::write_file_header(&mut output_file, &stanzas, &metadata, &file_key)?;
    std::io::Write::write_all(&mut output_file, &body_encrypted)?;

    // --- Metadata protection ---
    if !opts.no_metadata {
        let _ = metadata::timestamp::normalize(&output_path);
    }

    // --- Report (no secrets in output) ---
    eprintln!("Encrypted: {} -> {}", opts.input.display(), output_path.display());
    eprintln!("  Algorithm:    {:?}", algorithm);
    eprintln!("  Recipients:   {}", stanzas.len());
    if !opts.no_padding {
        eprintln!("  Padded to:    {} bytes", padded_size);
    }

    Ok(())
}

fn build_whitelist(opts: &EncryptOptions) -> Result<PathWhitelist, VaultError> {
    if opts.no_whitelist {
        return Ok(PathWhitelist::permissive());
    }
    let mut wl = PathWhitelist::new();
    if opts.whitelist_rules.is_empty() {
        wl.add_user_defaults()
            .map_err(|e| VaultError::PlatformError(e.to_string()))?;
    } else {
        for rule in &opts.whitelist_rules {
            wl.add_rule(rule, Permission::ReadWrite)
                .map_err(|e| VaultError::PlatformError(e.to_string()))?;
        }
    }
    Ok(wl)
}

fn num_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
        .min(8) // Cap at 8 for reasonable KDF parallelism
}
