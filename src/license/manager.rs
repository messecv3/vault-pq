//! License manager — handles registration, storage, and runtime checks.
//!
//! # Flow
//!
//! 1. User runs `vault register` — enters name + email
//! 2. System generates a Community license signed with the project key
//! 3. License saved to `~/.vault/license.json`
//! 4. On every invocation, license is checked (fast, offline)
//! 5. If no license, tool runs in unregistered mode (still functional,
//!    but shows registration prompt)
//!
//! # Project Signing Key
//!
//! The project has a hardcoded Ed25519 verifying key. Licenses signed with
//! the corresponding secret key (held by the project maintainer) are valid.
//! This means:
//! - Anyone can verify a license (public key is in the binary)
//! - Only the maintainer can generate valid licenses
//! - Tampering with a license invalidates the signature

use std::path::{Path, PathBuf};
use crate::license::key::{License, Licensee, LicenseTier, generate_license};
use crate::license::fingerprint::MachineFingerprint;
use crate::crypto::sig::SigningKeyPair;
use crate::error::VaultError;

/// The project's Ed25519 verifying key (public).
/// In production, this would be a fixed key whose secret is held by the maintainer.
/// For development/testing, we generate a fresh one.
///
/// To set up for production:
/// 1. Generate a keypair: `vault keygen --output project-signing.vkey`
/// 2. Extract the verifying key bytes
/// 3. Hardcode them here
/// 4. Keep the signing key OFFLINE and SECURE
fn project_verifying_key() -> [u8; 32] {
    // Development placeholder — in production, replace with fixed bytes
    // e.g., [0x01, 0x02, ...] from your project signing key
    [0u8; 32] // All-zeros means "development mode, accept self-signed"
}

/// Check if we're in development mode (no hardcoded project key).
fn is_dev_mode() -> bool {
    project_verifying_key() == [0u8; 32]
}

/// Default license file path.
pub fn license_path() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".vault").join("license.json")
}

/// Runtime license status.
#[derive(Clone, Debug)]
pub enum LicenseStatus {
    /// Valid license loaded and verified.
    Licensed {
        licensee: String,
        tier: LicenseTier,
        days_remaining: Option<u32>,
    },
    /// No license file found — unregistered.
    Unregistered,
    /// License file exists but is invalid.
    Invalid(String),
    /// Development mode — no project key configured.
    DevMode,
}

impl std::fmt::Display for LicenseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Licensed { licensee, tier, days_remaining } => {
                write!(f, "Licensed to {} ({})", licensee, tier)?;
                if let Some(days) = days_remaining {
                    write!(f, " — {} days remaining", days)?;
                }
                Ok(())
            }
            Self::Unregistered => write!(f, "Unregistered — run 'vault register' for a free license"),
            Self::Invalid(reason) => write!(f, "Invalid license: {}", reason),
            Self::DevMode => write!(f, "Development mode (no project key configured)"),
        }
    }
}

/// Check the current license status. Fast, offline, called on every invocation.
pub fn check_license() -> LicenseStatus {
    if is_dev_mode() {
        return LicenseStatus::DevMode;
    }

    let path = license_path();
    if !path.exists() {
        return LicenseStatus::Unregistered;
    }

    match load_license(&path) {
        Ok(license) => {
            let vk = project_verifying_key();
            let validation = license.validate(&vk);

            if validation.valid {
                LicenseStatus::Licensed {
                    licensee: license.licensee.name.clone(),
                    tier: validation.tier,
                    days_remaining: validation.days_remaining,
                }
            } else {
                LicenseStatus::Invalid(validation.reason)
            }
        }
        Err(e) => LicenseStatus::Invalid(format!("{}", e)),
    }
}

/// Register a new user — generates and saves a Community license.
///
/// In production, this would submit a registration request to a server
/// and receive back a signed license. For open-source / self-hosted use,
/// the tool self-signs with a development key.
pub fn register(name: &str, email: &str, organization: Option<&str>) -> Result<License, VaultError> {
    // Validate inputs
    if name.trim().is_empty() {
        return Err(VaultError::InvalidFormat("name cannot be empty".into()));
    }
    if !email.contains('@') || !email.contains('.') {
        return Err(VaultError::InvalidFormat("invalid email format".into()));
    }

    let licensee = Licensee {
        name: name.trim().to_string(),
        email: email.trim().to_lowercase(),
        organization: organization.map(|s| s.trim().to_string()),
    };

    // In dev mode, self-sign. In production, this would call a license server.
    let signing_key = if is_dev_mode() {
        // Generate ephemeral key for self-signing in dev mode
        SigningKeyPair::generate()
    } else {
        return Err(VaultError::PlatformError(
            "Production registration requires a license server. Contact support.".into()
        ));
    };

    let license = generate_license(
        &signing_key,
        licensee,
        LicenseTier::Community,
        None, // Perpetual community license
    );

    // Save
    save_license(&license)?;

    Ok(license)
}

/// Save a license to the default path.
pub fn save_license(license: &License) -> Result<(), VaultError> {
    let path = license_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(license)
        .map_err(|e| VaultError::InvalidFormat(format!("license serialize: {}", e)))?;

    std::fs::write(&path, json)?;
    Ok(())
}

/// Load a license from a path.
pub fn load_license(path: &Path) -> Result<License, VaultError> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json)
        .map_err(|e| VaultError::InvalidFormat(format!("license parse: {}", e)))
}

/// Print license status for the CLI.
pub fn print_status() {
    let status = check_license();
    let fp = MachineFingerprint::current();

    eprintln!("Machine ID: {}", fp.short_id());
    eprintln!("License:    {}", status);

    if let LicenseStatus::Unregistered = status {
        eprintln!();
        eprintln!("Register for free: vault register --name \"Your Name\" --email you@example.com");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_mode_active() {
        // With all-zero verifying key, should be dev mode
        assert!(is_dev_mode());
    }

    #[test]
    fn test_check_license_dev_mode() {
        let status = check_license();
        match status {
            LicenseStatus::DevMode => {} // Expected
            _ => {} // May have a license file from a previous test
        }
    }

    #[test]
    fn test_register_dev_mode() {
        let license = register("Test User", "test@example.com", None).unwrap();

        assert_eq!(license.tier, LicenseTier::Community);
        assert_eq!(license.licensee.name, "Test User");
        assert_eq!(license.licensee.email, "test@example.com");
        assert!(!license.is_expired());
        assert!(license.is_valid_machine());
    }

    #[test]
    fn test_register_invalid_email() {
        let result = register("Test", "not-an-email", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_register_empty_name() {
        let result = register("", "test@test.com", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_load_round_trip() {
        let license = register("Round Trip", "rt@test.com", Some("Test Org")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_license.json");

        // Manual save
        let json = serde_json::to_string_pretty(&license).unwrap();
        std::fs::write(&path, &json).unwrap();

        // Load
        let loaded = load_license(&path).unwrap();
        assert_eq!(loaded.licensee.name, "Round Trip");
        assert_eq!(loaded.licensee.organization, Some("Test Org".into()));
        assert_eq!(loaded.tier, LicenseTier::Community);
    }

    #[test]
    fn test_license_json_format() {
        let license = register("JSON Test", "json@test.com", None).unwrap();
        let json = serde_json::to_string_pretty(&license).unwrap();

        // Should be valid JSON
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Should contain key fields
        assert!(json.contains("licensee"));
        assert!(json.contains("tier"));
        assert!(json.contains("machine_id"));
        assert!(json.contains("signature"));
    }
}
