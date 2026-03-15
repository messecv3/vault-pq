//! Persistent configuration file at ~/.vault/config.toml.
//!
//! Stores user preferences for default behavior:
//! - Default KDF parameters
//! - Default AEAD algorithm
//! - Whitelist rules
//! - Shred mode
//! - Compression settings
//! - Polymorphism settings

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use crate::error::VaultError;

/// Vault configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultConfig {
    /// Default KDF memory in MB.
    pub argon2_memory_mb: u32,
    /// Default KDF iterations.
    pub argon2_iterations: u32,
    /// Preferred AEAD algorithm: "auto", "xchacha20", or "aes-gcm".
    pub algorithm: String,
    /// Enable compression before encryption.
    pub compress: bool,
    /// Compression level (1-22, default 3).
    pub compress_level: i32,
    /// Enable metadata protection by default.
    pub metadata_protection: bool,
    /// Enable content padding by default.
    pub padding: bool,
    /// Default shred mode: "quick", "dod", or "enhanced".
    pub shred_mode: String,
    /// Path whitelist rules.
    pub whitelist: Vec<String>,
    /// Enable polymorphic output by default.
    pub polymorph: bool,
    /// Number of decoy stanzas (0-4).
    pub decoy_stanzas: u32,
    /// Run environment check before passphrase entry.
    pub environment_check: bool,
    /// Enable ASCII armor output by default.
    pub armor: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            argon2_memory_mb: 512,
            argon2_iterations: 8,
            algorithm: "auto".into(),
            compress: true,
            compress_level: 3,
            metadata_protection: true,
            padding: true,
            shred_mode: "quick".into(),
            whitelist: Vec::new(),
            polymorph: false,
            decoy_stanzas: 0,
            environment_check: true,
            armor: false,
        }
    }
}

impl VaultConfig {
    /// Load config from the default location (~/.vault/config.toml).
    pub fn load() -> Self {
        Self::load_from(&default_config_path()).unwrap_or_default()
    }

    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Result<Self, VaultError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| VaultError::IoError(e))?;

        toml::from_str(&content)
            .map_err(|e| VaultError::InvalidFormat(format!("config parse error: {}", e)))
    }

    /// Save config to the default location.
    pub fn save(&self) -> Result<(), VaultError> {
        self.save_to(&default_config_path())
    }

    /// Save config to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<(), VaultError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| VaultError::InvalidFormat(format!("config serialize error: {}", e)))?;

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Generate a default config file with comments.
    pub fn generate_default_commented() -> String {
        r#"# Vault configuration file
# Location: ~/.vault/config.toml

# Key derivation (Argon2id)
argon2_memory_mb = 512      # Memory cost in MB (minimum 64)
argon2_iterations = 8       # Iteration count (minimum 3)

# Encryption algorithm: "auto", "xchacha20", "aes-gcm"
# "auto" selects AES-GCM if AES-NI is available, else XChaCha20
algorithm = "auto"

# Compression (zstd, applied before encryption)
compress = true
compress_level = 3          # 1=fast, 22=best ratio

# Metadata protection
metadata_protection = true  # Random filenames, epoch timestamps
padding = true              # Pad to bucket sizes (hides file size)

# Secure deletion mode: "quick" (1 pass), "dod" (3 pass), "enhanced" (7 pass)
shred_mode = "quick"

# Path whitelist (glob/regex patterns)
# whitelist = ["C:\\Users\\*\\Desktop\\**", "C:\\Users\\*\\Documents\\**"]
whitelist = []

# Polymorphic output
polymorph = false           # Add decoy stanzas and shuffle
decoy_stanzas = 0           # Number of fake stanzas (0-4)

# Runtime environment check before passphrase entry
environment_check = true

# ASCII armor output (base64, for email/chat)
armor = false
"#.into()
    }
}

fn default_config_path() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".vault").join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VaultConfig::default();
        assert_eq!(config.argon2_memory_mb, 512);
        assert_eq!(config.argon2_iterations, 8);
        assert!(config.compress);
        assert!(config.metadata_protection);
        assert!(config.padding);
    }

    #[test]
    fn test_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_config.toml");

        let mut config = VaultConfig::default();
        config.argon2_memory_mb = 256;
        config.algorithm = "xchacha20".into();
        config.whitelist = vec!["C:\\Users\\*\\Desktop\\**".into()];
        config.polymorph = true;

        config.save_to(&path).unwrap();

        let loaded = VaultConfig::load_from(&path).unwrap();
        assert_eq!(loaded.argon2_memory_mb, 256);
        assert_eq!(loaded.algorithm, "xchacha20");
        assert_eq!(loaded.whitelist.len(), 1);
        assert!(loaded.polymorph);
    }

    #[test]
    fn test_generate_commented() {
        let commented = VaultConfig::generate_default_commented();
        assert!(commented.contains("argon2_memory_mb"));
        assert!(commented.contains("# Vault configuration file"));
    }

    #[test]
    fn test_missing_fields_use_defaults() {
        let minimal = r#"
argon2_memory_mb = 128
"#;
        let config: VaultConfig = toml::from_str(minimal).unwrap();
        assert_eq!(config.argon2_memory_mb, 128);
        // Everything else should be default
        assert_eq!(config.argon2_iterations, 8);
        assert!(config.compress);
    }
}
