//! Machine fingerprinting — generates a stable, unique identifier for this machine.
//!
//! The fingerprint is derived from hardware characteristics that don't change
//! across reboots but are unique per machine. Used to bind licenses.
//!
//! # Components (hashed together)
//!
//! - OS type and architecture
//! - Machine hostname
//! - CPU count
//! - Home directory path (stable per user)
//! - Username
//!
//! The raw values are never stored — only the BLAKE3 hash.
//! This means the fingerprint can't be reverse-engineered to reveal
//! system details, but it's stable and unique enough for licensing.

use crate::error::VaultError;

/// A machine fingerprint — 32-byte BLAKE3 hash of hardware characteristics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineFingerprint {
    hash: [u8; 32],
}

impl MachineFingerprint {
    /// Generate a fingerprint for the current machine.
    pub fn current() -> Self {
        let mut hasher = blake3::Hasher::new();

        // OS + arch
        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());

        // Hostname
        if let Ok(name) = hostname() {
            hasher.update(name.as_bytes());
        }

        // CPU count (stable across reboots)
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        hasher.update(&cpus.to_le_bytes());

        // Home directory (stable per user account)
        if let Ok(home) = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
        {
            hasher.update(home.as_bytes());
        }

        // Username
        if let Ok(user) = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
        {
            hasher.update(user.as_bytes());
        }

        // Salt with a fixed domain separator
        hasher.update(b"vault-machine-fingerprint-v1");

        Self {
            hash: *hasher.finalize().as_bytes(),
        }
    }

    /// Create from a known hash (for loading from license file).
    pub fn from_bytes(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Get the raw hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Short display format (first 8 bytes, hex).
    pub fn short_id(&self) -> String {
        hex::encode(&self.hash[..8])
    }

    /// Full display format (all 32 bytes, hex).
    pub fn full_id(&self) -> String {
        hex::encode(&self.hash)
    }

    /// Check if this fingerprint matches another.
    pub fn matches(&self, other: &Self) -> bool {
        crate::memory::constant_time_eq(&self.hash, &other.hash)
    }
}

impl std::fmt::Display for MachineFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short_id())
    }
}

fn hostname() -> Result<String, VaultError> {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME")
            .map_err(|_| VaultError::PlatformError("no hostname".into()))
    }
    #[cfg(unix)]
    {
        std::env::var("HOSTNAME")
            .or_else(|_| {
                // Try reading /etc/hostname
                std::fs::read_to_string("/etc/hostname")
                    .map(|s| s.trim().to_string())
            })
            .map_err(|_| VaultError::PlatformError("no hostname".into()))
    }
    #[cfg(not(any(windows, unix)))]
    {
        Ok("unknown".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_stable() {
        let fp1 = MachineFingerprint::current();
        let fp2 = MachineFingerprint::current();
        assert!(fp1.matches(&fp2), "fingerprint should be stable across calls");
    }

    #[test]
    fn test_short_id_format() {
        let fp = MachineFingerprint::current();
        let short = fp.short_id();
        assert_eq!(short.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_full_id_format() {
        let fp = MachineFingerprint::current();
        let full = fp.full_id();
        assert_eq!(full.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_from_bytes_round_trip() {
        let fp = MachineFingerprint::current();
        let restored = MachineFingerprint::from_bytes(*fp.as_bytes());
        assert!(fp.matches(&restored));
    }

    #[test]
    fn test_display() {
        let fp = MachineFingerprint::current();
        let display = format!("{}", fp);
        assert_eq!(display.len(), 16);
    }
}
