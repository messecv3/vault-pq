//! Software licensing system for Vault.
//!
//! Provides registration, license key generation/validation, machine
//! fingerprinting, and tier management. Designed for open-source tools
//! that need to track usage and prevent unauthorized rebranding.
//!
//! # Design
//!
//! - **Offline-first**: validation works without network access
//! - **Signed licenses**: Ed25519 signature prevents tampering
//! - **Machine-bound**: license tied to hardware fingerprint
//! - **Tiered**: Community (free), Professional, Enterprise
//! - **Transparent**: license file is human-readable JSON
//! - **Non-intrusive**: Community tier has full functionality

pub mod fingerprint;
pub mod key;
pub mod manager;
