//! Vault — Post-quantum hybrid file encryption with metadata protection.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │              CLI (clap)                  │
//! ├─────────────────────────────────────────┤
//! │         Format (header, padding)         │
//! ├─────────────────────────────────────────┤
//! │  Crypto (AEAD, KDF, KEM, streaming)     │
//! ├─────────────────────────────────────────┤
//! │     Secure Memory (guard pages,          │
//! │     VirtualLock/mlock, zeroize)          │
//! └─────────────────────────────────────────┘
//! ```

pub mod error;
pub mod memory;
pub mod crypto;
pub mod format;
pub mod metadata;
pub mod forensic;
pub mod identity;
pub mod deniable;
pub mod platform;
pub mod cli;
pub mod testing;
pub mod panel;
pub mod license;
