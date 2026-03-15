//! Security testing framework.
//!
//! Tools for verifying that Vault's security properties actually hold
//! under adversarial conditions. Tests what Windows protections catch
//! and what they miss — documenting the real boundaries.

pub mod memory_probe;
pub mod forensic_probe;
pub mod behavioral_profile;
