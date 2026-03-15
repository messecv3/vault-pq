//! Error types for Vault.
//!
//! CRITICAL: Error messages MUST NOT contain secret material.
//! Never include key bytes, plaintext content, or passphrases in errors.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    // Crypto errors — deliberately vague to prevent oracle attacks
    #[error("cipher initialization failed")]
    CipherInit,

    #[error("encryption failed")]
    EncryptionFailed,

    /// Wrong key, tampered data, or wrong passphrase.
    /// Deliberately does not distinguish which one — this prevents
    /// padding oracle and chosen-ciphertext attacks.
    #[error("authentication failed: wrong key, wrong passphrase, or data was tampered with")]
    AuthenticationFailed,

    #[error("invalid nonce")]
    InvalidNonce,

    #[error("key derivation failed")]
    HkdfError,

    // KDF errors
    #[error("key derivation error: {0}")]
    KdfError(String),

    #[error("KDF parameters below minimum security threshold: {0}")]
    KdfParamsTooWeak(String),

    // Key management
    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("invalid Shamir share")]
    InvalidShare,

    #[error("share recovery failed — not enough valid shares")]
    ShareRecoveryFailed,

    #[error("invalid Shamir parameters: {0}")]
    InvalidShamirParams(String),

    #[error("no recipient specified — use --recipient or --passphrase")]
    NoRecipient,

    #[error("passphrases do not match")]
    PassphraseMismatch,

    // Format errors
    #[error("invalid vault format: {0}")]
    InvalidFormat(String),

    #[error("unsupported format version {0}.{1}")]
    UnsupportedVersion(u8, u8),

    #[error("file header corrupted or tampered")]
    HeaderCorrupted,

    // Memory
    #[error("secure memory allocation failed: {0}")]
    SecureAllocFailed(String),

    // I/O
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("file not found: {0}")]
    FileNotFound(String),

    // Platform
    #[error("platform error: {0}")]
    PlatformError(String),
}
