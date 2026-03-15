//! Deniable encryption — multiple passphrases decrypt to different content.
//!
//! A deniable vault file looks identical to a normal multi-recipient file.
//! Each passphrase stanza independently wraps a different file key, which
//! decrypts different content stored in separate body sections.
//!
//! An observer cannot distinguish "3 people sharing access" from
//! "1 person with 2 decoy passphrases and 1 real one."

pub mod engine;
