//! Web panel — app-style interface for Vault operations.
//!
//! Serves a local-only web server with a single-page application
//! that looks like a native desktop app (dark theme, no browser chrome feel).
//!
//! Binds to 127.0.0.1 only — never exposed to the network.

pub mod server;
pub mod api;
