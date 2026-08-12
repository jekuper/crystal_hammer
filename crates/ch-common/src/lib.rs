//! Shared types used across the workspace: errors, identifiers, config, keys, and the
//! wire protocol messages exchanged between `agent` and `client`.
//!
//! This crate has no platform dependencies so it builds everywhere (including the dev
//! host) and keeps the Linux-only crates thin.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod keys;
pub mod proto;

pub use error::{Error, Result};

/// Well-known identifier for a pluggable implementation (firewall backend, persistence
/// mechanism, monitor check, ...). Stable across versions; used in logs and registries.
pub type ImplId = &'static str;

/// A content hash used throughout the tool (file integrity, evidence chaining, transfer
/// verification). BLAKE3, hex-encoded when displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn of(bytes: &[u8]) -> Self {
        Hash(*blake3::hash(bytes).as_bytes())
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
