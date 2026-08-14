//! Compile-time embedded public key material.
//!
//! Per SPECS section 13.5, the agent only embeds the team public key
//! to verify client knocks and authenticate sessions. The private key
//! is held exclusively by the operator client.

use ed25519_dalek::VerifyingKey;
use base64::Engine;

/// The embedded team public key, injected at build time.
pub const TEAM_PUBLIC_KEY_RAW: &[u8] = include_bytes!("../../../id_rsa.pub");

/// Parse the embedded team public key.
pub fn team_pubkey() -> Option<VerifyingKey> {
    let pubkey_str = std::str::from_utf8(TEAM_PUBLIC_KEY_RAW).ok()?;
    parse_openssh_public_key(pubkey_str)
}

/// Simple parser for standard ssh-ed25519 public key format.
fn parse_openssh_public_key(s: &str) -> Option<VerifyingKey> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "ssh-ed25519" {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .ok()?;
    if bytes.len() < 32 {
        return None;
    }
    // Extract the raw key payload from the trailing bytes
    let key_bytes: [u8; 32] = bytes[bytes.len() - 32..].try_into().ok()?;
    VerifyingKey::from_bytes(&key_bytes).ok()
}