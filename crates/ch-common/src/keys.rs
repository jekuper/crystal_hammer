//! Compile-time embedded key material.
//!
//! Per SPECS section 13.5 the tool embeds a **single shared team ed25519 public key** at build
//! time, and the *same* keypair both signs the SPA knock and authenticates the SSH
//! session. Only the public half is ever embedded - never a private key (SPECS section 9).
//!
//! The build flow (M0) bakes the operator-provided public key in. Until that wiring
//! exists, `TEAM_PUBKEY_RAW` is empty and [`team_pubkey`] returns `None`.

use ed25519_dalek::VerifyingKey;

/// The embedded team public key, injected at build time.
///
/// M0 replaces this with `env!("CH_TEAM_PUBKEY")` (or an `include_bytes!` of a generated
/// file) so a build bakes in the real key.
pub const TEAM_PUBKEY_RAW: &[u8] = &[];

/// Parse the embedded team public key, if one was baked in.
pub fn team_pubkey() -> Option<VerifyingKey> {
    let raw: [u8; 32] = TEAM_PUBKEY_RAW.try_into().ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}
