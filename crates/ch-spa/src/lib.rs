//! Hybrid Single-Packet Authorization (SPECS 13.3).
//!
//! The same signed [`Knock`] serves both paths: a single UDP datagram on the direct
//! path, or the opening bytes of the TCP stream when reached through a proxy. The port
//! stays dark until a knock verifies. No rate-limit, no lockout (SPECS section 1).

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The knock payload, signed by the shared team key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Knock {
    /// Monotonic timestamp; stale knocks are rejected.
    pub timestamp: u64,
    /// Random nonce; replays are rejected via an LRU cache.
    pub nonce: [u8; 16],
    /// Which service/port the knock authorizes.
    pub service: u16,
    /// Identifies the signing key (single team key today).
    pub key_id: u32,
}

impl Knock {
    /// Bytes covered by the signature.
    pub fn signed_bytes(&self) -> Vec<u8> {
        // M1: stable, canonical encoding.
        let mut v = Vec::with_capacity(30);
        v.extend_from_slice(&self.timestamp.to_le_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.service.to_le_bytes());
        v.extend_from_slice(&self.key_id.to_le_bytes());
        v
    }
}

/// Outcome of validating an inbound knock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Open,
    Reject,
}

/// Verify a knock's signature. Freshness and replay checks are layered on top by the
/// listener (they need mutable nonce/clock state).
pub fn verify(knock: &Knock, sig: &Signature, key: &VerifyingKey) -> Verdict {
    match key.verify_strict(&knock.signed_bytes(), sig) {
        Ok(()) => Verdict::Open,
        Err(_) => Verdict::Reject,
    }
}
