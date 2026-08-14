//! Hybrid Single-Packet Authorization (SPECS 13.3).
//!
//! The same signed [`Knock`] serves both paths: a single UDP datagram on the direct
//! path, or the opening bytes of the TCP stream when reached through a proxy. The port
//! stays dark until a knock verifies. No rate-limit, no lockout (SPECS section 1).

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

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
        let mut v = Vec::with_capacity(30);
        v.extend_from_slice(&self.timestamp.to_le_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.service.to_le_bytes());
        v.extend_from_slice(&self.key_id.to_le_bytes());
        v
    }

    /// Decode from raw bytes (for UDP and TCP paths).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + 16 + 2 + 4 {
            return None;
        }
        let timestamp = u64::from_le_bytes(bytes[..8].try_into().ok()?);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[8..24]);
        let service = u16::from_le_bytes(bytes[24..26].try_into().ok()?);
        let key_id = u32::from_le_bytes(bytes[26..30].try_into().ok()?);
        Some(Self {
            timestamp,
            nonce,
            service,
            key_id,
        })
    }

    /// Serialize to bytes (for UDP and TCP paths).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(30);
        v.extend_from_slice(&self.timestamp.to_le_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.service.to_le_bytes());
        v.extend_from_slice(&self.key_id.to_le_bytes());
        v
    }
}

/// LRU cache for nonce rejection.
#[derive(Debug, Clone)]
pub struct NonceCache {
    cache: Arc<RwLock<HashMap<[u8; 16], u64>>>,
    capacity: usize,
    max_age: u64,
}

impl NonceCache {
    pub fn new(capacity: usize, max_age: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            capacity,
            max_age,
        }
    }

    /// Check if nonce is fresh, add if not present.
    pub async fn check_and_add(&self, nonce: [u8; 16], now: u64) -> bool {
        let mut cache = self.cache.write().await;
        let existing = cache.contains_key(&nonce);
        
        if !existing {
            cache.insert(nonce, now);
            
            // Evict oldest if needed
            if cache.len() > self.capacity {
                let mut min_ts = u64::MAX;
                let mut to_remove = None;
                
                for (key, &ts) in cache.iter() {
                    if ts < min_ts {
                        min_ts = ts;
                        to_remove = Some(*key);
                    }
                }
                if let Some(k) = to_remove {
                    cache.remove(&k);
                }
            }
        }
        
        !existing
    }

    /// Remove old entries.
    pub async fn cleanup(&self, now: u64) {
        let mut cache = self.cache.write().await;
        cache.retain(|_, ts| now - *ts < self.max_age);
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new(1024, 300) // 1024 entries, 300 second max age
    }
}

/// Outcome of validating an inbound knock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Open,
    RejectReplay,
    RejectSignature,
    RejectExpired,
}

/// Verify a knock's signature. Freshness and replay checks are layered on top by the
/// listener (they need mutable nonce/clock state).
pub fn verify(knock: &Knock, sig: &Signature, key: &VerifyingKey) -> Verdict {
    match key.verify_strict(&knock.signed_bytes(), sig) {
        Ok(()) => Verdict::Open,
        Err(_) => Verdict::RejectSignature,
    }
}

/// Validating inbound knock with context.
pub async fn validate(knock: &Knock, sig: &Signature, key: &VerifyingKey, cache: &NonceCache, now: u64) -> Verdict {
    // Standard tolerances for clock skew
    const MAX_PAST_SKEW: u64 = 60;
    const MAX_FUTURE_SKEW: u64 = 10;

    if now >= knock.timestamp {
        if now - knock.timestamp > MAX_PAST_SKEW {
            return Verdict::RejectExpired;
        }
    } else {
        if knock.timestamp - now > MAX_FUTURE_SKEW {
            return Verdict::RejectExpired;
        }
    }

    // Nonce replay check
    let fresh = cache.check_and_add(knock.nonce, knock.timestamp).await;
    if !fresh {
        return Verdict::RejectReplay;
    }

    // Signature check
    verify(knock, sig, key)
}