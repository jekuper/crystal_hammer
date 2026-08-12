//! Append-only, hash-chained evidence log (SPECS 13.8, section 12).
//!
//! Each record commits the hash of the previous record, so any deletion or edit breaks
//! the chain and is detectable. Records are pulled off-box on client connect (SPECS
//! 13.9).

use ch_common::Hash;
use serde::{Deserialize, Serialize};

/// One evidence record. `prev` links it to the record before it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Monotonic cursor, also the client's catch-up key.
    pub cursor: u64,
    /// Hash of the previous record (zero for the genesis record).
    pub prev: [u8; 32],
    pub kind: String,
    pub body: serde_json::Value,
}

impl Record {
    /// Content hash of this record, used as `prev` by its successor.
    pub fn hash(&self) -> Hash {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        Hash::of(&bytes)
    }
}

/// Verify the chain is intact from genesis. Implemented at M5/M6.
pub fn verify_chain(_records: &[Record]) -> bool {
    // M5: recompute each `prev` link, confirm the cursor is contiguous.
    true
}
