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

/// Verify a contiguous run of records: each cursor follows the last and each `prev` link
/// equals the previous record's hash. A deletion (cursor gap) or edit (hash mismatch)
/// fails. Works on any contiguous slice, so a catch-up batch can be checked on its own.
pub fn verify_chain(records: &[Record]) -> bool {
    records.windows(2).all(|w| {
        w[1].cursor == w[0].cursor + 1 && w[1].prev == w[0].hash().0
    })
}
