//! Local state on redb: baseline, watchlist, sentinel bindings, and the evidence log
//! (SPECS 13.8). The evidence log is append-only and hash-chained so tampering is
//! detectable.

#![forbid(unsafe_code)]

pub mod evidence;

use std::path::Path;

/// Handle to the on-disk state. Wraps a single redb database file.
pub struct Store {
    // M5: redb::Database plus typed table defs.
    _path: std::path::PathBuf,
}

impl Store {
    /// Open (or create) the state database under `state_dir`.
    pub fn open(state_dir: &Path) -> ch_common::Result<Self> {
        // M5: open redb, run migrations, seed default watchlist.
        Ok(Store { _path: state_dir.to_path_buf() })
    }
}
