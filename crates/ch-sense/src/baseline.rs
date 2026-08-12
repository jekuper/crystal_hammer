//! Baseline-at-start and diff (SPECS section 4). Trust-on-first-use, so first run pairs
//! with a one-time known-bad sweep.

use crate::HostSnapshot;

/// Difference between a stored baseline and a current snapshot. Shape filled in at M5.
#[derive(Debug, Clone, Default)]
pub struct Diff {
    pub summary: String,
}

/// Compare a baseline against the current snapshot.
pub fn diff(_baseline: &HostSnapshot, _current: &HostSnapshot) -> Diff {
    // M5: structural diff feeding the alert engine.
    Diff::default()
}
