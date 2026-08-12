//! Monitoring / hunt engine built from registry-dispatched checks (SPECS 13.11).
//!
//! Every detection in SPECS sections 4 and 5 is a [`Check`]. Add one by implementing the
//! trait and registering it in [`Registry::with_builtins`]. The engine runs checks on a
//! poll and feeds findings into the evidence log; real-time layers (fanotify) push into
//! the same finding stream.

#![forbid(unsafe_code)]

mod checks;

use serde::{Deserialize, Serialize};

/// Severity for a finding, used for alert routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

/// One detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,
    pub severity: Severity,
    pub summary: String,
    pub detail: serde_json::Value,
}

/// When a check runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cadence {
    /// Run once at startup (e.g. the known-bad sweep).
    Once,
    /// Run on every poll tick.
    Poll,
}

/// A pluggable detection. Reads the shared host model; never shells out.
pub trait Check: Send + Sync {
    fn id(&self) -> ch_common::ImplId;
    fn cadence(&self) -> Cadence;
    /// Evaluate against a host snapshot, returning any findings.
    fn run(&self, host: &ch_sense::HostSnapshot) -> Vec<Finding>;
}

pub struct Registry {
    checks: Vec<Box<dyn Check>>,
}

impl Registry {
    /// All shipped checks. Add new detections here.
    pub fn with_builtins() -> Self {
        let mut r = Registry { checks: Vec::new() };
        r.register(Box::new(checks::persistence::AuthorizedKeys::new()));
        r.register(Box::new(checks::stealth::PacketSocketHolders::new()));
        r
    }

    pub fn register(&mut self, check: Box<dyn Check>) {
        self.checks.push(check);
    }

    /// Run every check whose cadence matches and collect findings.
    pub fn run(&self, cadence: Cadence, host: &ch_sense::HostSnapshot) -> Vec<Finding> {
        self.checks
            .iter()
            .filter(|c| c.cadence() == cadence)
            .flat_map(|c| c.run(host))
            .collect()
    }
}
