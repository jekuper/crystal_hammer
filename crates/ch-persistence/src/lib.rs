//! Self-preservation via multiple independent, idempotent mechanisms (SPECS 13.10).
//!
//! Extension seam: add a mechanism by implementing [`Mechanism`] and registering it in
//! [`Registry::with_builtins`]. `install` must be idempotent so re-running after a
//! self-update restart cannot corrupt state (SPECS 13.5).

#![forbid(unsafe_code)]

mod mechanisms;

use ch_common::Result;

/// Health of one installed mechanism, surfaced by `info` (SPECS section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Active,
    Degraded,
    Missing,
}

/// A pluggable persistence/respawn mechanism.
pub trait Mechanism: Send + Sync {
    fn id(&self) -> ch_common::ImplId;

    /// Is this mechanism usable on this host (e.g. systemd present)?
    fn available(&self) -> bool;

    /// Install or repair. Must be idempotent.
    fn install(&self, self_path: &std::path::Path) -> Result<()>;

    /// Report current health without changing anything.
    fn check(&self) -> Result<Health>;

    /// Remove this mechanism (teardown).
    fn remove(&self) -> Result<()>;
}

pub struct Registry {
    mechanisms: Vec<Box<dyn Mechanism>>,
}

impl Registry {
    /// All shipped mechanisms. Add new ones here.
    pub fn with_builtins() -> Self {
        let mut r = Registry { mechanisms: Vec::new() };
        r.register(Box::new(mechanisms::systemd::Systemd::new()));
        r.register(Box::new(mechanisms::cron::Cron::new()));
        r
    }

    pub fn register(&mut self, m: Box<dyn Mechanism>) {
        self.mechanisms.push(m);
    }

    /// Install every available mechanism (multi-mechanism survivability). Returns the
    /// ids that were installed.
    pub fn install_all(&self, self_path: &std::path::Path) -> Vec<ch_common::ImplId> {
        let mut done = Vec::new();
        for m in &self.mechanisms {
            if m.available() {
                match m.install(self_path) {
                    Ok(()) => done.push(m.id()),
                    Err(e) => tracing::warn!(mechanism = m.id(), error = %e, "install failed"),
                }
            }
        }
        done
    }

    pub fn all(&self) -> impl Iterator<Item = &dyn Mechanism> {
        self.mechanisms.iter().map(|m| m.as_ref())
    }
}
