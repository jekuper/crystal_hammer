//! Firewall control with registry-dispatched backends.
//!
//! Extension seam (SPECS 13.7, 13.11): add a backend by implementing [`Backend`] and
//! adding one line to [`Registry::with_builtins`]. Nothing else changes.
//!
//! Backends drive `nft`/`iptables` by exec (SPECS 13.7). The binary is hash-verified
//! before use elsewhere; detection/read paths do not trust these binaries.

#![forbid(unsafe_code)]

mod backends;

use ch_common::Result;

/// An opaque saved ruleset, replayed verbatim on restore (SPECS section 1).
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub backend: ch_common::ImplId,
    pub blob: Vec<u8>,
}

/// The allow-rule for the tool's own SPA/port, inserted first and atomically.
#[derive(Debug, Clone)]
pub struct ToolRule {
    pub port: u16,
    pub udp: bool,
}

/// A default-deny allowlist plan. Empty is valid and means "only the tool is reachable"
/// (SPECS section 1).
#[derive(Debug, Clone, Default)]
pub struct LockdownPlan {
    pub allow_inbound: Vec<PortSpec>,
    pub tool_rule: Option<ToolRule>,
}

#[derive(Debug, Clone, Copy)]
pub struct PortSpec {
    pub port: u16,
    pub udp: bool,
}

/// A pluggable firewall backend.
pub trait Backend: Send + Sync {
    /// Stable identifier, e.g. "nftables".
    fn id(&self) -> ch_common::ImplId;

    /// Cheap probe: is this the active backend on this host?
    fn detect(&self) -> bool;

    /// Save the current ruleset for exact restore.
    fn snapshot(&self) -> Result<Snapshot>;

    /// Replay a previously saved snapshot.
    fn restore(&self, snap: &Snapshot) -> Result<()>;

    /// Insert the tool's own allow-rule first and atomically, before any flush.
    fn ensure_tool_rule(&self, rule: &ToolRule) -> Result<()>;

    /// Apply a default-deny allowlist. Must be safe with an empty allowlist.
    fn apply_lockdown(&self, plan: &LockdownPlan) -> Result<()>;
}

/// Holds every known backend and picks the active one.
pub struct Registry {
    backends: Vec<Box<dyn Backend>>,
}

impl Registry {
    /// All shipped backends. Add new backends here.
    pub fn with_builtins() -> Self {
        let mut r = Registry { backends: Vec::new() };
        r.register(Box::new(backends::nftables::Nftables::new()));
        r.register(Box::new(backends::iptables::Iptables::new()));
        r
    }

    pub fn register(&mut self, backend: Box<dyn Backend>) {
        self.backends.push(backend);
    }

    /// First backend that reports itself active. nftables is registered first so it wins
    /// when both are present (SPECS section 1: nftables preferred).
    pub fn active(&self) -> Result<&dyn Backend> {
        self.backends
            .iter()
            .map(|b| b.as_ref())
            .find(|b| b.detect())
            .ok_or(ch_common::Error::NoImpl("firewall"))
    }
}
