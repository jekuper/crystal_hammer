//! iptables-legacy backend. Drives `iptables`/`iptables-save`/`iptables-restore` by exec.

use crate::{Backend, LockdownPlan, Snapshot, ToolRule};
use ch_common::Result;

pub struct Iptables {
    _priv: (),
}

impl Iptables {
    pub fn new() -> Self {
        Iptables { _priv: () }
    }
}

impl Backend for Iptables {
    fn id(&self) -> ch_common::ImplId {
        "iptables"
    }

    fn detect(&self) -> bool {
        // M2: probe for iptables-legacy when nftables is absent.
        false
    }

    fn snapshot(&self) -> Result<Snapshot> {
        unimplemented!("M2: iptables-save")
    }

    fn restore(&self, _snap: &Snapshot) -> Result<()> {
        unimplemented!("M2: iptables-restore")
    }

    fn ensure_tool_rule(&self, _rule: &ToolRule) -> Result<()> {
        unimplemented!("M2: -I first, atomically")
    }

    fn apply_lockdown(&self, _plan: &LockdownPlan) -> Result<()> {
        unimplemented!("M2: default-deny allowlist, empty-safe")
    }
}
