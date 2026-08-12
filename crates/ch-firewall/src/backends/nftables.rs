//! nftables backend. Drives `nft` by exec; snapshots via `nft list ruleset`.

use crate::{Backend, LockdownPlan, Snapshot, ToolRule};
use ch_common::Result;

pub struct Nftables {
    _priv: (),
}

impl Nftables {
    pub fn new() -> Self {
        Nftables { _priv: () }
    }
}

impl Backend for Nftables {
    fn id(&self) -> ch_common::ImplId {
        "nftables"
    }

    fn detect(&self) -> bool {
        // M2: probe for a usable `nft` and an active ruleset.
        false
    }

    fn snapshot(&self) -> Result<Snapshot> {
        unimplemented!("M2: nft list ruleset")
    }

    fn restore(&self, _snap: &Snapshot) -> Result<()> {
        unimplemented!("M2: nft -f <snapshot>")
    }

    fn ensure_tool_rule(&self, _rule: &ToolRule) -> Result<()> {
        unimplemented!("M2: insert tool allow-rule first, atomically")
    }

    fn apply_lockdown(&self, _plan: &LockdownPlan) -> Result<()> {
        unimplemented!("M2: default-deny allowlist, empty-safe")
    }
}
