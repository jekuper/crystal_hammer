//! No-open-port backdoor checks (SPECS section 5 `hunt` / `stealth`).

use crate::{Cadence, Check, Finding};

/// Packet/raw socket holders that show no listening port (SPECS section 5.1).
pub struct PacketSocketHolders {
    _priv: (),
}

impl PacketSocketHolders {
    pub fn new() -> Self {
        PacketSocketHolders { _priv: () }
    }
}

impl Check for PacketSocketHolders {
    fn id(&self) -> ch_common::ImplId {
        "stealth.packet_sockets"
    }

    fn cadence(&self) -> Cadence {
        Cadence::Poll
    }

    fn run(&self, _host: &ch_sense::HostSnapshot) -> Vec<Finding> {
        // M4: parse /proc/net/packet + raw, map socket inodes to PIDs, allowlist legit.
        Vec::new()
    }
}
