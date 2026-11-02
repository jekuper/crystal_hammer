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

    fn run(&self, host: &ch_sense::HostSnapshot) -> Vec<Finding> {
        host.sockets
            .iter()
            .filter(|s| s.proto == "packet" || s.proto.starts_with("raw"))
            .map(|s| {
                let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string());
                Finding {
                    check: self.id().to_string(),
                    severity: crate::Severity::Warn,
                    summary: format!("{} socket held by pid {pid}", s.proto),
                    detail: serde_json::json!({ "proto": s.proto, "pid": s.pid, "inode": s.inode }),
                }
            })
            .collect()
    }
}

/// A process whose executable is deleted or memfd-backed (SPECS section 4) - a classic
/// sign of a fileless implant.
pub struct AnomalousExe {
    _priv: (),
}

impl AnomalousExe {
    pub fn new() -> Self {
        AnomalousExe { _priv: () }
    }
}

impl Check for AnomalousExe {
    fn id(&self) -> ch_common::ImplId {
        "stealth.anomalous_exe"
    }

    fn cadence(&self) -> Cadence {
        Cadence::Poll
    }

    fn run(&self, host: &ch_sense::HostSnapshot) -> Vec<Finding> {
        host.processes
            .iter()
            .filter(|p| p.anomalous_exe)
            .map(|p| Finding {
                check: self.id().to_string(),
                severity: crate::Severity::Critical,
                summary: format!("pid {} ({}) runs a deleted/memfd executable", p.pid, p.comm),
                detail: serde_json::json!({
                    "pid": p.pid, "ppid": p.ppid, "comm": p.comm, "exe": p.exe, "loginuid": p.loginuid
                }),
            })
            .collect()
    }
}
