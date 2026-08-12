//! Sensing core: build a read-only host model by parsing /proc and config files
//! directly, never shelling out (SPECS 13.6). One snapshot feeds info, hunt, baseline,
//! and the dossier builder.

#![forbid(unsafe_code)]

pub mod baseline;
pub mod procfs;

use serde::{Deserialize, Serialize};

/// A point-in-time view of the host, built once and shared by all consumers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub processes: Vec<Process>,
    pub sockets: Vec<Socket>,
    // Extended at M3/M4: users, modules, mounts, firewall state, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub exe: String,
    /// Original login account, survives su/sudo (SPECS section 10).
    pub loginuid: Option<u32>,
    /// True if the exe is deleted or a memfd (SPECS section 4).
    pub anomalous_exe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socket {
    pub proto: String,
    pub local: String,
    pub inode: u64,
    pub pid: Option<i32>,
}

/// Build a fresh snapshot of the host.
pub fn snapshot() -> ch_common::Result<HostSnapshot> {
    // M3: populate from /proc.
    Ok(HostSnapshot::default())
}
