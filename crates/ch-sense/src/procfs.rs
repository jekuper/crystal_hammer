//! Direct /proc parsers. No external process is ever spawned here; this is pure reading.

use std::collections::HashMap;
use std::fs;

use crate::{Process, Socket};

fn status_field(status: &str, prefix: &str) -> String {
    status
        .lines()
        .find(|l| l.starts_with(prefix))
        .map(|l| l[prefix.len()..].trim().to_string())
        .unwrap_or_default()
}

/// Parse /proc into the process list (read-only).
pub fn read_processes() -> ch_common::Result<Vec<Process>> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else { return Ok(out) };
    for e in entries.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
        let comm = status_field(&status, "Name:");
        let ppid = status_field(&status, "PPid:").parse::<i32>().unwrap_or(0);

        // A deleted or memfd-backed exe is the classic sign of a process running from a
        // file that is no longer on disk.
        let raw = fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.display().to_string()).unwrap_or_default();
        let anomalous_exe = raw.contains("(deleted)") || raw.contains("/memfd:") || raw.starts_with("memfd:");
        let exe = raw.trim_end_matches(" (deleted)").to_string();

        let loginuid = fs::read_to_string(format!("/proc/{pid}/loginuid"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&u| u != u32::MAX);

        out.push(Process { pid, ppid, comm, exe, loginuid, anomalous_exe });
    }
    Ok(out)
}

/// Socket inode -> owning pid, from every process's fd table.
fn inode_pid_map() -> HashMap<u64, i32> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else { return map };
    for e in entries.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if let Some(ino) = target
                    .to_str()
                    .and_then(|s| s.strip_prefix("socket:["))
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    map.entry(ino).or_insert(pid);
                }
            }
        }
    }
    map
}

/// Parse the raw/packet socket tables, which is where a no-open-port sniffer shows up.
/// (TCP/UDP tables are served by the `ports`/`conns` commands; the hunt path only needs
/// the stealthy socket families here.)
pub fn read_sockets() -> ch_common::Result<Vec<Socket>> {
    let map = inode_pid_map();
    let mut out = Vec::new();

    // AF_PACKET: last column is the socket inode.
    if let Ok(content) = fs::read_to_string("/proc/net/packet") {
        for line in content.lines().skip(1) {
            if let Some(ino) = line.split_whitespace().last().and_then(|s| s.parse::<u64>().ok()) {
                out.push(Socket { proto: "packet".into(), local: String::new(), inode: ino, pid: map.get(&ino).copied() });
            }
        }
    }

    // Raw IP sockets: same column layout as tcp/udp (inode is field 9).
    for (path, proto) in [("/proc/net/raw", "raw"), ("/proc/net/raw6", "raw6")] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 10 {
                    continue;
                }
                let ino = f[9].parse::<u64>().unwrap_or(0);
                out.push(Socket { proto: proto.into(), local: f[1].to_string(), inode: ino, pid: map.get(&ino).copied() });
            }
        }
    }

    Ok(out)
}
