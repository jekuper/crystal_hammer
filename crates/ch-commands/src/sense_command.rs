//! Standalone host-visibility commands (SPECS M3). `procs` and `conns` parse /proc
//! directly; `ports`, `users` and `recent` are thin front-ends onto the richer `info`
//! sections so an operator can reach each view by name.

use std::fmt::Write as _;
use std::fs;

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::info_command::{get_inode_to_process_map, get_uid_to_username_map, parse_hex_ip};
use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

fn status_field(status: &str, prefix: &str) -> String {
    status
        .lines()
        .find(|l| l.starts_with(prefix))
        .map(|l| l[prefix.len()..].trim().to_string())
        .unwrap_or_default()
}

/// "<hex-ip>:<hex-port>" (as in /proc/net/tcp) -> "ip:port".
fn endpoint(field: &str, is_v6: bool) -> String {
    match field.split_once(':') {
        Some((ip, port)) => {
            let ip = parse_hex_ip(ip, is_v6).unwrap_or_else(|| ip.to_string());
            let port = u16::from_str_radix(port, 16).map(|p| p.to_string()).unwrap_or_else(|_| port.to_string());
            format!("{ip}:{port}")
        }
        None => field.to_string(),
    }
}

// =============================================================================
// procs
// =============================================================================

pub struct ProcsAgentCommand {}
impl ProcsAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for ProcsAgentCommand {
    fn name(&self) -> &'static str {
        "procs"
    }
    async fn execute(&self, _args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let users = get_uid_to_username_map();
        let mut rows: Vec<(i32, i32, String, String, String)> = Vec::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for e in entries.flatten() {
                let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
                let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
                let comm = status_field(&status, "Name:");
                let ppid = status_field(&status, "PPid:").parse::<i32>().unwrap_or(0);
                let uid = status
                    .lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u32>().ok());
                let user = uid
                    .and_then(|u| users.get(&u).cloned().or(Some(u.to_string())))
                    .unwrap_or_default();
                let exe = fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.display().to_string()).unwrap_or_default();
                let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
                    .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
                    .unwrap_or_default();
                rows.push((pid, ppid, user, comm, if cmdline.is_empty() { exe } else { cmdline }));
            }
        }
        rows.sort_by_key(|r| r.0);

        let mut out = format!("{:>7} {:>7} {:<12} {:<16} {}\n", "PID", "PPID", "USER", "COMM", "CMD/EXE");
        for (pid, ppid, user, comm, cmd) in rows {
            let _ = writeln!(out, "{pid:>7} {ppid:>7} {user:<12} {comm:<16} {cmd}");
        }
        ctx.stdout.write_all(out.as_bytes()).await?;
        Ok(())
    }
}

// =============================================================================
// conns
// =============================================================================

pub struct ConnsAgentCommand {}
impl ConnsAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for ConnsAgentCommand {
    fn name(&self) -> &'static str {
        "conns"
    }
    async fn execute(&self, _args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        const ESTABLISHED: &str = "01";
        let inode_map = get_inode_to_process_map();
        let mut out = format!("{:<5} {:<28} {:<28} {:<7} {}\n", "PROTO", "LOCAL", "REMOTE", "PID", "PROCESS");
        for (path, proto, is_v6) in [("/proc/net/tcp", "tcp", false), ("/proc/net/tcp6", "tcp6", true)] {
            let Ok(content) = fs::read_to_string(path) else { continue };
            for line in content.lines().skip(1) {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 10 || f[3] != ESTABLISHED {
                    continue;
                }
                let local = endpoint(f[1], is_v6);
                let remote = endpoint(f[2], is_v6);
                let (pid, name) = f[9]
                    .parse::<u64>()
                    .ok()
                    .and_then(|ino| inode_map.get(&ino))
                    .map(|(p, n)| (p.to_string(), n.clone()))
                    .unwrap_or_else(|| ("-".to_string(), "-".to_string()));
                let _ = writeln!(out, "{proto:<5} {local:<28} {remote:<28} {pid:<7} {name}");
            }
        }
        ctx.stdout.write_all(out.as_bytes()).await?;
        Ok(())
    }
}

// =============================================================================
// Client sides (procs/conns are real; ports/users/recent reuse `info`)
// =============================================================================

macro_rules! simple_client {
    ($ty:ident, $name:literal, $short:literal, $help:literal, $remote:literal, $args:expr) => {
        pub struct $ty {}
        impl $ty {
            pub fn new() -> Self {
                Self {}
            }
        }
        #[async_trait]
        impl ClientCommand for $ty {
            fn name(&self) -> &'static str { $name }
            fn short_description(&self) -> &'static str { $short }
            fn help(&self) -> &'static str { $help }
            fn complete_arg(&self, _p: &[&str], _w: &str, _c: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
                Vec::new()
            }
            async fn execute(&self, _e: &dyn ClientCommandExecutor, _args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
                let args: Vec<String> = $args.iter().map(|s: &&str| s.to_string()).collect();
                run_remote(ctx, $remote, &args).await
            }
        }
    };
}

simple_client!(ProcsClientCommand, "procs", "List processes", "Usage: procs\n\nAll processes with pid, ppid, user, comm and cmdline (from /proc).", "procs", &[] as &[&str]);
simple_client!(ConnsClientCommand, "conns", "List established connections", "Usage: conns\n\nEstablished TCP connections with local/remote endpoints and owning process.", "conns", &[] as &[&str]);
simple_client!(PortsClientCommand, "ports", "List listening sockets", "Usage: ports\n\nListening TCP/UDP sockets and their owners (the info 'listeners' view).", "info", &["listeners"]);
simple_client!(UsersClientCommand, "users", "List users and sessions", "Usage: users\n\nLogged-in sessions and login-shell accounts (the info 'users' view).", "info", &["users"]);
simple_client!(RecentClientCommand, "recent", "Recent auth activity", "Usage: recent\n\nRecent authentication failures from the auth log (the info 'auth' view).", "info", &["auth"]);
