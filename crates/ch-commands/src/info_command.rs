use std::fs;
use std::collections::HashMap;
use async_trait::async_trait;
use ch_common::Result;
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, ClientCommand, ClientContext, Context};
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;


#[derive(Debug, Clone)]
struct Listener {
    proto: String,
    local_ip: String,
    local_port: u16,
    inode: u64,
}



/// TCP states we consider "listening". UDP has no real state machine over
/// its socket table, so for UDP we treat *any* bound entry as a "listener"
/// (there's no LISTEN concept — it's just "something is bound to this port").
const TCP_LISTEN_STATE: &str = "0A";

pub struct InfoAgentCommand {}

impl InfoAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    fn get_hostname(&self) -> String {
        fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }

    fn get_distro(&self) -> String {
        if let Ok(content) = fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return line
                        .trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string();
                }
            }
        }
        "Unknown Linux Distro".to_string()
    }

    fn get_kernel(&self) -> String {
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }

    async fn get_firewall_status(&self) -> String {
        let fw = ch_firewall::loader::Firewall::global();
        let mode_str = match fw.get_mode().await {
            Ok(ch_firewall::loader::Mode::Regular) => "Regular (All traffic passes)".to_string(),
            Ok(ch_firewall::loader::Mode::Lockdown) => {
                let ports = fw.get_allowed_ports().await
                    .map(|p| p.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "))
                    .unwrap_or_else(|_| "Unknown".to_string());
                format!("Lockdown (Allowed ports: [{}])", ports)
            }
            Err(e) => format!("Error reading mode: {}", e),
        };

        // Helper closure to check if a binary exists in common system paths
        let has_binary = |binary_name: &str| -> bool {
            let paths = [
                format!("/usr/sbin/{}", binary_name),
                format!("/sbin/{}", binary_name),
                format!("/usr/bin/{}", binary_name),
                format!("/bin/{}", binary_name),
            ];
            paths.iter().any(|p| Path::new(p).exists())
        };

        let mut tools = Vec::new();

        // 1. Core Backends
        if has_binary("nft") {
            tools.push("nftables");
        }
        if has_binary("iptables") {
            tools.push("iptables");
        }

        // 2. Debian/Ubuntu Frontend
        if has_binary("ufw") {
            tools.push("UFW");
        }

        // 3. RHEL/Fedora/CentOS & Modern SUSE Frontend
        if has_binary("firewall-cmd") {
            tools.push("firewalld");
        }

        // 4. Legacy SUSE Frontend
        if has_binary("SuSEfirewall2") {
            tools.push("SuSEfirewall2");
        }

        let tools_str = if tools.is_empty() {
            "None detected".to_string()
        } else {
            tools.join("\n")
        };

        format!("eBPF ({})\nSystem backends present: {}", mode_str, tools_str)
    }

    fn get_all_listeners(&self) -> String {
        let mut report = String::with_capacity(4096);

        let _ = writeln!(
            report,
            "{:<6} {:<47} {:<10} {:<6} {:<15}",
            "Proto", "Local Address", "Inode", "PID", "Process"
        );
        let _ = writeln!(report, "{}", "-".repeat(90));

        let inode_proc = get_inode_to_process_map();

        let mut listeners = Vec::new();
        listeners.extend(parse_listeners_from_file("/proc/net/tcp", "tcp", false));
        listeners.extend(parse_listeners_from_file("/proc/net/tcp6", "tcp6", true));
        listeners.extend(parse_listeners_from_file("/proc/net/udp", "udp", false));
        listeners.extend(parse_listeners_from_file("/proc/net/udp6", "udp6", true));

        if listeners.is_empty() {
            report.push_str("No active listeners found.\n");
            return report;
        }

        listeners.sort_by(|a, b| {
            a.proto
                .cmp(&b.proto)
                .then(a.local_port.cmp(&b.local_port))
        });

        for listener in &listeners {
            let local_addr = format!("{}:{}", listener.local_ip, listener.local_port);
            let (pid_str, proc_name) = inode_proc
                .get(&listener.inode)
                .map(|(pid, name)| (pid.to_string(), name.clone()))
                .unwrap_or_else(|| ("-".to_string(), "-".to_string()));

            let _ = writeln!(
                report,
                "{:<6} {:<47} {:<10} {:<6} {:<15}",
                listener.proto, local_addr, listener.inode, pid_str, proc_name
            );
        }

        report
    }

    
    fn get_logged_in_users(&self) -> String {
        let mut report = String::new();
        let uid_map = get_uid_to_username_map();
        let sessions = get_active_shells(&uid_map);

        if sessions.is_empty() {
            report.push_str("No active sessions found\n");
        } else {
            for s in sessions {
                report.push_str(&format!("- {}\n", s));
            }
        }
        report
    }

    fn get_all_users(&self) -> String {
        let mut users = Vec::new();
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let username = parts[0];
                    let shell = parts[6];
                    users.push(format!("{} ({})", username, shell));
                }
            }
        }
        if users.is_empty() {
            "None".to_string()
        } else {
            users.join("\n")
        }
    }

    fn get_recent_auth_failures(&self) -> String {
        let failures = get_recent_auth_failures_log();
        failures.join("\n")
    }

    fn get_persistence_health(&self) -> String {
        return "Not Implemented!".to_string();
    }
}

#[async_trait]
impl AgentCommand for InfoAgentCommand {
    fn name(&self) -> &'static str { "info" }

    async fn execute(&self, args: Vec<String>, mut ctx: Context) -> Result<()> {
        let mut level = "max";
        let mut show_host = false;
        let mut show_firewall = false;
        let mut show_listeners = false;
        let mut show_users = false;
        let mut show_auth = false;
        let mut show_persistence = false;

        let mut has_specific_sections = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "min" => level = "min",
                "med" => level = "med",
                "max" => level = "max",
                "--level" if i + 1 < args.len() => {
                    level = match args[i + 1].as_str() {
                        "min" => "min",
                        "med" => "med",
                        _ => "max",
                    };
                    i += 1;
                }
                "host" => {
                    show_host = true;
                    has_specific_sections = true;
                }
                "firewall" => {
                    show_firewall = true;
                    has_specific_sections = true;
                }
                "listeners" | "ports" => {
                    show_listeners = true;
                    has_specific_sections = true;
                }
                "users" => {
                    show_users = true;
                    has_specific_sections = true;
                }
                "auth" => {
                    show_auth = true;
                    has_specific_sections = true;
                }
                "persistence" => {
                    show_persistence = true;
                    has_specific_sections = true;
                }
                _ => {}
            }
            i += 1;
        }

        if !has_specific_sections {
            match level {
                "min" => {
                    show_host = true;
                    show_persistence = true;
                }
                "med" => {
                    show_host = true;
                    show_firewall = true;
                    show_users = true;
                    show_persistence = true;
                }
                _ => {
                    show_host = true;
                    show_firewall = true;
                    show_listeners = true;
                    show_users = true;
                    show_auth = true;
                    show_persistence = true;
                }
            }
        }

        let mut report = String::new();

        if show_host {
            report.push_str("--- Host Information ---\n");
            report.push_str(&format!("Hostname: {}\n", self.get_hostname()));
            report.push_str(&format!("Distro:   {}\n", self.get_distro()));
            report.push_str(&format!("Kernel:   {}\n\n", self.get_kernel()));
        }

        if show_firewall {
            report.push_str("--- Firewall Backend & State ---\n");
            report.push_str(&format!("{}\n\n", self.get_firewall_status().await));
        }

        if show_listeners {
            report.push_str("--- Listening Sockets ---\n");
            report.push_str(&self.get_all_listeners());
            report.push_str("\n");
        }

        if show_users {
            report.push_str("--- Active Users & Logins ---\n");
            report.push_str("Logged-in Sessions (utmp/loginuid):\n");
            report.push_str(&self.get_logged_in_users());
            report.push_str("\nAll System Users (login shells):\n");
            report.push_str(&format!("{}\n\n", self.get_all_users()));
        }

        if show_auth {
            report.push_str("--- Recent Auth Failures ---\n");
            report.push_str(&self.get_recent_auth_failures());
            report.push_str("\n\n");
        }

        if show_persistence {
            report.push_str("--- Persistence Health ---\n");
            report.push_str(&format!("Tool Persistence: {}\n\n", self.get_persistence_health()));
        }

        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

fn parse_listeners_from_file(path: &str, proto: &str, is_v6: bool) -> Vec<Listener> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(), // file missing (e.g. IPv6 disabled) — not fatal
    };

    let is_udp = proto.starts_with("udp");
    let mut out = Vec::new();

    // Skip header line
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // local_address is field[1], state is field[3], inode is field[9]
        if fields.len() < 10 {
            continue; // malformed/unexpected line — skip, don't panic
        }

        let state = fields[3];
        if !is_udp && state != TCP_LISTEN_STATE {
            continue; // TCP: only listening sockets
        }

        let local = fields[1];
        let Some((ip_hex, port_hex)) = local.split_once(':') else {
            continue;
        };

        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };

        let Some(ip_str) = parse_hex_ip(ip_hex, is_v6) else {
            continue;
        };

        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };

        out.push(Listener {
            proto: proto.to_string(),
            local_ip: ip_str,
            local_port: port,
            inode,
        });
    }

    out
}

fn get_inode_to_process_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map, // /proc unreadable — return empty, don't panic
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else { continue };
        let Ok(pid) = pid_str.parse::<u32>() else { continue }; // skip non-PID entries

        let fd_dir_path = format!("/proc/{pid}/fd");
        let Ok(fd_dir) = fs::read_dir(&fd_dir_path) else { continue }; // process gone / no fds

        // Resolve process name once per PID
        let name = fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "-".to_string());

        for fd_entry in fd_dir.flatten() {
            let path = fd_entry.path();
            let Ok(target) = fs::read_link(&path) else { continue }; // fd closed mid-scan
            let Some(target_str) = target.to_str() else { continue };

            if let Some(inode_str) = target_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    map.insert(inode, (pid, name.clone()));
                }
            }
        }
    }

    map
}


/// Primary source of truth: walks /proc directly, independent of utmp.
/// Finds session-leader processes with a real controlling tty.
fn get_active_shells(uid_map: &HashMap<u32, String>) -> Vec<String> {
    let mut sessions = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else { return sessions; };

    for entry in entries.flatten() {
        let pid_str = entry.file_name().to_string_lossy().to_string();
        let Ok(pid) = pid_str.parse::<i32>() else { continue };

        let stat_path = entry.path().join("stat");
        let Ok(stat) = fs::read_to_string(&stat_path) else { continue };

        // comm field can contain spaces/parens, so split after the LAST ')'
        let Some(rparen) = stat.rfind(')') else { continue };
        let rest: Vec<&str> = stat[rparen + 2..].split_whitespace().collect();
        // fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4) ...
        let (Some(&sid_str), Some(&tty_nr_str)) = (rest.get(3), rest.get(4)) else { continue };
        let (Ok(sid), Ok(tty_nr)) = (sid_str.parse::<i32>(), tty_nr_str.parse::<i64>()) else { continue };

        // Only session leaders with a real controlling tty
        if pid != sid || tty_nr == 0 {
            continue;
        }

        let tty_name = resolve_tty_name(&entry.path(), major_minor(tty_nr));

        let Ok(status) = fs::read_to_string(entry.path().join("status")) else { continue };
        let uid = status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u32>().ok());

        if let Some(uid) = uid {
            let user = uid_map
                .get(&uid)
                .cloned()
                .unwrap_or_else(|| uid.to_string());
            sessions.push(format!("{} (on {}, pid {})", user, tty_name, pid));
        }
    }

    sessions
}

/// Decode tty_nr from /proc/[pid]/stat into (major, minor).
fn major_minor(tty_nr: i64) -> (i64, i64) {
    let major = (tty_nr >> 8) & 0xfff;
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
    (major, minor)
}

/// Resolve a tty device to a friendly name. Tries fd/0 symlink first
/// (most direct — no major/minor guessing), falls back to major/minor math.
fn resolve_tty_name(proc_pid_path: &std::path::Path, mm: (i64, i64)) -> String {
    for fd in ["fd/0", "fd/1", "fd/2"] {
        if let Ok(target) = fs::read_link(proc_pid_path.join(fd)) {
            let target_str = target.to_string_lossy();
            if target_str.starts_with("/dev/pts/") || target_str.starts_with("/dev/tty") {
                return target_str
                    .trim_start_matches("/dev/")
                    .to_string();
            }
        }
    }

    let (major, minor) = mm;
    if (136..=143).contains(&major) {
        format!("pts/{}", minor)
    } else {
        format!("tty (major {}, minor {})", major, minor)
    }
}

fn get_uid_to_username_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let username = parts[0].to_string();
                if let Ok(uid) = parts[2].parse::<u32>() {
                    map.insert(uid, username);
                }
            }
        }
    }
    map
}

fn get_recent_auth_failures_log() -> Vec<String> {
    let mut failures = Vec::new();
    let paths = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/audit/audit.log"
    ];
    let mut log_content = String::new();
    for p in &paths {
        if let Ok(content) = fs::read_to_string(p) {
            log_content = content;
            break;
        }
    }

    if log_content.is_empty() {
        return vec!["No readable auth log found or empty".to_string()];
    }

    let lines: Vec<&str> = log_content.lines().collect();
    let start = lines.len().saturating_sub(500);
    for line in &lines[start..] {
        let line_lower = line.to_lowercase();
        if line_lower.contains("fail") || line_lower.contains("invalid user") || (!line_lower.contains("accept") && line_lower.contains("unauthorized")) {
            if line_lower.contains("password") || line_lower.contains("publickey") || line_lower.contains("login") || line_lower.contains("ssh") {
                failures.push(line.trim().to_string());
            }
        }
    }

    if failures.is_empty() {
        failures.push("No recent authentication failures detected in log".to_string());
    } else if failures.len() > 10 {
        let len = failures.len();
        failures = failures[len - 10..].to_vec();
    }
    failures
}



/// Parses the hex-encoded IP from /proc/net/{tcp,udp}[6].
/// IPv4 fields are 8 hex chars (little-endian 32-bit).
/// IPv6 fields are 32 hex chars (four little-endian 32-bit words).
fn parse_hex_ip(hex: &str, is_v6: bool) -> Option<String> {
    if is_v6 {
        if hex.len() != 32 {
            return None;
        }
        let mut words = [0u32; 4];
        for i in 0..4 {
            words[i] = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        }
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&words[i].to_le_bytes());
        }
        let addr = Ipv6Addr::from(bytes);
        // Normalize dual-stack-mapped v4 addresses for readability
        if let Some(v4) = addr.to_ipv4_mapped() {
            Some(v4.to_string())
        } else {
            Some(addr.to_string())
        }
    } else {
        if hex.len() != 8 {
            return None;
        }
        let n = u32::from_str_radix(hex, 16).ok()?;
        Some(Ipv4Addr::from(n.to_le_bytes()).to_string())
    }
}


pub struct InfoClientCommand {}

impl InfoClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for InfoClientCommand {
    fn name(&self) -> &'static str { "info" }
    fn short_description(&self) -> &'static str { "Fetch host info" }
    fn help(&self) -> &'static str { 
        "Usage: info [options] [sections]\n\n\
        Options:\n\
          min            Minimal information (Host, Persistence)\n\
          med            Medium information (Host, Firewall, Users, Persistence)\n\
          max            Full information (Default)\n\
          --level <lvl>  Set level to min, med, or max\n\n\
        Sections (multiple can be specified):\n\
          host           Hostname, Distro, Kernel\n\
          firewall       eBPF/system firewall state\n\
          listeners      Network listening ports and owners\n\
          users          utmp, loginuids, login shells\n\
          auth           Recent authentication logs\n\
          persistence    Tool persistence self-checks"
    }

    async fn execute(&self, args: &[String], ctx: ClientContext<'_>) -> Result<()> {
        let session = ctx.session;
        let mut channel = session.channel_open_session()
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let server_command = InfoAgentCommand::new();

        let exec_payload = if args.is_empty() {
            server_command.name().to_string()
        } else {
            format!("{} {}", server_command.name(), args.join(" "))
        };

        channel.exec(true, exec_payload.as_bytes()).await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    let s = std::str::from_utf8(data).unwrap_or_default();
                    print!("{}", s);
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }
                russh::ChannelMsg::ExtendedData { ref data, .. } => {
                    let s = std::str::from_utf8(data).unwrap_or_default();
                    eprint!("{}", s);
                    use std::io::Write;
                    let _ = std::io::stderr().flush();
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    if exit_status != 0 {
                        tracing::warn!("Remote command exited with status {}", exit_status);
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        Ok(())
    }
}