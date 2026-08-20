use std::fs;
use std::collections::HashMap;
use async_trait::async_trait;
use ch_common::Result;
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, ClientCommand, ClientContext, Context};

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

        let mut tools = Vec::new();
        if fs::metadata("/usr/sbin/nft").is_ok() || fs::metadata("/sbin/nft").is_ok() {
            tools.push("nftables");
        }
        if fs::metadata("/usr/sbin/iptables").is_ok() || fs::metadata("/sbin/iptables").is_ok() {
            tools.push("iptables");
        }
        let tools_str = if tools.is_empty() {
            "None detected".to_string()
        } else {
            tools.join(", ")
        };

        format!("eBPF ({}) [System backends present: {}]", mode_str, tools_str)
    }

    use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

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

/// Maps socket inode -> (pid, process name). Best-effort: any per-PID
/// failure (process exited mid-scan, unreadable fd, etc.) is skipped
/// rather than aborting the whole scan.
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
        let utmp_users = get_logged_in_users_utmp();
        if utmp_users.is_empty() {
            report.push_str("No active utmp sessions\n");
        } else {
            for u in utmp_users {
                report.push_str(&format!("- {}\n", u));
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
            users.join(", ")
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
            report.push_str(&format!("Status: {}\n\n", self.get_firewall_status().await));
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
            report.push_str(&format!("- {}\n\n", self.get_all_users()));
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

struct ListenerInfo {
    proto: String,
    local_ip: String,
    local_port: u16,
    inode: u64,
}

fn parse_ipv4_hex(hex_str: &str) -> Option<std::net::Ipv4Addr> {
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    let b1 = (val & 0xFF) as u8;
    let b2 = ((val >> 8) & 0xFF) as u8;
    let b3 = ((val >> 16) & 0xFF) as u8;
    let b4 = ((val >> 24) & 0xFF) as u8;
    Some(std::net::Ipv4Addr::new(b1, b2, b3, b4))
}

fn parse_ipv6_hex(hex_str: &str) -> Option<std::net::Ipv6Addr> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut segments = [0u16; 8];
    for i in 0..8 {
        let seg_str = &hex_str[i * 4..(i + 1) * 4];
        let val = u32::from_str_radix(seg_str, 16).ok()?;
        segments[i] = (val & 0xFFFF) as u16;
    }
    #[cfg(target_endian = "little")]
    {
        for seg in segments.iter_mut() {
            *seg = seg.swap_bytes();
        }
    }
    Some(std::net::Ipv6Addr::new(
        segments[0], segments[1], segments[2], segments[3],
        segments[4], segments[5], segments[6], segments[7]
    ))
}

fn parse_listeners_from_file(path: &str, proto: &str, is_v6: bool) -> Vec<ListenerInfo> {
    let mut listeners = Vec::new();
    let Ok(content) = fs::read_to_string(path) else {
        return listeners;
    };
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local_addr_part = parts[1];
        let state_part = parts[3];
        let inode_part = parts[9];

        if proto.starts_with("tcp") && state_part != "0A" {
            continue;
        }

        let addr_port_parts: Vec<&str> = local_addr_part.split(':').collect();
        if addr_port_parts.len() != 2 {
            continue;
        }
        let ip_hex = addr_port_parts[0];
        let port_hex = addr_port_parts[1];

        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let Ok(inode) = inode_part.parse::<u64>() else {
            continue;
        };

        let ip_str = if is_v6 {
            if let Some(ip) = parse_ipv6_hex(ip_hex) {
                ip.to_string()
            } else {
                continue;
            }
        } else {
            if let Some(ip) = parse_ipv4_hex(ip_hex) {
                ip.to_string()
            } else {
                continue;
            }
        };

        listeners.push(ListenerInfo {
            proto: proto.to_string(),
            local_ip: ip_str,
            local_port: port,
            inode,
        });
    }
    listeners
}

fn get_inode_to_process_map() -> HashMap<u64, (i32, String)> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries {
        let Ok(entry) = entry else { continue; };
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<i32>() else {
            continue;
        };
        
        let comm = fs::read_to_string(path.join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
            
        let fd_path = path.join("fd");
        let Ok(fd_entries) = fs::read_dir(fd_path) else {
            continue;
        };
        for fd_entry in fd_entries {
            let Ok(fd_entry) = fd_entry else { continue; };
            if let Ok(link) = fs::read_link(fd_entry.path()) {
                let link_str = link.to_string_lossy();
                if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                    let inode_str = &link_str[8..link_str.len() - 1];
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        map.insert(inode, (pid, comm.clone()));
                    }
                }
            }
        }
    }
    map
}

fn get_logged_in_users_utmp() -> Vec<String> {
    let mut users = Vec::new();
    let paths = ["/run/utmp", "/var/run/utmp"];
    let mut content = None;
    for p in &paths {
        if let Ok(bytes) = fs::read(p) {
            content = Some(bytes);
            break;
        }
    }
    
    if let Some(bytes) = content {
        const UTMP_SIZE: usize = 384;
        for chunk in bytes.chunks_exact(UTMP_SIZE) {
            let ut_type = u16::from_ne_bytes([chunk[0], chunk[1]]);
            if ut_type == 7 {
                let ut_user_bytes = &chunk[44..76];
                let ut_user = std::str::from_utf8(ut_user_bytes)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();

                let ut_line_bytes = &chunk[8..40];
                let ut_line = std::str::from_utf8(ut_line_bytes)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();

                let ut_host_bytes = &chunk[76..332];
                let ut_host = std::str::from_utf8(ut_host_bytes)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();

                if !ut_user.is_empty() {
                    let host_info = if ut_host.is_empty() {
                        "".to_string()
                    } else {
                        format!(" from {}", ut_host)
                    };
                    users.push(format!("{} (on {}){}", ut_user, ut_line, host_info));
                }
            }
        }
    }

    if users.is_empty() {
        let uid_map = get_uid_to_username_map();
        users = get_active_loginuids(&uid_map);
    }

    users
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

fn get_active_loginuids(uid_map: &HashMap<u32, String>) -> Vec<String> {
    let mut active = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return active;
    };
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        let Ok(entry) = entry else { continue; };
        let path = entry.path();
        let Ok(_pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if let Ok(loginuid_str) = fs::read_to_string(path.join("loginuid")) {
            if let Ok(loginuid) = loginuid_str.trim().parse::<u32>() {
                if loginuid != 4294967295 && seen.insert(loginuid) {
                    if let Some(user) = uid_map.get(&loginuid) {
                        active.push(format!("{} (loginuid: {})", user, loginuid));
                    }
                }
            }
        }
    }
    active
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