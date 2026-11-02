//! `attribute <pid>` - the dossier (SPECS M6). Given a process, assemble who/what/how by
//! reading /proc directly and correlating with the auth log: identity (real vs effective
//! uid, loginuid), the exe and its hash, the parent chain (the entry vector), the tty, and
//! the matching SSH login (source IP + method). Never shells out to host binaries.

use std::fs;
use std::fmt::Write as _;
use std::path::Path;

use async_trait::async_trait;
use ch_common::{Hash, Result};
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

const MAX_ANCESTRY: usize = 32;
const AUTH_LOGS: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

/// uid -> username, read straight from /etc/passwd.
fn uid_name(uid: &str) -> Option<String> {
    if uid.is_empty() || uid == "4294967295" {
        return None;
    }
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut f = line.split(':');
        if let (Some(name), Some(_), Some(id)) = (f.next(), f.next(), f.next()) {
            if id == uid {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn show_uid(uid: &str) -> String {
    match uid_name(uid) {
        Some(name) => format!("{uid} ({name})"),
        None => uid.to_string(),
    }
}

/// One line of /proc/<pid>/status by prefix (e.g. "PPid:").
fn status_field(status: &str, prefix: &str) -> Option<String> {
    status
        .lines()
        .find(|l| l.starts_with(prefix))
        .map(|l| l[prefix.len()..].trim().to_string())
}

struct Proc {
    pid: i32,
    name: String,
    ppid: i32,
    exe: String,
    exe_deleted: bool,
}

fn read_proc(pid: i32) -> Option<Proc> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let name = status_field(&status, "Name:").unwrap_or_default();
    let ppid = status_field(&status, "PPid:").and_then(|v| v.parse().ok()).unwrap_or(0);
    // readlink of exe may come back as "<path> (deleted)" or a "/memfd:..." - both are the
    // classic signs of a process running from a file that no longer exists on disk.
    let raw = fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.display().to_string()).unwrap_or_default();
    let exe_deleted = raw.ends_with(" (deleted)") || raw.starts_with("/memfd:") || raw.contains("(deleted)");
    let exe = raw.trim_end_matches(" (deleted)").to_string();
    Some(Proc { pid, name, ppid, exe, exe_deleted })
}

/// Resolves the controlling tty from fd 0/1/2, if any points at a terminal.
fn tty_of(pid: i32) -> Option<String> {
    for fd in ["0", "1", "2"] {
        if let Ok(t) = fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
            let s = t.display().to_string();
            if s.starts_with("/dev/pts/") || s.starts_with("/dev/tty") {
                return Some(s.trim_start_matches("/dev/").to_string());
            }
        }
    }
    None
}

/// Most recent `Accepted ... for <user> from <ip>` line in the auth log, if any.
fn last_login_for(user: &str) -> Option<String> {
    if user.is_empty() {
        return None;
    }
    let needle = format!(" for {user} from ");
    for path in AUTH_LOGS {
        let Ok(content) = fs::read_to_string(path) else { continue };
        if let Some(line) = content
            .lines()
            .filter(|l| l.contains("Accepted ") && l.contains(&needle))
            .last()
        {
            return Some(line.trim().to_string());
        }
    }
    None
}

pub struct AttributeAgentCommand {}

impl AttributeAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for AttributeAgentCommand {
    fn name(&self) -> &'static str {
        "attribute"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let Some(pid) = args.first().and_then(|a| a.parse::<i32>().ok()) else {
            ctx.stdout.write_all(b"usage: attribute <pid>\n").await?;
            return Ok(());
        };
        if !Path::new(&format!("/proc/{pid}")).exists() {
            ctx.stdout.write_all(format!("no such process: pid {pid}\n").as_bytes()).await?;
            return Ok(());
        }

        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
            .unwrap_or_default();
        let cwd = fs::read_link(format!("/proc/{pid}/cwd")).map(|p| p.display().to_string()).unwrap_or_default();
        let loginuid = fs::read_to_string(format!("/proc/{pid}/loginuid")).map(|s| s.trim().to_string()).unwrap_or_default();

        // Uid line is "real effective saved fs"; a real != effective is a privilege change.
        let uids: Vec<String> = status_field(&status, "Uid:").unwrap_or_default().split_whitespace().map(str::to_owned).collect();
        let real_uid = uids.first().cloned().unwrap_or_default();
        let eff_uid = uids.get(1).cloned().unwrap_or_default();

        let me = read_proc(pid);
        let exe = me.as_ref().map(|p| p.exe.clone()).unwrap_or_default();
        let exe_deleted = me.as_ref().map(|p| p.exe_deleted).unwrap_or(false);

        let mut r = String::new();
        let _ = writeln!(r, "=== Attribution: pid {pid} ===");
        let _ = writeln!(r, "Process:");
        let _ = writeln!(r, "  comm:    {}", status_field(&status, "Name:").unwrap_or_default());
        let _ = writeln!(r, "  exe:     {}{}", if exe.is_empty() { "<unknown>" } else { &exe }, if exe_deleted { "  [DELETED/memfd - anomalous]" } else { "" });
        if !exe.is_empty() && !exe_deleted {
            match fs::read(&exe) {
                Ok(bytes) => { let _ = writeln!(r, "  exehash: blake3:{}", Hash::of(&bytes)); }
                Err(e) => { let _ = writeln!(r, "  exehash: <unreadable: {e}>"); }
            }
        }
        let _ = writeln!(r, "  cmdline: {cmdline}");
        let _ = writeln!(r, "  cwd:     {cwd}");
        let _ = writeln!(r, "  state:   {}", status_field(&status, "State:").unwrap_or_default());

        let _ = writeln!(r, "Identity:");
        let _ = writeln!(r, "  uid:      {}", show_uid(&real_uid));
        if eff_uid != real_uid && !eff_uid.is_empty() {
            let _ = writeln!(r, "  euid:     {}   <- privilege change from uid", show_uid(&eff_uid));
        }
        let login_name = uid_name(&loginuid).unwrap_or_default();
        let _ = writeln!(
            r,
            "  login(auid): {}",
            if loginuid.is_empty() || loginuid == "4294967295" {
                "unset (no login session - service or kernel origin)".to_string()
            } else {
                show_uid(&loginuid)
            }
        );
        let _ = writeln!(r, "  tty:      {}", tty_of(pid).unwrap_or_else(|| "none".to_string()));

        // Parent chain: the entry vector. Walk PPid up to init.
        let _ = writeln!(r, "Parent chain (entry vector, child -> ancestor):");
        let mut cur = pid;
        for _ in 0..MAX_ANCESTRY {
            match read_proc(cur) {
                Some(p) => {
                    let _ = writeln!(r, "  {:>7} {:<16} {}", p.pid, p.name, if p.exe.is_empty() { "<unknown>" } else { &p.exe });
                    if p.ppid == 0 || p.pid == 1 {
                        break;
                    }
                    cur = p.ppid;
                }
                None => break,
            }
        }

        // Login correlation: tie the loginuid to an SSH login (source IP + method).
        let _ = writeln!(r, "Login correlation:");
        match last_login_for(&login_name) {
            Some(line) => { let _ = writeln!(r, "  {line}"); }
            None if login_name.is_empty() => { let _ = writeln!(r, "  (no login user to correlate)"); }
            None => { let _ = writeln!(r, "  (no matching 'Accepted' line in the auth log for {login_name})"); }
        }

        ctx.stdout.write_all(r.as_bytes()).await?;
        Ok(())
    }
}

pub struct AttributeClientCommand {}

impl AttributeClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for AttributeClientCommand {
    fn name(&self) -> &'static str {
        "attribute"
    }
    fn short_description(&self) -> &'static str {
        "Full who/what/how dossier for a pid"
    }
    fn help(&self) -> &'static str {
        "Usage: attribute <pid>\n\n\
        Builds a dossier for a process: identity (real/effective uid, loginuid), exe +\n\
        hash (flagging a deleted/memfd exe), the parent chain (the entry vector), tty, and\n\
        the matching SSH login (source IP + method) from the auth log."
    }
    fn complete_arg(&self, _preceding: &[&str], _word: &str, _ctx: &rustyline::Context<'_>, _fc: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "attribute", args).await
    }
}
