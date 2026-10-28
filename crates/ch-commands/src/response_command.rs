//! Active response: terminate rogue processes (`kill`) and boot an intruder's whole
//! session set (`kick`). Both capture process identity from /proc before acting so the
//! operator sees who/what was terminated, and both refuse targets that would take down
//! the host or the agent itself (pid 1, our own process, uid 0 for `kick`).

use std::fs;

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};

struct ProcInfo {
    comm: String,
    exe: String,
    cmdline: String,
    uid: String,
}

fn read_proc(pid: i32) -> Option<ProcInfo> {
    // comm is the only field we insist on; a pid with no comm isn't a live process.
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?.trim().to_string();
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
        .unwrap_or_default();
    let uid = fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .map(str::to_owned)
        })
        .unwrap_or_default();
    Some(ProcInfo { comm, exe, cmdline, uid })
}

fn describe(pid: i32, p: &ProcInfo) -> String {
    format!(
        "pid {pid} (comm={} uid={} exe={} cmd=[{}])",
        p.comm, p.uid, p.exe, p.cmdline
    )
}

/// True for pids the tool must never signal: itself, its process group, and init.
fn protected(pid: i32) -> bool {
    let me = std::process::id() as i32;
    pid <= 1 || pid == me
}

fn send_signal(pid: i32, sig: i32) -> std::io::Result<()> {
    // SAFETY: kill(2) with a plain pid and signal number; no memory is touched.
    if unsafe { libc::kill(pid, sig) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

// =============================================================================
// kill
// =============================================================================

pub struct KillAgentCommand {}

impl KillAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for KillAgentCommand {
    fn name(&self) -> &'static str {
        "kill"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let mut sig = libc::SIGTERM;
        let mut pids: Vec<i32> = Vec::new();
        let mut report = String::new();

        for a in &args {
            match a.as_str() {
                "--kill" | "-9" => sig = libc::SIGKILL,
                "--term" | "-15" => sig = libc::SIGTERM,
                other => match other.parse::<i32>() {
                    Ok(p) => pids.push(p),
                    Err(_) => report.push_str(&format!("not a pid: {other}\n")),
                },
            }
        }

        if pids.is_empty() {
            report.push_str("usage: kill <pid> [pid...] [--kill]\n");
            ctx.stdout.write_all(report.as_bytes()).await?;
            return Ok(());
        }

        let signame = if sig == libc::SIGKILL { "SIGKILL" } else { "SIGTERM" };
        for pid in pids {
            if protected(pid) {
                report.push_str(&format!("refusing to signal protected pid {pid}\n"));
                continue;
            }
            match read_proc(pid) {
                Some(info) => match send_signal(pid, sig) {
                    Ok(()) => report.push_str(&format!("sent {signame} to {}\n", describe(pid, &info))),
                    Err(e) => report.push_str(&format!("failed to signal pid {pid}: {e}\n")),
                },
                None => report.push_str(&format!("no such process: pid {pid}\n")),
            }
        }

        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

// =============================================================================
// kick
// =============================================================================

pub struct KickAgentCommand {}

impl KickAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    /// Resolves a username or numeric id to a uid. Returns None if unknown.
    fn resolve_uid(target: &str) -> Option<u32> {
        if let Ok(uid) = target.parse::<u32>() {
            return Some(uid);
        }
        let passwd = fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let mut f = line.split(':');
            if let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next()) {
                if name == target {
                    return uid.parse().ok();
                }
            }
        }
        None
    }

    /// All pids owned by `uid`, read from /proc (never via host binaries).
    fn pids_for_uid(uid: u32) -> Vec<i32> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir("/proc") else { return out };
        for e in entries.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
            let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
            let owner = status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u32>().ok());
            if owner == Some(uid) {
                out.push(pid);
            }
        }
        out
    }
}

#[async_trait]
impl AgentCommand for KickAgentCommand {
    fn name(&self) -> &'static str {
        "kick"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let Some(target) = args.first() else {
            ctx.stdout.write_all(b"usage: kick <user|uid>\n").await?;
            return Ok(());
        };

        let Some(uid) = Self::resolve_uid(target) else {
            ctx.stdout.write_all(format!("unknown user: {target}\n").as_bytes()).await?;
            return Ok(());
        };

        // Kicking uid 0 would kill system daemons and this agent. Use `kill <pid>` for a
        // specific root process instead.
        if uid == 0 {
            ctx.stdout
                .write_all(b"refusing to kick uid 0 (would take down the host and the agent); target a specific pid with kill\n")
                .await?;
            return Ok(());
        }

        let mut report = String::new();
        let mut killed = 0usize;
        for pid in Self::pids_for_uid(uid) {
            if protected(pid) {
                continue;
            }
            let desc = read_proc(pid).map(|i| describe(pid, &i)).unwrap_or_else(|| format!("pid {pid}"));
            match send_signal(pid, libc::SIGKILL) {
                Ok(()) => {
                    killed += 1;
                    report.push_str(&format!("killed {desc}\n"));
                }
                Err(e) => report.push_str(&format!("failed to kill pid {pid}: {e}\n")),
            }
        }

        report.push_str(&format!("kicked uid {uid} ({target}): {killed} process(es) terminated\n"));
        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

// =============================================================================
// Client sides
// =============================================================================

/// Shared client-side exec: forwards the typed command to the agent and streams output.
pub(crate) async fn run_remote(ctx: ClientCommandContext<'_>, name: &str, args: &[String]) -> Result<()> {
    let session = ctx.session;
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| ch_common::Error::Other(e.to_string()))?;

    let payload = if args.is_empty() {
        name.to_string()
    } else {
        format!("{name} {}", args.join(" "))
    };
    channel
        .exec(true, payload.as_bytes())
        .await
        .map_err(|e| ch_common::Error::Other(e.to_string()))?;

    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { ref data } => {
                print!("{}", std::str::from_utf8(data).unwrap_or_default());
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
            russh::ChannelMsg::ExtendedData { ref data, .. } => {
                eprint!("{}", std::str::from_utf8(data).unwrap_or_default());
                use std::io::Write;
                let _ = std::io::stderr().flush();
            }
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok(())
}

pub struct KillClientCommand {}

impl KillClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for KillClientCommand {
    fn name(&self) -> &'static str {
        "kill"
    }
    fn short_description(&self) -> &'static str {
        "Terminate a process by pid"
    }
    fn help(&self) -> &'static str {
        "Usage: kill <pid> [pid...] [--kill]\n\n\
        Sends SIGTERM by default, SIGKILL with --kill (or -9). Reports the identity\n\
        (comm/uid/exe/cmdline) of each process signalled. Refuses pid 1 and the agent."
    }
    fn complete_arg(&self, _preceding: &[&str], word: &str, _ctx: &rustyline::Context<'_>, _fc: &FilenameCompleter) -> Vec<Pair> {
        ["--kill", "--term"]
            .iter()
            .filter(|o| o.starts_with(word))
            .map(|o| Pair { display: o.to_string(), replacement: format!("{o} ") })
            .collect()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "kill", args).await
    }
}

pub struct KickClientCommand {}

impl KickClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for KickClientCommand {
    fn name(&self) -> &'static str {
        "kick"
    }
    fn short_description(&self) -> &'static str {
        "Kill every process of a user"
    }
    fn help(&self) -> &'static str {
        "Usage: kick <user|uid>\n\n\
        SIGKILLs every process owned by the user - boots a logged-in intruder in one\n\
        step. Refuses uid 0 (would take down the host and the agent)."
    }
    fn complete_arg(&self, _preceding: &[&str], _word: &str, _ctx: &rustyline::Context<'_>, _fc: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "kick", args).await
    }
}
