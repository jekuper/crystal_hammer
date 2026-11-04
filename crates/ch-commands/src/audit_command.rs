//! `audit` - report the file-monitoring backend and how to enable the kernel audit
//! backend; `audit install` installs+starts the audit userspace (the agent is root, so
//! no sudo). The kernel audit subsystem is always present; only the `auditd` userspace is
//! missing on a stock box, which is why the agent falls back to fanotify.

use std::path::Path;

use async_trait::async_trait;
use ch_common::Result;
use ch_monitor::audit::ActiveBackend;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

fn have(bin: &str) -> bool {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"].iter().any(|d| Path::new(&format!("{d}/{bin}")).exists())
}

/// (binary, install-args) for the host's package manager, if recognized.
fn pkg_install() -> Option<(&'static str, Vec<&'static str>)> {
    if have("apt-get") {
        Some(("apt-get", vec!["install", "-y", "auditd"]))
    } else if have("dnf") {
        Some(("dnf", vec!["install", "-y", "audit"]))
    } else if have("zypper") {
        Some(("zypper", vec!["--non-interactive", "install", "audit"]))
    } else if have("apk") {
        Some(("apk", vec!["add", "audit"]))
    } else {
        None
    }
}

pub struct AuditAgentCommand {}
impl AuditAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    async fn install(&self, ctx: &mut AgentCommandContext) -> Result<()> {
        let Some((bin, args)) = pkg_install() else {
            ctx.stdout.write_all(b"no supported package manager found (apt/dnf/zypper/apk)\n").await?;
            return Ok(());
        };
        let mut report = format!("installing audit userspace via {bin} ...\n");
        let out = tokio::process::Command::new(bin)
            .args(&args)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .output()
            .await;
        match out {
            Ok(o) => {
                report.push_str(&String::from_utf8_lossy(&o.stdout));
                let err = String::from_utf8_lossy(&o.stderr);
                if !err.trim().is_empty() {
                    report.push_str(&err);
                }
                report.push_str(&format!("install exit: {}\n", o.status.code().unwrap_or(-1)));
                // Best-effort enable+start so the agent's 30s re-check finds a live auditd.
                let _ = tokio::process::Command::new("systemctl").args(["enable", "--now", "auditd"]).output().await;
                report.push_str("started auditd; the agent re-checks backends every ~30s and will switch to audit automatically.\n");
            }
            Err(e) => report.push_str(&format!("failed to run {bin}: {e}\n")),
        }
        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl AgentCommand for AuditAgentCommand {
    fn name(&self) -> &'static str {
        "audit"
    }
    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        if args.first().map(String::as_str) == Some("install") {
            return self.install(&mut ctx).await;
        }

        let backend = ctx.audit.backend().await;
        let auditd_present = have("auditctl") || have("auditd");
        let mut r = format!("file-monitoring backend: {}\n", backend.label());
        r.push_str(&format!("auditd userspace installed: {}\n", if auditd_present { "yes" } else { "no" }));

        match backend {
            ActiveBackend::Multicast | ActiveBackend::LogTail | ActiveBackend::Daemon => {
                r.push_str("audit backend is active (execve/module-syscall monitoring available).\n");
            }
            _ => {
                r.push_str(
                    "\nOn the fanotify fallback: file tracking works, but execve/module-syscall\n\
                     monitoring (which needs kernel audit) is dormant. The kernel audit subsystem\n\
                     is built in - no reboot needed - only the auditd userspace is missing.\n\
                     Enable it with:\n\
                     \x20 audit install           (installs + starts auditd via the host package manager)\n\
                     \x20 or manually: apt install auditd && systemctl enable --now auditd\n\
                     The agent re-checks backends every ~30s and switches to audit on its own.\n",
                );
            }
        }
        ctx.stdout.write_all(r.as_bytes()).await?;
        Ok(())
    }
}

pub struct AuditClientCommand {}
impl AuditClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for AuditClientCommand {
    fn name(&self) -> &'static str {
        "audit"
    }
    fn short_description(&self) -> &'static str {
        "Show/enable the kernel audit backend"
    }
    fn help(&self) -> &'static str {
        "Usage: audit [install]\n\n\
        'audit' shows the current file-monitoring backend (audit vs fanotify fallback) and\n\
        how to enable audit. 'audit install' installs + starts the auditd userspace (the\n\
        agent runs as root); the agent then switches to the audit backend within ~30s."
    }
    fn complete_arg(&self, preceding: &[&str], word: &str, _c: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
        if preceding.is_empty() && "install".starts_with(word) {
            return vec![Pair { display: "install".to_string(), replacement: "install".to_string() }];
        }
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "audit", args).await
    }
}
