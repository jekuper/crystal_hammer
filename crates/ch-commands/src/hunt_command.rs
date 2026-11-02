//! `hunt` (SPECS M4/section 5): a one-shot, read-only sweep for compromise that shows no
//! open port - packet/raw-socket sniffers, deleted/memfd executables, and every account's
//! authorized_keys. Parses /proc and config only; never writes, kills, or alters anything.

use std::fmt::Write as _;

use async_trait::async_trait;
use ch_common::Result;
use ch_monitor::Severity;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 2,
        Severity::Warn => 1,
        Severity::Info => 0,
    }
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

pub struct HuntAgentCommand {}
impl HuntAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for HuntAgentCommand {
    fn name(&self) -> &'static str {
        "hunt"
    }
    async fn execute(&self, _args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let mut findings = ch_monitor::hunt();
        findings.sort_by(|a, b| sev_rank(b.severity).cmp(&sev_rank(a.severity)));

        let mut report = format!("=== hunt: {} finding(s) ===\n", findings.len());
        if findings.is_empty() {
            report.push_str("no findings\n");
        }
        for f in &findings {
            let _ = writeln!(report, "[{}] {}: {}", sev_label(f.severity), f.check, f.summary);
            let _ = writeln!(report, "    {}", f.detail);
        }
        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

pub struct HuntClientCommand {}
impl HuntClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for HuntClientCommand {
    fn name(&self) -> &'static str {
        "hunt"
    }
    fn short_description(&self) -> &'static str {
        "Read-only sweep for stealthy compromise"
    }
    fn help(&self) -> &'static str {
        "Usage: hunt\n\n\
        One-shot, read-only sweep: packet/raw-socket holders (sniffers), processes running\n\
        a deleted/memfd executable, and every account's authorized_keys. Alters nothing."
    }
    fn complete_arg(&self, _p: &[&str], _w: &str, _c: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "hunt", args).await
    }
}
