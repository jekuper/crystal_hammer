//! Integrity baseline (SPECS M5). `baseline` snapshots a content hash of every watched
//! file at a known-good moment (T0); `diff` re-hashes and reports what changed since -
//! the complement to the live file tracker, catching drift and anything added out of band.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

/// Cap how many paths each change class lists, so a big diff stays readable.
const LIST_CAP: usize = 100;

fn section(report: &mut String, title: &str, items: &[&String]) {
    let _ = writeln!(report, "{} ({}):", title, items.len());
    for p in items.iter().take(LIST_CAP) {
        let _ = writeln!(report, "  {p}");
    }
    if items.len() > LIST_CAP {
        let _ = writeln!(report, "  ... and {} more", items.len() - LIST_CAP);
    }
}

pub struct BaselineAgentCommand {}
impl BaselineAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for BaselineAgentCommand {
    fn name(&self) -> &'static str {
        "baseline"
    }
    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let Some(store) = ctx.store.clone() else {
            ctx.stdout.write_all(b"state store unavailable; cannot take a baseline\n").await?;
            return Ok(());
        };
        // `baseline flush` discards the stored baseline; `baseline` (re)takes it.
        if args.first().map(String::as_str) == Some("flush") {
            let msg = match store.clear_baseline() {
                Ok(()) => "baseline flushed\n".to_string(),
                Err(e) => format!("failed to flush baseline: {e}\n"),
            };
            ctx.stdout.write_all(msg.as_bytes()).await?;
            return Ok(());
        }
        let paths = ctx.audit.list();
        let msg = match store.take_baseline(&paths) {
            Ok(n) => format!("baseline captured: {n} file(s) hashed across {} watched path(s)\n", paths.len()),
            Err(e) => format!("failed to store baseline: {e}\n"),
        };
        ctx.stdout.write_all(msg.as_bytes()).await?;
        Ok(())
    }
}

pub struct DiffAgentCommand {}
impl DiffAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for DiffAgentCommand {
    fn name(&self) -> &'static str {
        "diff"
    }
    async fn execute(&self, _args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let Some(store) = ctx.store.clone() else {
            ctx.stdout.write_all(b"state store unavailable; cannot diff\n").await?;
            return Ok(());
        };
        let base: BTreeMap<String, String> = match store.baseline() {
            Ok(b) if !b.is_empty() => b.into_iter().collect(),
            Ok(_) => {
                ctx.stdout.write_all(b"no baseline taken yet; run 'baseline' first\n").await?;
                return Ok(());
            }
            Err(e) => {
                ctx.stdout.write_all(format!("failed to read baseline: {e}\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let cur = ch_store::hash_paths(&ctx.audit.list());
        let mut modified = Vec::new();
        let mut added = Vec::new();
        let mut removed = Vec::new();
        for (path, hash) in &cur {
            match base.get(path) {
                Some(b) if b == hash => {}
                Some(_) => modified.push(path),
                None => added.push(path),
            }
        }
        for path in base.keys() {
            if !cur.contains_key(path) {
                removed.push(path);
            }
        }
        modified.sort();
        added.sort();
        removed.sort();

        let mut report = String::new();
        let _ = writeln!(
            report,
            "diff against baseline: {} modified, {} added, {} removed ({} files now, {} at baseline)",
            modified.len(), added.len(), removed.len(), cur.len(), base.len()
        );
        section(&mut report, "MODIFIED", &modified);
        section(&mut report, "ADDED", &added);
        section(&mut report, "REMOVED", &removed);
        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

pub struct BaselineClientCommand {}
impl BaselineClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for BaselineClientCommand {
    fn name(&self) -> &'static str {
        "baseline"
    }
    fn short_description(&self) -> &'static str {
        "Snapshot known-good file hashes"
    }
    fn help(&self) -> &'static str {
        "Usage: baseline [flush]\n\n\
        Hashes every watched file and stores it as the known-good baseline (also taken\n\
        automatically ~10s after the agent starts). 'baseline flush' discards it. Use\n\
        'diff' to see what changed since."
    }
    fn complete_arg(&self, _p: &[&str], _w: &str, _c: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "baseline", args).await
    }
}

pub struct DiffClientCommand {}
impl DiffClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for DiffClientCommand {
    fn name(&self) -> &'static str {
        "diff"
    }
    fn short_description(&self) -> &'static str {
        "Show file changes since the baseline"
    }
    fn help(&self) -> &'static str {
        "Usage: diff\n\n\
        Re-hashes every watched file and reports what is modified, added or removed versus\n\
        the stored baseline."
    }
    fn complete_arg(&self, _p: &[&str], _w: &str, _c: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "diff", args).await
    }
}
