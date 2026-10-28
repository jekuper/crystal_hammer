//! File-tracker control and the live alert stream.
//!
//! `watch stream` is the long-lived subcommand the client subscribes to on connect. It
//! first replays the engine's recent-alert ring (catch-up), then forwards live alerts, so
//! a newly connected operator sees what they missed and then everything live. `list`,
//! `add`, `remove` and `test` are ordinary one-shot operator commands; `add`/`remove`
//! persist (when a store is present) so runtime edits survive an agent restart.

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
pub struct WatchAgentCommand {}

impl WatchAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    async fn stream(&self, mut ctx: AgentCommandContext) -> Result<()> {
        use tokio::sync::broadcast::error::RecvError;

        // Subscribe first so any alert published between the catch-up snapshot and the live
        // loop is captured; the per-alert sequence number then dedups the overlap exactly.
        let mut live = ctx.audit.subscribe();
        let mut last_seq = 0u64;
        for (seq, alert) in ctx.audit.recent() {
            last_seq = seq;
            if !write_alert(&mut ctx.stdout, &alert).await {
                return Ok(());
            }
        }

        loop {
            match live.recv().await {
                Ok((seq, alert)) => {
                    if seq <= last_seq {
                        continue; // already delivered in the catch-up snapshot
                    }
                    last_seq = seq;
                    if !write_alert(&mut ctx.stdout, &alert).await {
                        return Ok(());
                    }
                }
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return Ok(()),
            }
        }
    }
}

/// Writes one alert as an NDJSON line and flushes. Returns false once the operator left.
async fn write_alert(w: &mut (impl AsyncWriteExt + Unpin), alert: &ch_common::proto::Alert) -> bool {
    let line = serde_json::to_string(alert).unwrap_or_default();
    w.write_all(line.as_bytes()).await.is_ok()
        && w.write_all(b"\n").await.is_ok()
        && w.flush().await.is_ok()
}

#[async_trait]
impl AgentCommand for WatchAgentCommand {
    fn name(&self) -> &'static str {
        "watch"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let sub = args.first().map(String::as_str).unwrap_or("list");
        match sub {
            "stream" => self.stream(ctx).await,
            "add" => {
                let mut report = String::new();
                if args.len() < 2 {
                    report.push_str("usage: watch add <path> [path...]\n");
                } else {
                    for path in &args[1..] {
                        let added = ctx.audit.add_watch(path.clone());
                        if let Some(store) = &ctx.store {
                            if let Err(e) = store.add_watch(path) {
                                tracing::warn!("Failed to persist watch add {path}: {e}");
                            }
                        }
                        if added {
                            report.push_str(&format!("tracking {path} (enforced within a few seconds)\n"));
                        } else {
                            report.push_str(&format!("already tracked: {path}\n"));
                        }
                    }
                }
                ctx.stdout.write_all(report.as_bytes()).await?;
                Ok(())
            }
            "remove" => {
                let mut report = String::new();
                if args.len() < 2 {
                    report.push_str("usage: watch remove <path> [path...]\n");
                } else {
                    for path in &args[1..] {
                        let removed = ctx.audit.remove_watch(path);
                        if let Some(store) = &ctx.store {
                            if let Err(e) = store.remove_watch(path) {
                                tracing::warn!("Failed to persist watch remove {path}: {e}");
                            }
                        }
                        if removed {
                            report.push_str(&format!("stopped tracking {path}\n"));
                        } else {
                            report.push_str(&format!("was not tracked: {path}\n"));
                        }
                    }
                }
                ctx.stdout.write_all(report.as_bytes()).await?;
                Ok(())
            }
            "test" => {
                let detail = args[1..].join(" ");
                ctx.audit.emit_test(&detail);
                ctx.stdout
                    .write_all(b"test alert sent to connected operators\n")
                    .await?;
                Ok(())
            }
            "list" => {
                let paths = ctx.audit.list();
                let mut report = format!("tracking {} path(s):\n", paths.len());
                for p in paths {
                    report.push_str(&format!("  {p}\n"));
                }
                ctx.stdout.write_all(report.as_bytes()).await?;
                Ok(())
            }
            other => {
                ctx.stdout
                    .write_all(format!("unknown watch subcommand: {other}\n").as_bytes())
                    .await?;
                Ok(())
            }
        }
    }
}

pub struct WatchClientCommand {}

impl WatchClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for WatchClientCommand {
    fn name(&self) -> &'static str {
        "watch"
    }

    fn short_description(&self) -> &'static str {
        "Manage tracked files and alerts"
    }

    fn help(&self) -> &'static str {
        "Usage: watch <subcommand>\n\n\
        Subcommands:\n\
          list              Show the files currently tracked\n\
          add <path>...     Start tracking files/directories at runtime (persisted)\n\
          remove <path>...  Stop tracking files/directories (persisted)\n\
          test [message]    Fire a synthetic alert to verify the live channel\n\n\
        Alerts from tracked files stream to this console automatically while connected,\n\
        including recent ones you missed before connecting."
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, _ctx: &rustyline::Context<'_>, filename_completer: &FilenameCompleter) -> Vec<Pair> {
        // First token: the subcommand.
        if preceding_args.is_empty() {
            return ["list", "add", "remove", "test"]
                .iter()
                .filter(|s| s.starts_with(word))
                .map(|s| Pair { display: s.to_string(), replacement: format!("{s} ") })
                .collect();
        }
        // `add`/`remove` take file paths; defer to the filename completer.
        if matches!(preceding_args[0], "add" | "remove") {
            if let Ok((_, pairs)) = filename_completer.complete_path(word, word.len()) {
                return pairs;
            }
        }
        Vec::new()
    }

    async fn execute(&self, _executor: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        let session = ctx.session;
        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let payload = if args.is_empty() {
            "watch list".to_string()
        } else {
            format!("watch {}", args.join(" "))
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
}
