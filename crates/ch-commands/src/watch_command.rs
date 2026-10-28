//! File-tracker control and the live alert stream.
//!
//! `watch stream` is the long-lived subcommand the client subscribes to on connect; it
//! writes one JSON alert per line for the life of the channel. `list`/`add`/`test` are
//! ordinary one-shot operator commands.

use async_trait::async_trait;
use ch_common::proto::{Actor, Alert, AlertSeverity};
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast::error::RecvError;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};

pub struct WatchAgentCommand {}

impl WatchAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    async fn stream(&self, mut ctx: AgentCommandContext) -> Result<()> {
        let mut rx = ctx.audit.subscribe();
        loop {
            let alert = match rx.recv().await {
                Ok(alert) => alert,
                Err(RecvError::Lagged(n)) => Alert {
                    kind: "stream_lagged".to_string(),
                    severity: AlertSeverity::Warn,
                    path: String::new(),
                    detail: format!("{n} alert(s) dropped: this client fell behind"),
                    actor: Actor::default(),
                    unix_time: 0,
                },
                Err(RecvError::Closed) => break,
            };

            let mut line = serde_json::to_string(&alert).unwrap_or_default();
            line.push('\n');
            // A write error means the operator disconnected; end the stream quietly.
            if ctx.stdout.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if ctx.stdout.flush().await.is_err() {
                break;
            }
        }
        Ok(())
    }
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
                        if ctx.audit.add_watch(path.clone()) {
                            report.push_str(&format!("tracking {path} (enforced within a few seconds)\n"));
                        } else {
                            report.push_str(&format!("already tracked: {path}\n"));
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
          add <path>...     Start tracking one or more files/directories at runtime\n\
          test [message]    Fire a synthetic alert to verify the live channel\n\n\
        Alerts from tracked files stream to this console automatically while connected."
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, _ctx: &rustyline::Context<'_>, filename_completer: &FilenameCompleter) -> Vec<Pair> {
        // First token: the subcommand.
        if preceding_args.is_empty() {
            return ["list", "add", "test"]
                .iter()
                .filter(|s| s.starts_with(word))
                .map(|s| Pair { display: s.to_string(), replacement: format!("{s} ") })
                .collect();
        }
        // `add` takes file paths; defer to the filename completer.
        if preceding_args[0] == "add" {
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
