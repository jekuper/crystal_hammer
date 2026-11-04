//! Manage the suspicious-binary list: binaries whose execution raises a critical
//! `suspicious_exec` alert. `add`/`remove` persist (when a store is present) so runtime
//! edits survive an agent restart; matching is by basename (e.g. `curl`, not `/usr/bin/curl`).

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

pub struct SuspectAgentCommand {}
impl SuspectAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for SuspectAgentCommand {
    fn name(&self) -> &'static str {
        "suspect"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let sub = args.first().map(String::as_str).unwrap_or("list");
        match sub {
            "add" | "remove" => {
                let on = sub == "add";
                let mut report = String::new();
                if args.len() < 2 {
                    report.push_str(&format!("usage: suspect {sub} <binary> [binary...]\n"));
                } else {
                    for name in &args[1..] {
                        let changed = if on {
                            ctx.audit.add_suspicious(name.clone())
                        } else {
                            ctx.audit.remove_suspicious(name)
                        };
                        if let Some(store) = &ctx.store {
                            let r = if on { store.add_suspect(name) } else { store.remove_suspect(name) };
                            if let Err(e) = r {
                                tracing::warn!("Failed to persist suspect {sub} {name}: {e}");
                            }
                        }
                        report.push_str(&match (on, changed) {
                            (true, true) => format!("now flagging {name} on execution\n"),
                            (true, false) => format!("already flagged: {name}\n"),
                            (false, true) => format!("no longer flagging {name}\n"),
                            (false, false) => format!("was not flagged: {name}\n"),
                        });
                    }
                }
                ctx.stdout.write_all(report.as_bytes()).await?;
                Ok(())
            }
            "list" => {
                let bins = ctx.audit.list_suspicious();
                let mut report = format!("{} suspicious binary name(s):\n", bins.len());
                for b in bins {
                    report.push_str(&format!("  {b}\n"));
                }
                ctx.stdout.write_all(report.as_bytes()).await?;
                Ok(())
            }
            other => {
                ctx.stdout
                    .write_all(format!("unknown suspect subcommand: {other}\n").as_bytes())
                    .await?;
                Ok(())
            }
        }
    }
}

pub struct SuspectClientCommand {}
impl SuspectClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for SuspectClientCommand {
    fn name(&self) -> &'static str {
        "suspect"
    }

    fn short_description(&self) -> &'static str {
        "Manage binaries that raise a critical alert on execution"
    }

    fn help(&self) -> &'static str {
        "Usage: suspect <subcommand>\n\n\
        Subcommands:\n\
          list                 Show the flagged binary names\n\
          add <binary>...      Flag a binary so its execution raises a critical alert (persisted)\n\
          remove <binary>...   Stop flagging a binary (persisted)\n\n\
        Matching is by basename, e.g. 'suspect add curl', not the full path. The default\n\
        list covers download/recon/persistence/evasion tools; generic execs stay at info."
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, _ctx: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
        if preceding_args.is_empty() {
            return ["list", "add", "remove"]
                .iter()
                .filter(|s| s.starts_with(word))
                .map(|s| Pair { display: s.to_string(), replacement: format!("{s} ") })
                .collect();
        }
        Vec::new()
    }

    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        let fwd: Vec<String> = if args.is_empty() { vec!["list".to_string()] } else { args.to_vec() };
        run_remote(ctx, "suspect", &fwd).await
    }
}
