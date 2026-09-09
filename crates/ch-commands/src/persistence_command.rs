// File: crates/ch-commands/src/persistence_command.rs

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use std::env;
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, ClientCommand, ClientCommandContext, AgentCommandContext};

// =========================================================================
// AGENT-SIDE COMMAND
// =========================================================================

pub struct PersistenceAgentCommand {}

impl PersistenceAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for PersistenceAgentCommand {
    fn name(&self) -> &'static str {
        "persistence"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        if args.is_empty() {
            ctx.stdout.write_all(b"Usage: persistence <info|install|uninstall> [target]\n").await?;
            return Ok(());
        }

        let action = args[0].as_str();
        let target = args.get(1).map(|s| s.as_str()).unwrap_or("all");

        let mut output = String::new();

        match action {
            "info" => {
                for m in ctx.persistence_registry.all() {
                    if target == "all" || target == m.id() {
                        output.push_str(&format!("Mechanism: {}\n", m.id()));
                        for line in m.info().lines() {
                            output.push_str(&format!("    {}\n", line));
                        }
                        output.push_str("\n");
                    }
                }
                if output.is_empty() {
                    output = format!("No mechanism found matching '{}'\n", target);
                }
            }
            "install" => {
                let self_path = match env::current_exe() {
                    Ok(path) => path,
                    Err(e) => {
                        ctx.stdout.write_all(format!("Error: Failed to resolve current executable path: {}\n", e).as_bytes()).await?;
                        return Ok(());
                    }
                };

                let mut performed_any = false;
                for m in ctx.persistence_registry.all() {
                    if target == "all" || target == m.id() {
                        if !m.available() {
                            output.push_str(&format!("Mechanism '{}' is not available on this host.\n", m.id()));
                            continue;
                        }
                        output.push_str(&format!("Installing mechanism '{}'...\n", m.id()));
                        match m.install(&self_path) {
                            Ok(()) => {
                                output.push_str(&format!("Successfully installed '{}'.\n", m.id()));
                                performed_any = true;
                            }
                            Err(e) => {
                                output.push_str(&format!("Failed to install '{}': {}\n", m.id(), e));
                            }
                        }
                    }
                }
                if !performed_any && target != "all" && ctx.persistence_registry.all().all(|m| m.id() != target) {
                    output = format!("No mechanism found matching '{}'\n", target);
                }
            }
            "uninstall" | "remove" => {
                let mut performed_any = false;
                for m in ctx.persistence_registry.all() {
                    if target == "all" || target == m.id() {
                        output.push_str(&format!("Uninstalling mechanism '{}'...\n", m.id()));
                        match m.remove() {
                            Ok(()) => {
                                output.push_str(&format!("Successfully removed '{}'.\n", m.id()));
                                performed_any = true;
                            }
                            Err(e) => {
                                output.push_str(&format!("Failed to remove '{}': {}\n", m.id(), e));
                            }
                        }
                    }
                }
                if !performed_any && target != "all" && ctx.persistence_registry.all().all(|m| m.id() != target) {
                    output = format!("No mechanism found matching '{}'\n", target);
                }
            }
            _ => {
                output = format!("Error: Unknown action '{}'. Supported actions: [info|install|uninstall]\n", action);
            }
        }

        ctx.stdout.write_all(output.as_bytes()).await?;
        Ok(())
    }
}

// =========================================================================
// CLIENT-SIDE COMMAND
// =========================================================================

pub struct PersistenceClientCommand {}

impl PersistenceClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for PersistenceClientCommand {
    fn name(&self) -> &'static str {
        "persistence"
    }

    fn short_description(&self) -> &'static str {
        "Manage self-preservation mechanisms on the agent"
    }

    fn help(&self) -> &'static str {
        "Usage: persistence <info|install|uninstall> [target]\n\n\
         Queries, registers, or removes independent persistence mechanisms on the host.\n\
         If no target is specified, the action is run across all mechanisms.\n\n\
         Available targets:\n\
           systemd       Supervised systemd unit\n\
           cron          Fallback cron reboot/watchdog job\n\
           all           All of the above"
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, _ctx: &rustyline::Context<'_>, _filename_completer: &FilenameCompleter) -> Vec<Pair> {
        let actions = ["info", "install", "uninstall"];
        let targets = ["systemd", "cron", "all"];

        if preceding_args.is_empty() {
            return actions
                .iter()
                .filter(|act| act.starts_with(word))
                .map(|act| Pair {
                    display: act.to_string(),
                    replacement: format!("{} ", act),
                })
                .collect();
        }

        if preceding_args.len() == 1 {
            let action = preceding_args[0];
            if actions.contains(&action) {
                return targets
                    .iter()
                    .filter(|tgt| tgt.starts_with(word))
                    .map(|tgt| Pair {
                        display: tgt.to_string(),
                        replacement: format!("{} ", tgt),
                    })
                    .collect();
            }
        }

        Vec::new()
    }

    async fn execute(&self, _executor: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        let session = ctx.session;
        let mut channel = session.channel_open_session()
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let server_command = PersistenceAgentCommand::new();
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
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        Ok(())
    }
}