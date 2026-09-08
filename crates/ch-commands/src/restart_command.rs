// File: crates/ch-commands/src/restart_command.rs

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;
use std::time::Duration;

use crate::model::{AgentCommand, ClientCommand, ClientCommandContext, AgentCommandContext};

pub struct RestartAgentCommand {}

impl RestartAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    fn has_healthy_persistence(&self, ctx: &AgentCommandContext) -> bool {
        let registry = &ctx.persistence_registry;
        for m in registry.all() {
            if m.available() {
                if let Ok(ch_persistence::Health::Active) = m.check() {
                    return true;
                }
            }
        }
        false
    }
}

#[async_trait]
impl AgentCommand for RestartAgentCommand {
    fn name(&self) -> &'static str {
        "restart"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let force = args.iter().any(|arg| arg == "--force" || arg == "-f");

        if !self.has_healthy_persistence(&ctx) && !force {
            let warn_msg = "Warning: No healthy/active persistence mechanisms detected!\n\
                            Restarting now might lock you out of the machine if the agent does not auto-start.\n\
                            If you are sure, run: restart --force\n";
            ctx.stdout.write_all(warn_msg.as_bytes()).await?;
            ctx.stdout.flush().await?;
            return Ok(());
        }

        ctx.stdout.write_all(b"Restarting agent daemon now...\n").await?;
        ctx.stdout.flush().await?;

        // Brief delay allows the TCP buffers to flush the message before process exit
        tokio::time::sleep(Duration::from_millis(500)).await;

        std::process::exit(0);
    }
}

pub struct RestartClientCommand {}

impl RestartClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for RestartClientCommand {
    fn name(&self) -> &'static str {
        "restart"
    }

    fn short_description(&self) -> &'static str {
        "Restarts the agent process safely"
    }

    fn help(&self) -> &'static str {
        "Usage: restart [--force | -f]\n\n\
         Kills the active agent process, triggering its watchdog or init supervisor to respawn it.\n\
         Fails with a safety warning if no active persistence/watchdog mechanism is currently healthy,\n\
         unless `--force` or `-f` is passed."
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, _ctx: &rustyline::Context<'_>, _filename_completer: &FilenameCompleter) -> Vec<Pair> {
        if !preceding_args.is_empty() {
            return Vec::new();
        }
        let options = ["--force", "-f"];
        options
            .iter()
            .filter(|opt| opt.starts_with(word))
            .map(|opt| Pair {
                display: opt.to_string(),
                replacement: format!("{} ", opt),
            })
            .collect()
    }

    async fn execute(&self, _executor: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        let session = ctx.session;
        let mut channel = session.channel_open_session()
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let server_command = RestartAgentCommand::new();
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