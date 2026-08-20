use std::fs;
use anyhow::Error;
use async_trait::async_trait;
use ch_common::Result;
use ch_common::config::CH_PORT;
use ch_firewall::loader::Firewall;
use ch_firewall::loader::Mode;
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, ClientCommand, ClientContext, Context};

pub struct UnlockAgentCommand {}

impl UnlockAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}


#[async_trait]
impl AgentCommand for UnlockAgentCommand {
    fn name(&self) -> &'static str { "unlock" }

    async fn execute(&self, args: Vec<String>, mut ctx: Context) -> Result<()> {
        Firewall::global()
            .set_mode(Mode::Regular)
            .await
            .map_err(|e| ch_common::Error::AgentCommand(format!("{e:#}")))?;
        
        Firewall::global().remove_all_allow_ports()
            .await
            .map_err(|e| ch_common::Error::AgentCommand(format!("{e:#}")))?;

        ctx.stdout.write_all("Lockdown lifted. The storm is over?\n".as_bytes()).await?;
        Ok(())
    }
}



pub struct UnlockClientCommand {}

impl UnlockClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for UnlockClientCommand {
    fn name(&self) -> &'static str { "unlock" }
    fn short_description(&self) -> &'static str { "lifts any firewall blocks" }
    fn help(&self) -> &'static str { 
    "lol" 
    }

    async fn execute(&self, args: &[String], ctx: ClientContext<'_>) -> Result<()> {
        let session = ctx.session;
        let mut channel = session.channel_open_session()
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let server_command = UnlockAgentCommand::new();

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
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    if exit_status != 0 {
                        tracing::warn!("Remote command exited with status {}", exit_status);
                    }
                    // don't break here — Eof/Close will follow
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        Ok(())
    }
}