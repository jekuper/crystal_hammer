use async_trait::async_trait;
use ch_common::Result;
use ch_common::config::CH_PORT;
use ch_firewall::loader::Firewall;
use ch_firewall::loader::Mode;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::FilenameCompleter;
use rustyline::completion::Pair;
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, ClientCommand, ClientContext, Context};

/// Parses port specifications similar to nmap.
/// Supports formats like: "80", "80,443", "8000-8100", or combinations "22,80-90,443".
fn parse_ports(args: &[String]) -> std::result::Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for arg in args {
        for part in arg.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.contains('-') {
                let mut range_parts = part.split('-');
                let start_str = range_parts.next().ok_or_else(|| "Invalid range format".to_string())?.trim();
                let end_str = range_parts.next().ok_or_else(|| "Invalid range format".to_string())?.trim();
                if range_parts.next().is_some() {
                    return Err(format!("Invalid range format: {}", part));
                }
                let start = start_str.parse::<u16>().map_err(|_| format!("Invalid start port: {}", start_str))?;
                let end = end_str.parse::<u16>().map_err(|_| format!("Invalid end port: {}", end_str))?;
                if start > end {
                    return Err(format!("Invalid range (start {} is greater than end {}): {}", start, end, part));
                }
                ports.extend(start..=end);
            } else {
                let port = part.parse::<u16>().map_err(|_| format!("Invalid port format: {}", part))?;
                ports.push(port);
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

pub struct LockdownAgentCommand {}

impl LockdownAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for LockdownAgentCommand {
    fn name(&self) -> &'static str { "lockdown" }

    async fn execute(&self, args: Vec<String>, mut ctx: Context) -> Result<()> {
        let additional_ports = parse_ports(&args)
            .map_err(|e| ch_common::Error::AgentCommand(format!("Port parsing error: {e}")))?;

        Firewall::global()
            .set_mode(Mode::Lockdown)
            .await
            .map_err(|e| ch_common::Error::AgentCommand(format!("{e:#}")))?;
        
        // Ensure administration port remains open
        Firewall::global().allow_port(CH_PORT)
            .await
            .map_err(|e| ch_common::Error::AgentCommand(format!("{e:#}")))?;

        // Apply additional parsed ports
        for port in additional_ports {
            if port != CH_PORT {
                Firewall::global().allow_port(port)
                    .await
                    .map_err(|e| ch_common::Error::AgentCommand(format!("{e:#}")))?;
            }
        }

        ctx.stdout.write_all("Lockdown enforced. Allowed ports updated.\n".as_bytes()).await?;
        Ok(())
    }
}

pub struct LockdownClientCommand {}

impl LockdownClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for LockdownClientCommand {
    fn name(&self) -> &'static str { "lockdown" }
    fn short_description(&self) -> &'static str { "configures firewalls to deny everything except specified ports" }
    fn help(&self) -> &'static str { 
        "Usage: lockdown [ports]\n\n\
        Locks down the agent firewall, allowing only the management port and any additional specified ports.\n\
        Supports nmap-style formatting (e.g., 22,80-90,443)." 
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, _ctx: &rustyline::Context<'_>, _filename_completer: &FilenameCompleter) -> Vec<Pair> {
        if !preceding_args.is_empty() {
            return Vec::new();
        }

        if word.is_empty() {
            return vec![
                Pair { display: "<port>       e.g. 8080".to_string(),             replacement: String::new() },
                Pair { display: "<range>      e.g. 8000-9000".to_string(),        replacement: String::new() },
                Pair { display: "<list>       e.g. 22,80,443".to_string(),        replacement: String::new() },
                Pair { display: "<mixed>      e.g. 22,8000-9000,443".to_string(), replacement: String::new() },
            ];
        }

        let last_token = word.split(',').last().unwrap_or("");

        if last_token.contains('-') {
            let mut parts = last_token.split('-');
            let start_str = parts.next().unwrap_or("");
            let end_str = parts.next().unwrap_or("");

            match (start_str.parse::<u16>(), end_str) {
                (Err(_), _) => vec![
                    Pair { display: format!("{}  -- invalid start port", word), replacement: word.to_string() }
                ],
                (Ok(start), "") => vec![
                    Pair { display: format!("{}  -- e.g. {}-{}", word, start, start.saturating_add(100)), replacement: word.to_string() }
                ],
                (Ok(start), end) => match end.parse::<u16>() {
                    Ok(e) if e < start => vec![
                        Pair { display: format!("{}  -- end must be >= start ({})", word, start), replacement: word.to_string() }
                    ],
                    Ok(_) => vec![
                        Pair { display: format!("{}  -- valid range", word), replacement: format!("{} ", word) }
                    ],
                    Err(_) => vec![
                        Pair { display: format!("{}  -- invalid end port", word), replacement: word.to_string() }
                    ],
                }
            }
        } else {
            match last_token.parse::<u16>() {
                Ok(_) => vec![
                    Pair { display: format!("{}   -- confirm", word),          replacement: format!("{} ", word) },
                    Pair { display: format!("{},  -- add another port/range", word), replacement: format!("{},", word) },
                ],
                Err(_) if !last_token.is_empty() => vec![
                    Pair { display: format!("{}  -- invalid port number", word), replacement: word.to_string() }
                ],
                _ => Vec::new(),
            }
        }
    }

    async fn execute(&self, _executor: &dyn ClientCommandExecutor, args: &[String], ctx: ClientContext<'_>) -> Result<()> {
        let session = ctx.session;
        let mut channel = session.channel_open_session()
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let server_command = LockdownAgentCommand::new();

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
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        Ok(())
    }
}