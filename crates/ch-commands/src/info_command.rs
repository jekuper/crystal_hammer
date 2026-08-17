use std::fs;
use async_trait::async_trait;
use ch_common::Result;
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, ClientCommand, ClientContext, Context};

pub struct InfoAgentCommand {}

impl InfoAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    // --- Active Implementations ---

    fn get_hostname(&self) -> String {
        fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }

    fn get_distro(&self) -> String {
        if let Ok(content) = fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return line
                        .trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string();
                }
            }
        }
        "Unknown Linux Distro".to_string()
    }

    fn get_kernel(&self) -> String {
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }

    // --- Stub/Trunk Functions ---

    fn get_firewall_status(&self) -> String {
        "[Warning] Firewall backend and state detection is not implemented yet".to_string()
    }

    fn get_all_listeners(&self) -> String {
        "[Warning] Port listeners detection is not implemented yet".to_string()
    }

    fn get_logged_in_users(&self) -> String {
        "[Warning] Logged-in users detection is not implemented yet".to_string()
    }

    fn get_all_users(&self) -> String {
        "[Warning] All users list query is not implemented yet".to_string()
    }

    fn get_recent_auth_failures(&self) -> String {
        "[Warning] Recent authentication failure checking is not implemented yet".to_string()
    }

    fn get_persistence_health(&self) -> String {
        "[Warning] Persistence mechanism self-health checks are not implemented yet".to_string()
    }
}


#[async_trait]
impl AgentCommand for InfoAgentCommand {
    fn name(&self) -> &'static str { "info" }

    async fn execute(&self, args: Vec<String>, mut ctx: Context) -> Result<()> {
        let show_users = args.contains(&"--users".to_string());
        
        let mut report = String::new();

        report.push_str("--- Host Information ---\n");
        report.push_str(&format!("Hostname: {}\n", self.get_hostname()));
        report.push_str(&format!("Distro:   {}\n", self.get_distro()));
        report.push_str(&format!("Kernel:   {}\n\n", self.get_kernel()));

        report.push_str("--- System State & Diagnostics ---\n");
        report.push_str(&format!("Firewall State:     {}\n", self.get_firewall_status()));
        report.push_str(&format!("Active Listeners:   {}\n", self.get_all_listeners()));
        report.push_str(&format!("Logged-in Users:    {}\n", self.get_logged_in_users()));
        report.push_str(&format!("All Users:          {}\n", self.get_all_users()));
        report.push_str(&format!("Auth Failures:      {}\n", self.get_recent_auth_failures()));
        report.push_str(&format!("Persistence Health: {}\n", self.get_persistence_health()));

        if show_users {
            report.push_str("\n--- Detailed Users requested (Stub) ---\n");
        }

        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}



pub struct InfoClientCommand {}

impl InfoClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for InfoClientCommand {
    fn name(&self) -> &'static str { "info" }
    fn short_description(&self) -> &'static str { "Fetch host info" }
    fn help(&self) -> &'static str { 
    "info command allows you to fetch information about the host
    newline test" 
    }

    async fn execute(&self, args: &[String], ctx: ClientContext<'_>) -> Result<()> {
        let session = ctx.session;
        let channel = session.channel_open_session()
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        // Allocate a thread-safe message sink for our channel
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ch_transport::client::register_sink(channel.id(), tx);

        let server_command = InfoAgentCommand::new();

        let exec_payload = if args.is_empty() {
            server_command.name().to_string()
        } else {
            format!("{} {}", server_command.name(), args.join(" "))
        };

        channel.exec(true, exec_payload.as_bytes()).await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        // Read and print incoming stream events synchronously in the command execution thread
        while let Some(event) = rx.recv().await {
            match event {
                ch_transport::client::ChannelEvent::Data(data) => {
                    let s = std::str::from_utf8(&data)
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    print!("{}", s);
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }
                ch_transport::client::ChannelEvent::ExtendedData(data, _) => {
                    let s = std::str::from_utf8(&data)
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    eprint!("{}", s);
                    use std::io::Write;
                    let _ = std::io::stderr().flush();
                }
                ch_transport::client::ChannelEvent::Eof | ch_transport::client::ChannelEvent::Close => {
                    break;
                }
            }
        }

        // Clean up our registered sink
        ch_transport::client::unregister_sink(channel.id());

        Ok(())
    }
}