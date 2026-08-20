//! Operator-side CLI client for Crystal Hammer.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ch_transport::{connect, Hop, Target};
use std::sync::Arc;

struct LocalExecutor {
    registry: ch_commands::model::ClientCommandRegistry,
}

#[async_trait::async_trait]
impl ch_transport::ClientCommandExecutor for LocalExecutor {
    async fn execute(
        &self,
        command: &str,
        args: &[String],
        session: &mut russh::client::Handle<ch_transport::client::ClientHandler>,
    ) -> std::result::Result<(), String> {
        if command == "help" {
            // If an argument is provided, look up the specific command's help text
            if let Some(target_command) = args.first() {
                if let Some(cmd) = self.registry.find(target_command) {
                    println!("{}", cmd.help());
                    return Ok(());
                } else {
                    return Err(format!("Unknown command: '{}'", target_command));
                }
            }

            // Default behavior: list all registered commands
            println!("Registered commands:");
            let mut help_summary = "".to_string();
            for command in self.registry.iter() {
                help_summary.push_str(command.name());
                help_summary.push_str(" - ");
                help_summary.push_str(command.short_description());
                help_summary.push_str("\n");
            }
            println!("{}", help_summary);
            return Ok(());
        }

        if let Some(cmd) = self.registry.find(command) {
            let ctx = ch_commands::model::ClientContext { session };
            cmd.execute(args, ctx)
                .await
                .map_err(|e| e.to_string())
        } else {
            Err(format!("Unknown command: '{}'", command))
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "crystal-hammer", version = "0.0.1", about = "Crystal Hammer Operator Client")]
struct Cli {
    /// Target host
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Target port
    #[arg(short, long, default_value_t = 2222)]
    port: u16,

    /// Proxy Jump host (optional, e.g. "jump.example.com:22")
    #[arg(short, long)]
    jump: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start an interactive shell
    Shell,
    /// Run a single command on the agent
    Run {
        /// The command to execute
        command: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();

    tracing::info!("Starting Crystal Hammer client");

    let target = Target {
        host: cli.host,
        port: cli.port,
    };

    let mut hops = Vec::new();
    if let Some(jump_host) = cli.jump {
        let parts: Vec<&str> = jump_host.split(':').collect();
        let host = parts[0].to_string();
        let port = if parts.len() > 1 {
            parts[1].parse::<u16>().context("Invalid jump port")?
        } else {
            22
        };
        hops.push(Hop::Jump { host, port });
    }

    let registry = ch_commands::model::ClientCommandRegistry::with_builtins();
    let executor = Arc::new(LocalExecutor { registry });

    connect(&target, &hops, executor).await.context("Failed to connect to agent")?;

    Ok(())
}