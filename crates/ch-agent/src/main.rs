// File: crates/ch-agent/src/main.rs
//! Crystal Hammer agent: on-host, root, autonomous from T0 (SPECS 13.2).

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use std::sync::Arc;

struct AgentExecutor {
    registry: ch_commands::model::AgentCommandRegistry,
    store: Arc<ch_store::Store>,
}

#[async_trait::async_trait]
impl ch_transport::CommandExecutor for AgentExecutor {
    async fn execute(
        &self,
        command: String,
        args: Vec<String>,
        stdout: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        stderr: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    ) -> std::result::Result<(), String> {
        if let Some(cmd) = self.registry.find(&command) {
            let (events_tx, _events_rx) = tokio::sync::mpsc::unbounded_channel();
            let ctx = ch_commands::model::Context {
                stdin: Box::new(tokio::io::empty()),
                stdout,
                stderr,
                events: events_tx,
                store: self.store.clone(),
            };
            cmd.execute(args, ctx)
                .await
                .map_err(|e| e.to_string())
        } else {
            Err(format!("Unknown agent command: '{}'", command))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .init();

    // Check for root early
    if !is_root() {
        tracing::error!("ERROR: Agent must run as root (SPECS 13.12)");
        std::process::exit(1);
    }

    tracing::info!("Crystal Hammer agent starting");

    // Load embedded public key
    let key = ch_common::keys::team_pubkey()
        .context("No embedded public key found in agent binary")?;

    // Registries are the extension seams; construct them up front.
    tracing::info!("Loading firewall backend...");
//    let _firewall = ch_firewall::Registry::with_builtins();
    
    tracing::info!("Loading persistence mechanisms...");
    let _persistence = ch_persistence::Registry::with_builtins();
    
    tracing::info!("Loading monitor checks...");
    let _checks = ch_monitor::Registry::with_builtins();

    let config = ch_common::config::AgentConfig::default();
    if !config.state_dir.exists() {
        std::fs::create_dir_all(&config.state_dir)
            .context("Failed to create state directory")?;
    }
    let store = Arc::new(ch_store::Store::open(&config.state_dir)?);

    let registry = ch_commands::model::AgentCommandRegistry::with_builtins();
    let executor = Arc::new(AgentExecutor {
        registry,
        store,
    });

    tracing::info!("crystal-hammer agent M1: SPA-gated listener ready");
    
    // Start the SPA-gated listener on configured port
    let port = 2222;
    ch_transport::serve(port, &key, executor).await?;
    
    Ok(())
}

fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::Uid;
        let uid = Uid::current();
        if uid.is_root() {
            return true;
        }
        return false;
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}