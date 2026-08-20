// File: crates/ch-agent/src/main.rs

//! Crystal Hammer agent: on-host, root, autonomous from T0 (SPECS 13.2).

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use ch_common::config::CH_PORT;
use ch_firewall::loader::Firewall;
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

    let firewall = Firewall::init_global()?;
    let handle = firewall.clone().spawn_supervised();
    
    let port = CH_PORT;

    // Run the listener until a shutdown signal is intercepted
    tokio::select! {
        res = ch_transport::serve(port, &key, executor) => {
            if let Err(e) = res {
                tracing::error!("Server error: {:?}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl-C, exiting gracefully");
        }
        _ = sigterm_signal() => {
            tracing::info!("Received SIGTERM, exiting gracefully");
        }
    }

    // Trigger graceful firewall cleanup and wait for detachment to complete
    tracing::info!("Shutting down firewall and detaching interfaces");
    firewall.shutdown();
    let _ = handle.await;
    
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

#[cfg(unix)]
async fn sigterm_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    if let Ok(mut stream) = signal(SignalKind::terminate()) {
        stream.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn sigterm_signal() {
    std::future::pending::<()>().await;
}