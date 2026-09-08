// File: crates/ch-agent/src/main.rs

//! Crystal Hammer agent: on-host, root, autonomous from T0 (SPECS 13.2).

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use ch_common::config::CH_PORT;
use ch_firewall::loader::Firewall;
use ch_pid_lock::pid_lock::PidGuard;
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
        stdin: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        stdout: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        stderr: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    ) -> std::result::Result<(), String> {
        if let Some(cmd) = self.registry.find(&command) {
            let (events_tx, _events_rx) = tokio::sync::mpsc::unbounded_channel();
            let ctx = ch_commands::model::Context {
                stdin,
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
    // Bind the guard to a variable to keep it in scope until main() exits
    let _guard = match PidGuard::acquire() {
        Ok(guard) => {
            // We need to initialize tracing before this if we want to see this log,
            // but for now we just return the guard from the match arm.
            guard 
        },
        Err(ch_common::Error::PidLockFailed(pid)) => {
            // We can't use tracing::error here yet because tracing isn't initialized,
            // so using eprintln is safer for early failures.
            eprintln!("Agent is already running with PID: {}", pid);
            std::process::exit(101);
        },
        Err(other_error) => {
            eprintln!("Failed to acquire lock: {:?}", other_error);
            std::process::exit(102);
        }
    };


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
    let persistence = ch_persistence::Registry::with_builtins();

    match std::env::current_exe() {
        Ok(exe_path) => {
            if let Some(installed) = persistence.install_first_successful(&exe_path) {
                tracing::info!("Installed active persistence mechanism: {}", installed);
            } else {
                tracing::warn!("No persistence mechanisms could be installed");
            }
        }
        Err(e) => {
            tracing::error!("Failed to get current executable path. Persistence won't be installed: {}", e);
        }
    }
    
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