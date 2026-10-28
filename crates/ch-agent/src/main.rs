// File: crates/ch-agent/src/main.rs

//! Crystal Hammer agent: on-host, root, autonomous from T0 (SPECS 13.2).

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use ch_common::config::CH_PORT;
use ch_firewall::loader::Firewall;
use ch_pid_lock::pid_lock::PidGuard;
use std::sync::Arc;

struct AgentExecutor {
    command_registry: Arc<ch_commands::model::AgentCommandRegistry>,
    persistence_registry: Arc<ch_persistence::Registry>,
    store: Option<Arc<ch_store::Store>>,
    audit: ch_monitor::audit::AuditHandle,
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
        if let Some(cmd) = self.command_registry.find(&command) {
            let (events_tx, _events_rx) = tokio::sync::mpsc::unbounded_channel();

            let command_registry_copy = self.command_registry.clone();
            let persistence_registry_copy = self.persistence_registry.clone();

            let ctx = ch_commands::model::AgentCommandContext {
                stdin,
                stdout,
                stderr,
                events: events_tx,
                store: self.store.clone(),
                command_registry: command_registry_copy,
                persistence_registry: persistence_registry_copy,
                audit: self.audit.clone(),
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
    let persistence_registry = Arc::new(ch_persistence::Registry::with_builtins());

    // CH_DISABLE_PERSISTENCE keeps the agent from installing/launching a self-preservation
    // copy of itself. Used by the integration tests so each test runs a single agent
    // instance (a second copy would race this one for the state DB lock).
    if std::env::var_os("CH_DISABLE_PERSISTENCE").is_some() {
        tracing::warn!("Persistence install disabled via CH_DISABLE_PERSISTENCE.");
    } else {
        match std::env::current_exe() {
            Ok(exe_path) => {
                if let Some(installed) = persistence_registry.install_first_successful(&exe_path) {
                    tracing::info!("Installed active persistence mechanism: {}", installed);
                } else {
                    tracing::warn!("No persistence mechanisms could be installed");
                }
            }
            Err(e) => {
                tracing::error!("Failed to get current executable path. Persistence won't be installed: {}", e);
            }
        }
    }
    
    tracing::info!("Loading monitor checks...");
    let _checks = ch_monitor::Registry::with_builtins();

    let config = ch_common::config::AgentConfig::default();
    if !config.state_dir.exists() {
        std::fs::create_dir_all(&config.state_dir)
            .context("Failed to create state directory")?;
    }
    // The store is best-effort: a locked or unusable DB must never stop the agent from
    // coming up, since emergency access is the whole point. Degrade to no persistence.
    let store = match ch_store::Store::open(&config.state_dir) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            tracing::warn!("State store unavailable (evidence log/persistence disabled): {}", e);
            None
        }
    };

    if !std::path::Path::new("/etc/pam.d/sshd").exists() ||
       !tokio::fs::read_to_string("/etc/pam.d/sshd").await.unwrap_or_default().contains("pam_loginuid.so") {
        tracing::warn!("pam_loginuid.so not found in sshd PAM config! AUIDs (login users) will be unset (4294967295).");
    }

    tracing::info!("Initializing audit kernel system for file tracking...");
    // Defaults + every user's SSH key dir, then the operator's persisted runtime edits.
    let mut base = config.watchlist.clone();
    base.extend(ssh_key_dirs());
    let watchlist = match &store {
        Some(s) => s.effective_watchlist(base.clone()).unwrap_or(base),
        None => base,
    };
    tracing::info!("Tracking {} path(s).", watchlist.len());
    let audit_engine = ch_monitor::audit::AuditEngine::new(
        watchlist,
        config.allow_audit_daemon
    );
    let audit = audit_engine.handle();
    audit_engine.start().await;

    // Evidence writer: persist every alert to the hash-chained log, whether or not an
    // operator is connected. Also keeps a live subscriber so the engine always records.
    if let Some(store) = &store {
        spawn_evidence_writer(store.clone(), audit.subscribe());
    }


    let command_registry = Arc::new(ch_commands::model::AgentCommandRegistry::with_builtins());

    let executor = Arc::new(AgentExecutor {
        command_registry,
        persistence_registry,
        store,
        audit,
    });

    let firewall_handle = match Firewall::init_global() {
        Ok(fw) => {
            tracing::info!("Firewall initialized successfully");
            Some(fw.clone().spawn_supervised())
        }
        Err(e) => {
            tracing::warn!("Failed to load firewall (running in degraded mode): {}", e);
            None
        }
    };
    
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

    if let Some(fw) = Firewall::try_global() {
        // Trigger graceful firewall cleanup and wait for detachment to complete
        tracing::info!("Shutting down firewall and detaching interfaces");
        fw.shutdown();
    }
    if let Some(handle) = firewall_handle {
        let _ = handle.await;
    }
    
    Ok(())
}

/// Drains the alert broadcast into the evidence log. Each append is a quick redb write;
/// it runs on the blocking pool so it never stalls an async worker.
fn spawn_evidence_writer(
    store: Arc<ch_store::Store>,
    mut alerts: tokio::sync::broadcast::Receiver<ch_monitor::audit::SeqAlert>,
) {
    use tokio::sync::broadcast::error::RecvError;
    tokio::spawn(async move {
        loop {
            match alerts.recv().await {
                Ok((_seq, alert)) => {
                    let store = store.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        match serde_json::to_value(&alert) {
                            Ok(body) => {
                                if let Err(e) = store.append("alert", &body) {
                                    tracing::warn!("Failed to persist alert: {}", e);
                                }
                            }
                            Err(e) => tracing::warn!("Failed to encode alert: {}", e),
                        }
                    })
                    .await;
                }
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("Evidence writer lagged; {} alert(s) not persisted.", n);
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}

/// Per-user `.ssh` directories for every account in /etc/passwd, so authorized_keys and
/// private keys are tracked box-wide. Watching the dir covers key files added later; the
/// integrity rescan walks it. Users created mid-incident can be added with `watch add`.
fn ssh_key_dirs() -> Vec<String> {
    let mut dirs = vec!["/root/.ssh".to_string()];
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 6 {
                continue;
            }
            let home = fields[5];
            // Skip accounts parked on non-home paths (nobody, daemons).
            if !home.starts_with('/') || home == "/" || home == "/nonexistent" || home == "/dev/null"
            {
                continue;
            }
            dirs.push(format!("{}/.ssh", home.trim_end_matches('/')));
        }
    }
    dirs
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