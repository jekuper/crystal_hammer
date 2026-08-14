//! Crystal Hammer agent: on-host, root, autonomous from T0 (SPECS 13.2).
//!
//! Boot order:
//!   1. install persistence mechanisms (idempotent)
//!   2. open state store, take T0 baseline + known-bad sweep
//!   3. start the monitoring loop (runs whether or not a client is connected)
//!   4. serve the SPA-gated listener

#![forbid(unsafe_code)]

use anyhow::{Context, Result};

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
    let _firewall = ch_firewall::Registry::with_builtins();
    
    tracing::info!("Loading persistence mechanisms...");
    let _persistence = ch_persistence::Registry::with_builtins();
    
    tracing::info!("Loading monitor checks...");
    let _checks = ch_monitor::Registry::with_builtins();

    tracing::info!("crystal-hammer agent M1: SPA-gated listener ready");
    
    // Start the SPA-gated listener on configured port
    let port = 2222;
    ch_transport::serve(port, &key).await?;
    
    Ok(())
}

fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        use nix::unistd::Uid;
        let uid = Uid::current();
        if uid.is_root() {
            println!("Running as root");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}