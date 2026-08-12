//! Crystal Hammer agent: on-host, root, autonomous from T0 (SPECS 13.2).
//!
//! Boot order (filled in across milestones):
//!   1. install persistence mechanisms (idempotent)
//!   2. open state store, take T0 baseline + known-bad sweep
//!   3. start the monitoring loop (runs whether or not a client is connected)
//!   4. serve the SPA-gated listener

#![forbid(unsafe_code)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    if !is_root() {
        tracing::warn!("not running as root: degraded read-only mode (SPECS 13.12)");
    }

    // Registries are the extension seams; construct them up front.
    let _firewall = ch_firewall::Registry::with_builtins();
    let _persistence = ch_persistence::Registry::with_builtins();
    let _checks = ch_monitor::Registry::with_builtins();

    tracing::info!("crystal-hammer agent scaffold: no milestones wired yet");
    Ok(())
}

fn is_root() -> bool {
    // M0/M3: real euid check on Linux.
    false
}
