//! Crystal Hammer operator client (SPECS 13.2). Connects like SSH; on connect it does a
//! catch-up sync then live-tails events for the session (SPECS 13.9).

#![forbid(unsafe_code)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    tracing::info!("crystal-hammer client scaffold: no milestones wired yet");
    Ok(())
}
