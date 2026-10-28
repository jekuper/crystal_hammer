//! Agent configuration (TOML on disk, SPECS 13.12).
//!
//! `state_dir` is a configurable path (default below), created if it does not exist.


pub const CH_PORT: u16 = 2222;


use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Where redb state and the evidence log live. Created if missing.
    pub state_dir: PathBuf,
    /// Port the SPA-gated listener binds once knocked open.
    pub listen_port: u16,
    /// Dead-man's-switch auto-revert window, seconds (SPECS section 1).
    pub deadman_secs: u64,
    /// File paths/globs to watch for modification (SPECS 4a). Merged with built-in
    /// defaults at load time.
    pub watchlist: Vec<String>,
    /// Allow taking over the audit daemon slot if no daemon is running
    pub allow_audit_daemon: bool,
}

/// Files worth tracking on a typical box before any operator customization. More paths
/// can be added at runtime via the `watch add` command.
pub fn default_watchlist() -> Vec<String> {
    [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/nginx/nginx.conf",
        "/etc/nginx/conf.d",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            state_dir: PathBuf::from("/var/lib/crystal_hammer"),
            listen_port: 0,
            deadman_secs: 60,
            watchlist: default_watchlist(),
            allow_audit_daemon: false,
        }
    }
}
