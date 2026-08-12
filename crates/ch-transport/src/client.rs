//! Operator-side connector: send the knock, verify the pinned host key, open a session.

use ch_common::Result;

/// Target address, possibly reached through a proxy chain.
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Connect to an agent: knock, then russh handshake with host-key pinning.
pub async fn connect(_target: &Target, _via: &[proxy_hop::Hop]) -> Result<()> {
    // M1: resolve reachability (direct or proxy chain), knock, handshake, run session.
    unimplemented!("M1: knock + russh connect")
}

/// Re-export so callers build hop chains without reaching into `proxy`.
pub mod proxy_hop {
    pub use crate::proxy::Hop;
}
