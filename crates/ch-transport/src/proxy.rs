//! Reachability through jump hosts (SPECS 13.4): ProxyJump, generic ProxyCommand, and
//! Teleport. Over TCP proxies the SPA knock rides as the opening bytes of the stream.

/// One hop in a reachability chain.
#[derive(Debug, Clone)]
pub enum Hop {
    /// SSH jump host (ProxyJump semantics).
    Jump { host: String, port: u16 },
    /// Arbitrary command whose stdio is the tunnel (ProxyCommand).
    Command { argv: Vec<String> },
    /// Teleport proxy (`tsh proxy ssh`).
    Teleport { proxy: String },
}
