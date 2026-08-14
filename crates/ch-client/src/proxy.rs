//! Reachability through jump hosts: ProxyJump, generic ProxyCommand, and Teleport.
//!
//! For M1, this module provides the hop definitions and basic state management.
//! Full proxy chain handling will be filled in across milestones.

pub struct Hop {
    pub kind: HopKind,
}

pub enum HopKind {
    Jump { host: String, port: u16 },
    Command { argv: Vec<String> },
    Teleport { proxy: String },
}

impl Hop {
    pub fn host(&self) -> &str {
        match &self.kind {
            HopKind::Jump { host, .. } => host,
            HopKind::Command { argv } => &argv[0],
            HopKind::Teleport { proxy } => proxy,
        }
    }

    pub fn port(&self) -> u16 {
        match &self.kind {
            HopKind::Jump { port, .. } => *port,
            HopKind::Command { .. } => 22,
            HopKind::Teleport { .. } => 22,
        }
    }
}

pub struct ProxyState {
    target: Target,
    keypair: TeamKeyPair,
}

impl ProxyState {
    pub fn new(target: &Target, keypair: TeamKeyPair) -> Self {
        Self {
            target: target.clone(),
            keypair,
        }
    }
}

pub use proxy_hop;