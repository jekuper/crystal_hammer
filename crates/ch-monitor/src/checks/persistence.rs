//! Persistence-sweep checks (SPECS section 3 `persistence`).

use crate::{Cadence, Check, Finding};

/// authorized_keys created/modified anywhere (SPECS section 4).
pub struct AuthorizedKeys {
    _priv: (),
}

impl AuthorizedKeys {
    pub fn new() -> Self {
        AuthorizedKeys { _priv: () }
    }
}

impl Check for AuthorizedKeys {
    fn id(&self) -> ch_common::ImplId {
        "persistence.authorized_keys"
    }

    fn cadence(&self) -> Cadence {
        Cadence::Poll
    }

    fn run(&self, _host: &ch_sense::HostSnapshot) -> Vec<Finding> {
        // M4/M5: enumerate authorized_keys across homes/root/custom paths, diff hashes.
        Vec::new()
    }
}
