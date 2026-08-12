//! systemd unit mechanism.

use crate::{Health, Mechanism};
use ch_common::Result;
use std::path::Path;

pub struct Systemd {
    _priv: (),
}

impl Systemd {
    pub fn new() -> Self {
        Systemd { _priv: () }
    }
}

impl Mechanism for Systemd {
    fn id(&self) -> ch_common::ImplId {
        "systemd"
    }

    fn available(&self) -> bool {
        // M8: detect a running systemd.
        false
    }

    fn install(&self, _self_path: &Path) -> Result<()> {
        unimplemented!("M8: write + enable a unit, idempotently")
    }

    fn check(&self) -> Result<Health> {
        Ok(Health::Missing)
    }

    fn remove(&self) -> Result<()> {
        unimplemented!("M8: disable + delete the unit")
    }
}
