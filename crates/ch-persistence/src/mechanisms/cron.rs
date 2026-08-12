//! cron fallback mechanism.

use crate::{Health, Mechanism};
use ch_common::Result;
use std::path::Path;

pub struct Cron {
    _priv: (),
}

impl Cron {
    pub fn new() -> Self {
        Cron { _priv: () }
    }
}

impl Mechanism for Cron {
    fn id(&self) -> ch_common::ImplId {
        "cron"
    }

    fn available(&self) -> bool {
        // M8: detect a usable crond / crontab spool.
        false
    }

    fn install(&self, _self_path: &Path) -> Result<()> {
        unimplemented!("M8: install a respawn entry, idempotently")
    }

    fn check(&self) -> Result<Health> {
        Ok(Health::Missing)
    }

    fn remove(&self) -> Result<()> {
        unimplemented!("M8: remove the cron entry")
    }
}
