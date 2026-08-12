//! Built-in persistence mechanisms. New mechanisms register in
//! `Registry::with_builtins`.

pub mod cron;
pub mod systemd;
