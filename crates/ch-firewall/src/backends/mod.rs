//! Built-in firewall backends. New backends live here and get registered in
//! `Registry::with_builtins`.

pub mod iptables;
pub mod nftables;
