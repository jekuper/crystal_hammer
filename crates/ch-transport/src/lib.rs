//! Session transport over russh (SPECS 13.4): SPA-gated listener, PTY shell, channels,
//! mutual auth with a pinned host key, and proxy-chain reachability on the client side.

#![forbid(unsafe_code)]

pub mod client;
pub mod proxy;
pub mod server;
