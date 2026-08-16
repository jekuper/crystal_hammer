//! Wire protocol messages exchanged between agent and client over the russh session.
//!
//! Kept transport-agnostic: these are the payloads carried inside SSH channels, not the
//! SSH framing itself.

use serde::{Deserialize, Serialize};

/// Monotonic cursor into the agent evidence log. The client stores its last-seen value
/// and sends it on connect to drive catch-up sync (SPECS 13.9).
pub type Cursor = u64;

/// Client -> agent requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Pull all evidence records after `since`.
    CatchUp { since: Cursor },
    /// Start streaming live events for the life of the connection.
    Subscribe,
    /// Run a one-shot command (non-interactive mode).
    Run { command: String },
    /// Push a replacement binary; agent swaps and restarts.
    Update { hash: crate::Hash, len: u64 },
}

/// Agent -> client messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// One evidence/alert record.
    Record { cursor: Cursor, kind: String, body: serde_json::Value },
    /// End of a catch-up batch; live tail follows.
    CaughtUp { cursor: Cursor },
    /// Human-readable status line.
    Status(String),
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandEvent {
    /// Progress update for file transfers or long-running sweeps
    Progress { current: u64, total: u64 },
    /// Non-fatal warnings or diagnostic status updates
    Status(String),
    /// Structured data payloads (e.g. process lists or port scans)
    Payload(serde_json::Value),
    /// Signal completion with exit code
    Exit(i32),
}