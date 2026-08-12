//! Agent-side listener: hold the port dark until a valid SPA knock, then serve russh.

use ch_common::Result;

/// Run the SPA-gated russh server until shutdown.
pub async fn serve(_port: u16) -> Result<()> {
    // M1: bind, gate on ch_spa knock (UDP + TCP-embedded), then russh with a pinned
    // host key and shared-team-key client auth. PTY channel plus telemetry channels.
    unimplemented!("M1: SPA-gated russh server")
}
