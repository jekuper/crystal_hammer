//! `time` - current clock on the agent host, plus uptime. Computed from the system clock
//! directly (no shelling out), UTC rendered with the civil-from-days algorithm.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

/// Formats a Unix timestamp as `YYYY-MM-DD HH:MM:SS UTC` (Howard Hinnant's algorithm).
fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

fn uptime() -> String {
    let secs = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_owned))
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0) as u64;
    format!("{}d {}h {}m", secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60)
}

pub struct TimeAgentCommand {}
impl TimeAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for TimeAgentCommand {
    fn name(&self) -> &'static str {
        "time"
    }
    async fn execute(&self, _args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let report = format!("agent time: {} (unix {})\nuptime: {}\n", fmt_utc(now), now, uptime());
        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

pub struct TimeClientCommand {}
impl TimeClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for TimeClientCommand {
    fn name(&self) -> &'static str {
        "time"
    }
    fn short_description(&self) -> &'static str {
        "Show the agent host's current time"
    }
    fn help(&self) -> &'static str {
        "Usage: time\n\nCurrent clock (UTC) and uptime on the agent host."
    }
    fn complete_arg(&self, _p: &[&str], _w: &str, _c: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "time", args).await
    }
}

#[cfg(test)]
mod tests {
    use super::fmt_utc;
    #[test]
    fn known_epochs() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }
}
