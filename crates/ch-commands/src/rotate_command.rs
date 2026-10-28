//! Credential rotation. `rotate <user>` locks the account's current password (so a stolen
//! password stops authenticating immediately) and forces a reset at next login, after
//! backing up /etc/shadow. Key-based SSH is unaffected, so this never locks out the tool.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ch_common::{Error, Result};
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

const SHADOW: &str = "/etc/shadow";

/// Copies `path` to `path.ch.bak.<unixtime>`, preserving its mode. Returns the backup path.
pub(crate) fn backup_file(path: &str) -> std::io::Result<String> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let dst = format!("{path}.ch.bak.{ts}");
    let data = fs::read(path)?;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    let mut f = OpenOptions::new().write(true).create_new(true).mode(mode).open(&dst)?;
    f.write_all(&data)?;
    f.flush()?;
    Ok(dst)
}

/// Writes `content` to `path` atomically (temp file in the same dir, then rename).
fn write_atomic(path: &str, content: &str, mode: u32) -> std::io::Result<()> {
    let tmp = format!("{path}.ch.tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(content.as_bytes())?;
    f.flush()?;
    fs::rename(&tmp, path)
}

/// Rewrites the shadow entry for `user`: lock the password hash (leading `!`) and set the
/// last-change field to 0 so a reset is required. Returns false if the user wasn't found.
fn rotate_user(shadow: &str, user: &str, out: &mut String) -> bool {
    let mut found = false;
    for line in shadow.lines() {
        let mut fields: Vec<String> = line.split(':').map(str::to_owned).collect();
        if !found && fields.first().map(|n| n == user).unwrap_or(false) && fields.len() >= 2 {
            found = true;
            if !fields[1].starts_with('!') {
                fields[1] = format!("!{}", fields[1]);
            }
            if fields.len() >= 3 {
                fields[2] = "0".to_string(); // lastchg = 0 -> must change at next login
            }
            out.push_str(&fields.join(":"));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    found
}

pub struct RotateAgentCommand {}

impl RotateAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for RotateAgentCommand {
    fn name(&self) -> &'static str {
        "rotate"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        let Some(user) = args.first() else {
            ctx.stdout.write_all(b"usage: rotate <user>\n").await?;
            return Ok(());
        };

        let shadow = match fs::read_to_string(SHADOW) {
            Ok(s) => s,
            Err(e) => {
                ctx.stdout.write_all(format!("cannot read {SHADOW}: {e}\n").as_bytes()).await?;
                return Ok(());
            }
        };
        let mode = fs::metadata(SHADOW).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o640);

        let mut updated = String::with_capacity(shadow.len() + 8);
        if !rotate_user(&shadow, user, &mut updated) {
            ctx.stdout.write_all(format!("user not found in shadow: {user}\n").as_bytes()).await?;
            return Ok(());
        }

        // Back up before writing so the original credential is recoverable.
        let backup = backup_file(SHADOW).map_err(|e| Error::Other(format!("backup failed: {e}")))?;
        write_atomic(SHADOW, &updated, mode).map_err(|e| Error::Other(format!("write failed: {e}")))?;

        let report = format!(
            "rotated {user}: password locked and reset forced at next login\nbacked up {SHADOW} -> {backup}\n"
        );
        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

pub struct RotateClientCommand {}

impl RotateClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for RotateClientCommand {
    fn name(&self) -> &'static str {
        "rotate"
    }
    fn short_description(&self) -> &'static str {
        "Lock + force-reset a user's password"
    }
    fn help(&self) -> &'static str {
        "Usage: rotate <user>\n\n\
        Locks the user's current password (stops a stolen password working) and forces a\n\
        reset at next login, after backing up /etc/shadow. Key-based SSH is unaffected."
    }
    fn complete_arg(&self, _preceding: &[&str], _word: &str, _ctx: &rustyline::Context<'_>, _fc: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "rotate", args).await
    }
}
