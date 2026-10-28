//! Auth-log monitor: tails the system auth log and turns SSH login activity into live
//! alerts, so an operator sees *who logged in from where* in the same feed as file-change
//! alerts - the first thread of "how did they get in".
//!
//! File-based (rsyslog `/var/log/auth.log` or `/var/log/secure`). A journald-only host
//! with no such file produces no auth alerts; that's a known limitation until a journald
//! reader lands.

use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use ch_common::proto::{Actor, Alert, AlertSeverity};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::info;

use crate::audit::AuditHandle;

const CANDIDATES: &[&str] = &["/var/log/auth.log", "/var/log/secure"];
const POLL: Duration = Duration::from_secs(2);

/// Spawn the auth-log monitor. Cheap to run; does nothing until a login line appears.
pub fn spawn(handle: AuditHandle) {
    tokio::spawn(async move { run(handle).await });
}

fn first_existing() -> Option<String> {
    CANDIDATES
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}

async fn run(handle: AuditHandle) {
    // (watched path, inode, byte offset). Starts at the end of a log that already exists
    // so we don't replay history; a log that only appears later is read from the start.
    let mut path: Option<String> = None;
    let mut ino: u64 = 0;
    let mut pos: u64 = 0;
    let mut announced = false;
    let mut first_tick = true;
    let mut ticker = tokio::time::interval(POLL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        let startup = first_tick;
        first_tick = false;

        // Keep the current log if it's still there; otherwise (re)select one.
        let current = match &path {
            Some(p) if tokio::fs::metadata(p).await.is_ok() => p.clone(),
            _ => {
                let Some(p) = first_existing() else { continue };
                if !announced {
                    info!("Auth-log monitor watching {}.", p);
                    announced = true;
                }
                let Ok(meta) = tokio::fs::metadata(&p).await else { continue };
                path = Some(p.clone());
                ino = meta.ino();
                // A log that already existed at startup: skip its history. One that only
                // appeared later: read it from the start.
                pos = if startup { meta.len() } else { 0 };
                p
            }
        };

        let Ok(meta) = tokio::fs::metadata(&current).await else { continue };
        if meta.ino() != ino {
            ino = meta.ino(); // rotated: read the new file from the start
            pos = 0;
        } else if meta.len() < pos {
            pos = 0; // truncated
        }
        if meta.len() <= pos {
            continue;
        }

        let Ok(mut f) = tokio::fs::File::open(&current).await else { continue };
        if f.seek(std::io::SeekFrom::Start(pos)).await.is_err() {
            continue;
        }
        let mut buf = String::new();
        if f.take(meta.len() - pos).read_to_string(&mut buf).await.is_err() {
            continue;
        }
        pos = meta.len();

        for line in buf.lines() {
            if let Some(alert) = parse_line(line) {
                handle.publish(alert);
            }
        }
    }
}

/// The token following `pat` in `s`, up to the next whitespace.
fn token_after<'a>(s: &'a str, pat: &str) -> Option<&'a str> {
    s.split_once(pat)?.1.split_whitespace().next()
}

fn login_alert(kind: &str, severity: AlertSeverity, detail: String, user: &str) -> Alert {
    Alert {
        kind: kind.to_string(),
        severity,
        path: String::new(),
        detail,
        actor: Actor { uname: user.to_string(), ..Actor::default() },
        unix_time: crate::audit::unix_now(),
    }
}

/// Parses one sshd auth-log line into an alert, or None if it isn't a login event.
fn parse_line(line: &str) -> Option<Alert> {
    if !line.contains("sshd") {
        return None;
    }
    if let Some(rest) = line.split_once("Accepted ").map(|x| x.1) {
        let method = rest.split_whitespace().next().unwrap_or("");
        let user = token_after(rest, "for ").unwrap_or("");
        let ip = token_after(rest, "from ").unwrap_or("");
        return Some(login_alert(
            "ssh_login",
            AlertSeverity::Warn,
            format!("accepted {method} for {user} from {ip}"),
            user,
        ));
    }
    if line.contains("Failed password for") {
        let tail = line.split_once("for ").map(|x| x.1).unwrap_or("");
        let user = tail.strip_prefix("invalid user ").unwrap_or(tail).split_whitespace().next().unwrap_or("");
        let ip = token_after(line, "from ").unwrap_or("");
        return Some(login_alert(
            "ssh_login_failed",
            AlertSeverity::Info,
            format!("failed password for {user} from {ip}"),
            user,
        ));
    }
    if let Some(rest) = line.split_once("Invalid user ").map(|x| x.1) {
        let user = rest.split_whitespace().next().unwrap_or("");
        let ip = token_after(line, "from ").unwrap_or("");
        return Some(login_alert(
            "ssh_login_failed",
            AlertSeverity::Info,
            format!("invalid user {user} from {ip}"),
            user,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_accepted_login() {
        let l = "Nov  1 12:00:00 h sshd[9]: Accepted publickey for alice from 10.1.2.3 port 5 ssh2: ED25519 x";
        let a = parse_line(l).unwrap();
        assert_eq!(a.kind, "ssh_login");
        assert!(a.detail.contains("alice") && a.detail.contains("10.1.2.3") && a.detail.contains("publickey"));
        assert_eq!(a.actor.uname, "alice");
    }

    #[test]
    fn parses_failed_and_invalid() {
        let f = parse_line("x sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2").unwrap();
        assert_eq!(f.kind, "ssh_login_failed");
        assert!(f.detail.contains("root") && f.detail.contains("9.9.9.9"));
        let i = parse_line("x sshd[1]: Invalid user bob from 8.8.8.8 port 1").unwrap();
        assert_eq!(i.actor.uname, "bob");
    }

    #[test]
    fn ignores_non_login() {
        assert!(parse_line("x sshd[1]: Server listening on 0.0.0.0 port 22").is_none());
        assert!(parse_line("x systemd[1]: Started something").is_none());
    }
}
