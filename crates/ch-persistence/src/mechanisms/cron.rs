//! cron fallback mechanism.

use crate::{Health, Mechanism};
use ch_common::Result;
use ch_pid_lock::pid_lock::PID_FILE;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Everything we manage lives between these two markers so we can find,
/// replace, and remove it without touching the user's other cron entries.
const MARKER_BEGIN: &str = "# >>> ch respawn (managed) >>>";
const MARKER_END: &str = "# <<< ch respawn (managed) <<<";

/// How often the watchdog line fires. Guarded so it only relaunches when the
/// process is not already running.
const RESPAWN_SCHEDULE: &str = "* * * * *";

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
        // Usable if we can locate the `crontab` client *and* actually invoke it.
        // `crontab -l` exits non-zero when there's no spool yet, so we only care
        // that the command executed at all - not its exit status.
        match find_crontab() {
            Some(bin) => Command::new(bin)
                .arg("-l")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok(),
            None => false,
        }
    }

    fn install(&self, self_path: &Path) -> Result<()> {
        // We install into *root's* crontab so the relaunched process runs as
        // root (needed for privileged binds). We must therefore already be root.
        if !is_root() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cron respawn requires root",
            )
            .into());
        }

        let bin = crontab_bin()?;
        let target = absolute_path(self_path);
        let block = build_block(&target);

        let current = read_crontab(&bin)?;

        // Rebuild from a copy that has any previous managed block stripped, then
        // append the fresh one. This makes install idempotent and also upgrades
        // a stale entry (e.g. the binary moved) in place.
        let mut next = strip_block(&current);
        if !next.is_empty() && !next.ends_with('\n') {
            next.push('\n');
        }
        next.push_str(&block);

        // Don't churn the spool if nothing would actually change.
        if same_crontab(&next, &current) {
            return Ok(());
        }

        write_crontab(&bin, &next)
    }

    fn check(&self) -> Result<Health> {
        // Meaningful only when run as root, since a non-root `crontab -l` reads
        // a different spool than the one we install into.
        let bin = match find_crontab() {
            Some(b) => b,
            None => return Ok(Health::Missing),
        };
        let current = read_crontab(&bin)?;
        if current.contains(MARKER_BEGIN) {
            Ok(Health::Active)
        } else {
            Ok(Health::Missing)
        }
    }

    fn remove(&self) -> Result<()> {
        if !is_root() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cron respawn requires root",
            )
            .into());
        }

        let bin = crontab_bin()?;
        let current = read_crontab(&bin)?;
        if !current.contains(MARKER_BEGIN) {
            return Ok(()); // nothing of ours to remove
        }

        let stripped = strip_block(&current);
        if stripped.trim().is_empty() {
            // Our block was the only content - drop the crontab entirely.
            clear_crontab(&bin)
        } else {
            write_crontab(&bin, &stripped)
        }
    }

    fn info(&self) -> String {
        // We re-use the logic from check() to see if we are currently "Enabled"
        let is_enabled = match self.check() {
            Ok(Health::Active) => "Yes",
            _ => "No",
        };

        let mut base = format!(
            "Available: {}\nEnabled: {}\n",
            if self.available() { "Yes" } else { "No" },
            is_enabled
        );

        // If it's not enabled, we hide the implementation details
        if is_enabled == "Yes" {
            base.push_str(&format!(
                "Schedule: {}\nPID File: {}\nMarker Begin: {}\nMarker End: {}",
                RESPAWN_SCHEDULE, PID_FILE, MARKER_BEGIN, MARKER_END
            ));
        }
        
        base
    }
}

// ---- crontab I/O -----------------------------------------------------------

fn crontab_bin() -> Result<PathBuf> {
    find_crontab().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no `crontab` executable found in PATH",
        )
        .into()
    })
}

fn read_crontab(bin: &Path) -> Result<String> {
    let out = Command::new(bin).arg("-l").output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        // The only portable failure mode worth handling is "no crontab for
        // <user>", which crontab reports with a non-zero exit. Treat a failed
        // listing as an empty spool - the safe default for install/remove.
        Ok(String::new())
    }
}

fn write_crontab(bin: &Path, content: &str) -> Result<()> {
    let mut child = Command::new(bin)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    child
        .stdin
        .take()
        .expect("stdin was requested as piped")
        .write_all(content.as_bytes())?;

    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("`crontab -` exited with {}", status),
        )
        .into())
    }
}

fn clear_crontab(bin: &Path) -> Result<()> {
    // `-r` removes the whole crontab. We only call this once we've confirmed
    // our block was the sole content, so nothing else is lost. Ignore a
    // non-zero exit (e.g. it was already gone).
    let _ = Command::new(bin)
        .arg("-r")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(())
}

// ---- block construction / parsing ------------------------------------------

fn build_block(target: &Path) -> String {
    let cmd = shell_quote(&target.to_string_lossy());
    let pid = shell_quote(PID_FILE);
    format!(
        "{begin}\n\
         # Managed automatically; edits inside this block will be overwritten.\n\
         # Delete the whole block (or run the program's uninstall) to remove it.\n\
         @reboot {cmd}\n\
         {schedule} kill -0 \"$(cat {pid} 2>/dev/null)\" 2>/dev/null || {cmd}\n\
         {end}\n",
        begin = MARKER_BEGIN,
        end = MARKER_END,
        schedule = RESPAWN_SCHEDULE,
        cmd = cmd,
        pid = pid,
    )
}

/// Remove our managed block (BEGIN..=END, inclusive) wherever it appears.
/// If a BEGIN has no matching END the rest of the file is dropped, which is the
/// right thing for a truncated/corrupted block.
fn strip_block(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut skipping = false;
    for line in content.lines() {
        match line.trim() {
            MARKER_BEGIN => skipping = true,
            MARKER_END => skipping = false,
            _ if !skipping => {
                out.push_str(line);
                out.push('\n');
            }
            _ => {}
        }
    }
    out
}

fn same_crontab(a: &str, b: &str) -> bool {
    a.trim_end() == b.trim_end()
}

// ---- helpers ---------------------------------------------------------------

/// Effective UID from /proc (Linux). The status line looks like:
///   Uid:\t<real>\t<effective>\t<saved>\t<fs>
fn is_root() -> bool {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1)) // effective uid
            .map(|euid| euid == "0")
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn find_crontab() -> Option<PathBuf> {
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join("crontab");
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    for p in ["/usr/bin/crontab", "/bin/crontab", "/usr/local/bin/crontab"] {
        let pb = PathBuf::from(p);
        if is_executable_file(&pb) {
            return Some(pb);
        }
    }
    None
}

fn is_executable_file(p: &Path) -> bool {
    match fs::metadata(p) {
        Ok(m) if m.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

/// cron runs jobs from `$HOME` with a minimal environment, so the entry needs
/// an absolute path. Resolve symlinks where possible, falling back gracefully.
fn absolute_path(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            env::current_dir()
                .map(|d| d.join(p))
                .unwrap_or_else(|_| p.to_path_buf())
        }
    })
}

/// POSIX single-quote quoting: wrap in `'...'`, and render any embedded quote as
/// `'\''`. Handles paths with spaces or shell metacharacters.
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}