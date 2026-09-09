//! systemd unit mechanism.

use crate::{Health, Mechanism};
use ch_common::Result;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use ch_common::Error;

/// Unit we own. Fully managed: reinstalling overwrites it, uninstalling deletes
/// it. Named to parallel the cron block's "ch respawn (managed)".
const SERVICE_NAME: &str = "ch-respawn.service";

/// Where a system unit lives. We install here (not the user dir) because, like
/// the cron mechanism, we run as root so the relaunched process can do
/// privileged binds and survive reboot without a logged-in session.
const UNIT_DIR: &str = "/etc/systemd/system";

/// The target the unit hooks into on boot.
const WANTED_BY: &str = "multi-user.target";

/// Delay before systemd relaunches a dead service.
const RESTART_SEC: &str = "60";

pub struct Systemd {
    _priv: (),
}

impl Systemd {
    pub fn new() -> Self {
        Systemd { _priv: () }
    }
}

impl Mechanism for Systemd {
    fn id(&self) -> ch_common::ImplId {
        "systemd"
    }

    fn available(&self) -> bool {
        // Usable only when systemd is actually the init system *and* we can find
        // the client. Distros that ship `systemctl` but boot something else
        // (e.g. inside a minimal container) correctly report unavailable.
        // Note: like cron's `available`, this does not require root - root is
        // only needed to actually install/remove.
        systemd_running() && systemctl_bin().is_ok()
    }

    fn install(&self, self_path: &Path) -> Result<()> {
        // We install a *system* unit so the relaunched process runs as root
        // (needed for privileged binds). We must therefore already be root.
        if !is_root() {
            return Err(Error::MissingRoot("systemd respawn".to_string()));
        }
        if !systemd_running() {
            return Err(Error::Unsupported("systemd respawn".to_string()));
        }

        let unit_path = Path::new(UNIT_DIR).join(SERVICE_NAME);
        let target = absolute_path(self_path);
        let unit = build_unit(&target);

        // Only touch the spool if something would actually change. `changed` is
        // also true when the file is absent, so a first install always writes.
        // This makes install idempotent and upgrades a stale entry (e.g. the
        // binary moved) in place - matching the cron mechanism's behavior.
        let changed = match fs::read_to_string(&unit_path) {
            Ok(existing) => existing != unit,
            Err(_) => true,
        };
        if changed {
            fs::create_dir_all(UNIT_DIR)?;
            fs::write(&unit_path, &unit)?;
            systemctl_checked(&["daemon-reload"])?;
        }

        // enable is idempotent (re-enabling an enabled unit is a no-op).
        systemctl_checked(&["enable", SERVICE_NAME])?;

        // Apply the running state. On a real change we restart so an updated
        // ExecStart takes effect now; otherwise a plain start is a no-op when
        // the service is already up. This is what makes repeated installs safe.
        if changed {
            systemctl_checked(&["restart", SERVICE_NAME])?;
        } else {
            systemctl_checked(&["start", SERVICE_NAME])?;
        }

        Ok(())
    }

    fn check(&self) -> Result<Health> {
        if !systemd_running() {
            return Ok(Health::Missing);
        }
        // `is-enabled` exits 0 when the unit is enabled -> our idea of "installed
        // and persistent", mirroring the cron marker check.
        let status = systemctl_status(&["is-enabled", SERVICE_NAME])?;
        if status.success() {
            Ok(Health::Active)
        } else {
            Ok(Health::Missing)
        }
    }

    fn remove(&self) -> Result<()> {
        if !is_root() {
            return Err(Error::MissingRoot("systemd remove".to_string()));
        }
        if !systemd_running() {
            return Ok(());
        }

        let unit_path = Path::new(UNIT_DIR).join(SERVICE_NAME);

        // Stop + unlink the enable symlinks. Ignore failure: the unit may already
        // be gone, which is exactly the state we want.
        let _ = systemctl_status(&["disable", "--now", SERVICE_NAME]);

        if unit_path.exists() {
            fs::remove_file(&unit_path)?;
            let _ = systemctl_status(&["daemon-reload"]);
        }
        Ok(())
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
                "Service Name: {}\nUnit Path: {}/{}\nTarget Hook: {}\nRestart Interval: {}s",
                SERVICE_NAME, UNIT_DIR, SERVICE_NAME, WANTED_BY, RESTART_SEC
            ));
        }
        
        base
    }
}

// ---- systemctl I/O ---------------------------------------------------------

/// Run `systemctl <args>`, discarding output, returning the exit status.
fn systemctl_status(args: &[&str]) -> Result<std::process::ExitStatus> {
    let bin = systemctl_bin()?;
    let status = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status)
}

/// Same, but turn a non-zero exit into an error. Use for steps that must succeed.
fn systemctl_checked(args: &[&str]) -> Result<()> {
    let status = systemctl_status(args)?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("`systemctl {}` exited with {}", args.join(" "), status),
        )
        .into())
    }
}

// ---- unit construction -----------------------------------------------------

fn build_unit(exec: &Path) -> String {
    let exec_start = systemd_quote(&exec.to_string_lossy());
    format!(
        "# Managed automatically by ch; edits will be overwritten on reinstall.\n\
         # Remove via the program's uninstall (systemctl disable + file delete).\n\
         [Unit]\n\
         Description=ch respawn (managed)\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         # Disable the crash-loop rate limiter so we relaunch relentlessly, the\n\
         # way the cron watchdog does. Trade-off: a genuinely broken binary will\n\
         # spin instead of parking in `failed`.\n\
         StartLimitIntervalSec=0\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec}\n\
         Restart=always\n\
         RestartSec={sec}\n\
         \n\
         [Install]\n\
         WantedBy={target}\n",
        exec = exec_start,
        sec = RESTART_SEC,
        target = WANTED_BY,
    )
}

/// systemd ExecStart quoting: a clean path is emitted bare; anything with
/// whitespace or systemd-significant characters is double-quoted with `"` and
/// `\` backslash-escaped and `%` doubled (systemd specifier escape).
fn systemd_quote(s: &str) -> String {
    let clean = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_graphic() && !matches!(c, '"' | '\\' | '%' | '$' | ';' | '\'')
        });
    if clean {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---- helpers ---------------------------------------------------------------

/// True iff the machine was booted with systemd as PID 1. This is the canonical
/// `sd_booted()` check and is what makes the mechanism distro-agnostic - it keys
/// off runtime behavior, not off which files a package happened to drop.
fn systemd_running() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

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

fn systemctl_bin() -> Result<PathBuf> {
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join("systemctl");
            if is_executable_file(&candidate) {
                return Ok(candidate);
            }
        }
    }
    for p in ["/usr/bin/systemctl", "/bin/systemctl", "/usr/local/bin/systemctl"] {
        let pb = PathBuf::from(p);
        if is_executable_file(&pb) {
            return Ok(pb);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no `systemctl` executable found in PATH",
    )
    .into())
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

/// systemd runs services with a minimal environment, so ExecStart needs an
/// absolute path. Resolve symlinks where possible, degrade gracefully.
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