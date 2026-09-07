
use std::fs;
use std::path::{Path, PathBuf};
use ch_common::Result;

/// Canonical PID file. The daemon writes it on startup; the cron watchdog reads
/// it. Kept under /run (tmpfs) so a stale file never survives a reboot.
pub const PID_FILE: &str = "/run/ch.pid";


// ---- PID file --------------------------------------------------------------

/// Ownership record for the running daemon. Call `PidGuard::acquire()` once,
/// early in the daemon's `main()`. Holding the returned guard keeps the PID
/// file present; dropping it (clean exit) removes the file, but only if it
/// still names us - a crashed process leaves a stale file that the watchdog
/// treats as "dead" on the next tick.
pub struct PidGuard {
    path: PathBuf,
    pid: u32,
}

impl PidGuard {
    pub fn acquire() -> Result<Self> {
        Self::acquire_at(Path::new(PID_FILE))
    }

    pub fn acquire_at(path: &Path) -> Result<Self> {
        let me = std::process::id();

        // Refuse to start a second instance while a live one owns the file.
        if let Some(existing) = read_pid(path) {
            if existing != me && pid_is_alive(existing) {
                return Err(
                    ch_common::Error::PidLockFailed(existing)
                );
            }
            // else: file is stale (dead pid) or already ours - take it over.
        }

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }

        // Write atomically: write a temp file, then rename over the target so a
        // concurrent reader never sees a half-written PID.
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("pidfile");
        let tmp = path.with_file_name(format!(".{name}.{me}.tmp"));
        fs::write(&tmp, format!("{me}\n"))?;
        fs::rename(&tmp, path)?;

        Ok(PidGuard {
            path: path.to_path_buf(),
            pid: me,
        })
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        // Never clobber a successor's file: only remove if it still names us.
        if read_pid(&self.path) == Some(self.pid) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Liveness check via /proc (Linux). Consistent with the watchdog's `kill -0`.
fn pid_is_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}