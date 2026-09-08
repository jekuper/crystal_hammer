use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use ch_common::Result;

/// Canonical PID/lock file. The daemon takes an exclusive `flock` on it at
/// startup and writes its PID into it; the cron watchdog reads that PID. Kept
/// under /run (tmpfs, node-local) so a stale file never survives a reboot and
/// so `flock` behaves - unlike some network filesystems, tmpfs locks are real.
pub const PID_FILE: &str = "/run/ch.pid";

// ---- PID lock --------------------------------------------------------------

/// Exclusive run-lock for the daemon. Call `PidGuard::acquire()` once, early in
/// `main()`, and keep the returned guard alive for the life of the process.
///
/// The lock lives on the open file descriptor held inside the guard. The kernel
/// releases it the instant that fd closes - on drop, on a clean exit, or on a
/// crash - so there is no stale-lock state to reason about and no liveness
/// guessing. That is the whole reason this uses `flock` instead of a
/// check-then-write on the file contents: the old scheme had a window where two
/// processes could both read "no live owner" and both claim the file.
pub struct PidGuard {
    // Holding this open keeps the flock held. Never closed early.
    _file: File,
    pid: u32,
}

impl PidGuard {
    pub fn acquire() -> Result<Self> {
        Self::acquire_at(Path::new(PID_FILE))
    }

    pub fn acquire_at(path: &Path) -> Result<Self> {
        let me = std::process::id();

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }

        // Open (creating if absent) WITHOUT truncating: if we lose the race for
        // the lock we still want to read the current owner's PID for the error
        // message. Truncation happens only after we've won the lock.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        // Atomically claim ownership. LOCK_EX | LOCK_NB either grabs the
        // exclusive lock right now or fails immediately with EWOULDBLOCK; it
        // never blocks and, crucially, never races - the kernel guarantees at
        // most one holder. This is the fix for the old check-then-write TOCTOU
        // window, so two supervisors (cron + systemd) firing at once can no
        // longer both start a daemon.
        loop {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // Interrupted by a signal before the lock resolved - just retry.
                Some(libc::EINTR) => continue,
                // Someone else holds the lock. Read their PID purely for the
                // error message; correctness came from the failed lock, not
                // from this read (which may briefly race the owner's write).
                Some(libc::EWOULDBLOCK) => {
                    let owner = read_pid(path).unwrap_or(0);
                    return Err(ch_common::Error::PidLockFailed(owner));
                }
                _ => return Err(err.into()),
            }
        }

        // We own the lock. Publish our PID for the watchdog. Truncate first so a
        // shorter PID can't leave trailing bytes from a previous, longer owner.
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{me}")?;
        file.flush()?;

        Ok(PidGuard { _file: file, pid: me })
    }

    /// Our PID, i.e. the value written into the lock file.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

// No `Drop` impl is needed to release the lock: dropping `_file` closes the fd,
// which drops the flock. We deliberately do NOT unlink the file. Unlinking a
// flock'd path is racy (a concurrent opener can end up locking an inode whose
// name is already gone, while a fresh create makes a different inode), and it
// buys nothing here: on exit the file is simply left holding our now-dead PID,
// which the cron watchdog treats as "not running" via `kill -0` and relaunches.
// Any reader of this file must pair it with a liveness check; it is a hint for
// the watchdog, not proof of a live process.

fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}