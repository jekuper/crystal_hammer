// File: crates/ch-monitor/src/audit.rs
//! File-integrity monitoring on the Linux audit subsystem, with a fanotify fallback.
//!
//! This module contains no `unsafe`: netlink goes through `netlink-sys` and
//! `netlink-packet-audit`, fanotify through `nix`, so it builds under
//! `#![forbid(unsafe_code)]`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock as RwLockStd, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _};
use ch_common::proto::{Actor, Alert, AlertSeverity};
use tokio::sync::{broadcast, mpsc, Mutex as AsyncMutex, RwLock};
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use self::netlink::AuditSocket;

pub const AUDIT_KEY: &str = "neccdc_fim";

const AUDIT_LOG: &str = "/var/log/audit/audit.log";
/// Root-owned, 0700 directory for the canary. Never /tmp: a world-writable directory lets
/// anyone plant a symlink there and have this (root) process overwrite an arbitrary file.
const CANARY_DIR: &str = "/var/lib/ch-monitor";

const RENEGOTIATE_BACKOFF: Duration = Duration::from_secs(1);
const FANOTIFY_AUDIT_RETRY: Duration = Duration::from_secs(30);
const NO_BACKEND_RETRY: Duration = Duration::from_secs(30);
/// Upper bound on any single netlink request/response exchange with the kernel.
const NETLINK_TIMEOUT: Duration = Duration::from_secs(2);
/// How often the log tailer polls at EOF.
const LOG_POLL: Duration = Duration::from_millis(250);
/// Records of one event that never get an EOE are flushed after this long.
const GROUP_FLUSH_AFTER: Duration = Duration::from_secs(2);
/// Cap on in-flight event groups, so a flood can't grow memory without bound.
const MAX_PENDING_GROUPS: usize = 4096;
/// Identical findings (same kind, path, pid) inside this window are reported once.
const DEDUP_WINDOW: Duration = Duration::from_secs(2);
const HASH_MAX_DEPTH: usize = 8;
const HASH_MAX_FILES: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveBackend {
    Multicast,
    LogTail,
    Daemon,
    Fanotify,
    None,
}

impl ActiveBackend {
    /// Whether events come from the kernel audit subsystem (and so audit rules matter).
    fn uses_audit(self) -> bool {
        matches!(self, Self::Multicast | Self::LogTail | Self::Daemon)
    }
}

/// One raw event as delivered by a backend, before grouping and enrichment.
#[derive(Debug, Clone)]
pub enum RawEvent {
    /// One audit record. `kind` is the record type name ("SYSCALL", "PATH", ...) and
    /// `body` the record text starting at `audit(<timestamp>:<serial>): ...`.
    Audit { kind: String, body: String },
    /// One fanotify notification.
    Fanotify { path: String, pid: i32, mask: String },
}

#[derive(Debug, Clone, Copy, Default)]
struct AuditStatus {
    /// 0 = disabled, 1 = enabled, 2 = enabled and immutable (rules locked until reboot).
    enabled: u32,
    pid: u32,
    lost: u32,
    backlog: u32,
}

impl AuditStatus {
    fn is_enabled(&self) -> bool {
        self.enabled != 0
    }

    fn is_immutable(&self) -> bool {
        self.enabled == 2
    }
}

/// Capacity of the live alert broadcast. A slow operator connection that falls this far
/// behind gets a Lagged signal rather than stalling the engine.
const ALERT_CHANNEL_CAP: usize = 1024;

/// Cheap, cloneable handle onto a running engine: lets commands stream alerts and extend
/// the tracked-file list at runtime without touching the engine internals.
#[derive(Clone)]
pub struct AuditHandle {
    alerts: broadcast::Sender<Alert>,
    watchlist: Arc<RwLockStd<Vec<String>>>,
}

impl AuditHandle {
    /// Subscribe to the live alert stream. Each subscriber gets every alert sent after it
    /// subscribed.
    pub fn subscribe(&self) -> broadcast::Receiver<Alert> {
        self.alerts.subscribe()
    }

    /// Current tracked paths.
    pub fn list(&self) -> Vec<String> {
        lock_r(&self.watchlist).clone()
    }

    /// Start tracking `path`. Returns false if it was already tracked. Audit-backend rules
    /// pick the new path up on the next sync (within ~5s); fanotify re-marks on its tick.
    pub fn add_watch(&self, path: String) -> bool {
        let mut list = lock_w(&self.watchlist);
        if list.iter().any(|p| p == &path) {
            return false;
        }
        list.push(path);
        true
    }
}

#[derive(Clone)]
pub struct AuditEngine {
    watchlist: Arc<RwLockStd<Vec<String>>>,
    alerts: broadcast::Sender<Alert>,
    allow_daemon: bool,
    current_backend: Arc<RwLock<ActiveBackend>>,
    canary_path: String,
    /// When the event processor last saw an audit event for the canary file.
    last_canary_seen: Arc<Mutex<Option<Instant>>>,
    /// Last time any audit/fanotify event touched each watchlist entry (for hash attribution).
    last_activity: Arc<Mutex<HashMap<String, Instant>>>,
    /// Serialises rule sync between the negotiator and the 5s status loop.
    rules_lock: Arc<AsyncMutex<()>>,
    /// Problems already reported at warn level; repeats drop to debug.
    warned: Arc<Mutex<HashSet<String>>>,
}

impl AuditEngine {
    pub fn new(watchlist: Vec<String>, allow_daemon: bool) -> Self {
        let (alerts, _) = broadcast::channel(ALERT_CHANNEL_CAP);
        Self {
            watchlist: Arc::new(RwLockStd::new(watchlist)),
            alerts,
            allow_daemon,
            current_backend: Arc::new(RwLock::new(ActiveBackend::None)),
            canary_path: format!("{CANARY_DIR}/.canary"),
            last_canary_seen: Arc::new(Mutex::new(None)),
            last_activity: Arc::new(Mutex::new(HashMap::new())),
            rules_lock: Arc::new(AsyncMutex::new(())),
            warned: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// A cloneable handle for streaming alerts and extending the watchlist at runtime.
    pub fn handle(&self) -> AuditHandle {
        AuditHandle {
            alerts: self.alerts.clone(),
            watchlist: self.watchlist.clone(),
        }
    }

    /// Snapshot of the tracked paths. Taken fresh by every loop so runtime additions are
    /// picked up on the next pass.
    fn watchlist(&self) -> Vec<String> {
        lock_r(&self.watchlist).clone()
    }

    /// Converts an internal finding into a wire alert and publishes it to live operators.
    /// A send error just means nobody is connected; findings still go to the evidence log
    /// via `Finding::emit`.
    fn publish(&self, f: &Finding) {
        let alert = Alert {
            kind: f.kind.to_string(),
            severity: severity_for(f.kind),
            path: f.path.clone(),
            detail: f.detail.clone(),
            actor: Actor {
                pid: f.pid,
                ppid: f.ppid.clone(),
                uid: f.uid.clone(),
                auid: f.auid.clone(),
                exe: f.exe.clone(),
                comm: f.comm.clone(),
                cmdline: f.cmdline.clone(),
            },
            unix_time: unix_now(),
        };
        let _ = self.alerts.send(alert);
    }

    /// Emits a finding to the evidence log and the live alert stream in one step.
    fn emit(&self, f: Finding) {
        f.emit();
        self.publish(&f);
    }

    /// Entry point for the monitoring engine. Spawns the negotiation and integrity loops.
    pub async fn start(self) {
        let mut dir = tokio::fs::DirBuilder::new();
        dir.recursive(true).mode(0o700);
        if let Err(e) = dir.create(CANARY_DIR).await {
            error!("Failed to create canary directory {}: {}", CANARY_DIR, e);
        }

        let (event_tx, event_rx) = mpsc::unbounded_channel::<RawEvent>();

        // Task 1: Backend Negotiation & Listening
        let engine_clone = self.clone();
        tokio::spawn(async move {
            engine_clone.run_backend_negotiator(event_tx).await;
        });

        // Task 2: Event Processor
        let processor = EventProcessor::new(self.clone());
        tokio::spawn(processor.run(event_rx));

        // Task 3: Integrity Check Loops (Specs: 5s status, 10s canary, 30s modules, 60s hash)
        let engine_checks = self.clone();
        tokio::spawn(async move {
            engine_checks.run_integrity_loops().await;
        });
    }

    async fn backend(&self) -> ActiveBackend {
        *self.current_backend.read().await
    }

    /// Logs at warn the first time `key` is seen, at debug afterwards.
    fn warn_once(&self, key: &str, msg: &str) {
        if lock(&self.warned).insert(key.to_owned()) {
            warn!("{}", msg);
        } else {
            debug!("{}", msg);
        }
    }

    /// Records that a monitored path was touched, for hash-change attribution.
    fn note_activity(&self, paths: &[String]) {
        let now = Instant::now();
        let mut activity = lock(&self.last_activity);
        for watch in self.watchlist() {
            if paths.iter().any(|p| Path::new(p).starts_with(&watch)) {
                activity.insert(watch, now);
            }
        }
    }

    // =========================================================================
    // Backend negotiation
    // =========================================================================

    /// Negotiates the backend according to the strict priority spec.
    async fn run_backend_negotiator(&self, tx: mpsc::UnboundedSender<RawEvent>) {
        loop {
            let status = self.get_audit_status().await;
            let backend = self.negotiate_backend(status.as_ref());

            {
                let mut b = self.current_backend.write().await;
                if *b != backend {
                    info!("Audit backend changed: {:?} -> {:?}", *b, backend);
                    *b = backend;
                }
            }

            // Rules only make sense when audit is the event source.
            if let (true, Some(status)) = (backend.uses_audit(), status.as_ref()) {
                self.apply_rules(status).await;
            }

            match backend {
                ActiveBackend::Multicast => {
                    if let Err(e) = self.listen_multicast(tx.clone()).await {
                        warn!("Multicast listener failed: {:#}. Renegotiating...", e);
                    }
                }
                ActiveBackend::LogTail => {
                    if let Err(e) = self.tail_audit_log(tx.clone()).await {
                        warn!("Log tailer failed: {:#}. Renegotiating...", e);
                    }
                }
                ActiveBackend::Daemon => {
                    // Claim the daemon slot (AUDIT_SET with PID) only because config allowed it
                    // and no other daemon was running.
                    if let Err(e) = self.listen_unicast_daemon(tx.clone()).await {
                        warn!("Daemon listener failed: {:#}. Renegotiating...", e);
                    }
                }
                ActiveBackend::Fanotify => {
                    info!("Running on fanotify fallback.");
                    // Fallback spec: while on fanotify, retry audit every 30s. If fanotify
                    // itself fails early, still wait out the window instead of spinning.
                    let deadline = time::Instant::now() + FANOTIFY_AUDIT_RETRY;
                    tokio::select! {
                        res = self.listen_fanotify(tx.clone()) => {
                            if let Err(e) = res {
                                warn!("fanotify listener failed: {:#}", e);
                            }
                            time::sleep_until(deadline).await;
                        }
                        _ = time::sleep_until(deadline) => {
                            info!("30s passed on fanotify, retrying primary audit backends...");
                        }
                    }
                    continue;
                }
                ActiveBackend::None => {
                    error!("No usable file monitoring backend available. Retrying in 30s.");
                    time::sleep(NO_BACKEND_RETRY).await;
                    continue;
                }
            }

            // An audit listener returned. Back off briefly so a listener that fails
            // immediately doesn't turn this into a hot loop of netlink requests.
            time::sleep(RENEGOTIATE_BACKOFF).await;
        }
    }

    fn negotiate_backend(&self, status: Option<&AuditStatus>) -> ActiveBackend {
        // 1. Check if audit is enabled in kernel (and reachable at all: no netlink audit
        //    access, e.g. in a container, counts as unavailable).
        let Some(status) = status.filter(|s| s.is_enabled()) else {
            return ActiveBackend::Fanotify;
        };

        // 2. Try Multicast (AUDIT_NLGRP_READLOG)
        if self.test_multicast_bind() {
            return ActiveBackend::Multicast;
        }

        // If we registered as the daemon on a previous pass, the kernel reports our own PID.
        // That must not be mistaken for an external auditd.
        let foreign_daemon = status.pid != 0 && status.pid != std::process::id();

        // 3. Try Log Tailing (if auditd is running)
        if foreign_daemon && Path::new(AUDIT_LOG).exists() {
            return ActiveBackend::LogTail;
        }

        // 4. Register as Daemon (only if config allows and no daemon is running)
        if !foreign_daemon && self.allow_daemon {
            return ActiveBackend::Daemon;
        }

        // 5. Fallback
        ActiveBackend::Fanotify
    }

    // =========================================================================
    // Rules
    // =========================================================================

    /// The full set of rules this engine needs loaded.
    fn desired_rules(&self) -> Vec<String> {
        let mut rules = Vec::new();

        // 1. File watches (the canary is watched too, otherwise writing it proves nothing)
        for path in self.watchlist().iter().chain(std::iter::once(&self.canary_path)) {
            rules.push(format!("-w {path} -p wa -k {AUDIT_KEY}"));
            // Add read watches for secrets
            if is_secret(path) {
                rules.push(format!("-w {path} -p r -k {AUDIT_KEY}"));
            }
        }

        // 2. Kernel Module Syscalls, for every ABI this machine can run
        for arch in rules::ARCHES {
            rules.push(format!(
                "-a always,exit -F arch={} -S {} -k {AUDIT_KEY}",
                arch.name,
                rules::MODULE_SYSCALLS.join(",")
            ));
        }

        rules
    }

    /// Evaluates existing rules via AUDIT_LIST_RULES, and injects missing ones via AUDIT_ADD_RULE.
    /// NEVER uses AUDIT_DEL_RULE or `auditctl -D` (per specs).
    async fn apply_rules(&self, status: &AuditStatus) {
        if status.is_immutable() {
            debug!("Audit rules are immutable (enabled=2); skipping rule sync.");
            return;
        }

        let _guard = self.rules_lock.lock().await;
        debug!("Synchronizing audit rules (Additive only)...");

        let existing = match self.list_existing_rules().await {
            Ok(rules) => rules,
            Err(e) => {
                self.warn_once("list_rules", &format!("Cannot list audit rules: {e:#}"));
                return;
            }
        };

        let mut added = 0usize;
        for rule in self.desired_rules() {
            if existing.contains(&canonical_rule(&rule)) {
                continue;
            }
            debug!("Adding missing rule: {}", rule);
            match self.send_audit_add_rule(&rule).await {
                Ok(()) => added += 1,
                Err(e) => self.warn_once(&rule, &format!("Cannot add audit rule `{rule}`: {e:#}")),
            }
        }
        if added > 0 {
            info!("Added {} missing audit rule(s).", added);
        }
    }

    // =========================================================================
    // Integrity Checks
    // =========================================================================

    async fn run_integrity_loops(&self) {
        let mut status_ticker = ticker(Duration::from_secs(5));
        let mut canary_ticker = ticker(Duration::from_secs(10));
        let mut module_ticker = ticker(Duration::from_secs(30));
        let mut hash_ticker = ticker(Duration::from_secs(60));

        let mut last_lost: u32 = 0;
        let mut last_canary_write: Option<Instant> = None;
        let mut last_tainted: Option<String> = None;
        let mut last_modules: Option<HashSet<String>> = None;
        let mut hashes = HashState::default();

        loop {
            tokio::select! {
                _ = status_ticker.tick() => {
                    let backend = self.backend().await;
                    match self.get_audit_status().await {
                        Some(status) => {
                            // `lost` is a cumulative counter: report the increase, not the total.
                            if status.lost > last_lost {
                                warn!(
                                    "Audit system dropped {} message(s) (total {}, backlog {}). Consider raising backlog_limit.",
                                    status.lost - last_lost, status.lost, status.backlog
                                );
                            }
                            last_lost = status.lost;

                            if backend.uses_audit() {
                                if status.is_enabled() {
                                    // Full rule list diff
                                    self.apply_rules(&status).await;
                                } else {
                                    error!("Audit was disabled while in use as the monitoring backend (possible tampering).");
                                }
                            }
                        }
                        None if backend.uses_audit() => {
                            error!("Audit status unavailable while audit is the monitoring backend.");
                        }
                        None => {}
                    }
                }
                _ = canary_ticker.tick() => {
                    self.canary_tick(&mut last_canary_write).await;
                }
                _ = module_ticker.tick() => {
                    self.check_modules(&mut last_tainted, &mut last_modules).await;
                }
                _ = hash_ticker.tick() => {
                    // Periodic hash rescan of watched paths
                    self.rescan_hashes(&mut hashes).await;
                }
            }
        }
    }

    /// Verifies the previous canary write was observed, then writes a new one.
    async fn canary_tick(&self, last_write: &mut Option<Instant>) {
        let backend = self.backend().await;
        if let Some(written) = *last_write {
            if backend.uses_audit() {
                let seen = *lock(&self.last_canary_seen);
                if !matches!(seen, Some(s) if s >= written) {
                    error!(
                        "Canary written {:?} ago was never observed via {:?}: audit pipeline may be blinded.",
                        written.elapsed(),
                        backend
                    );
                }
            }
        }

        // Take the timestamp before writing so a fast event can't arrive "before" the write.
        let now = Instant::now();
        match self.write_canary().await {
            Ok(()) => *last_write = Some(now),
            Err(e) => error!("Failed to write canary file {}: {}", self.canary_path, e),
        }
    }

    async fn write_canary(&self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            // Refuse to follow a planted symlink.
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.canary_path)
            .await?;
        f.write_all(b"canary").await?;
        f.flush().await
    }

    /// BLAKE3-hashes every regular file under the watchlist and reports changes that no
    /// audit/fanotify event accounts for ("unattributed change"). Returns those paths.
    async fn rescan_hashes(&self, state: &mut HashState) -> Vec<PathBuf> {
        let scan_started = Instant::now();
        let watchlist = self.watchlist();
        let current = match tokio::task::spawn_blocking(move || hash_watchlist(&watchlist)).await {
            Ok(current) => current,
            Err(e) => {
                error!("Hash rescan task failed: {}", e);
                return Vec::new();
            }
        };

        let mut unattributed = Vec::new();
        if let Some(prev_scan) = state.last_scan {
            let mut changes: Vec<(&Path, &str, &'static str)> = Vec::new();
            for (path, cur) in &current {
                match state.baseline.get(path) {
                    Some(old) if old.hash == cur.hash => {}
                    Some(_) => changes.push((path, &cur.watch, "modified")),
                    None => changes.push((path, &cur.watch, "created")),
                }
            }
            for (path, old) in &state.baseline {
                if !current.contains_key(path) {
                    changes.push((path, &old.watch, "deleted"));
                }
            }

            let activity = lock(&self.last_activity).clone();
            for (path, watch, change) in changes {
                if activity.get(watch).is_some_and(|t| *t >= prev_scan) {
                    debug!("{} {} (accounted for by monitored activity)", path.display(), change);
                    continue;
                }
                self.emit(Finding {
                    kind: "unattributed_change",
                    path: path.display().to_string(),
                    detail: format!("file {change} with no matching file-access event"),
                    ..Finding::default()
                });
                unattributed.push(path.to_path_buf());
            }
        } else {
            info!("Hash baseline established for {} file(s).", current.len());
        }

        state.baseline = current;
        state.last_scan = Some(scan_started);
        unattributed
    }

    // =========================================================================
    // Netlink control operations
    // =========================================================================

    async fn get_audit_status(&self) -> Option<AuditStatus> {
        let result = time::timeout(NETLINK_TIMEOUT, async {
            let mut sock = AuditSocket::open()?;
            sock.get_status().await
        })
        .await;

        match result {
            Ok(Ok(s)) => Some(AuditStatus {
                enabled: s.enabled,
                pid: s.pid,
                lost: s.lost,
                backlog: s.backlog,
            }),
            Ok(Err(e)) => {
                debug!("AUDIT_GET failed: {}", e);
                None
            }
            Err(_) => {
                warn!("AUDIT_GET timed out");
                None
            }
        }
    }

    fn test_multicast_bind(&self) -> bool {
        match AuditSocket::probe_multicast() {
            Ok(()) => true,
            Err(e) => {
                debug!("Cannot join audit multicast group: {}", e);
                false
            }
        }
    }

    /// Lists the kernel's rules via AUDIT_LIST_RULES, in canonical form.
    async fn list_existing_rules(&self) -> anyhow::Result<HashSet<String>> {
        let rules = time::timeout(NETLINK_TIMEOUT, async {
            let mut sock = AuditSocket::open()?;
            sock.list_rules().await
        })
        .await
        .context("AUDIT_LIST_RULES timed out")?
        .context("AUDIT_LIST_RULES failed")?;

        Ok(rules
            .iter()
            .map(|r| canonical_rule(&rules::render(r)))
            .collect())
    }

    /// Converts `rule` to an audit_rule_data and sends AUDIT_ADD_RULE.
    async fn send_audit_add_rule(&self, rule: &str) -> anyhow::Result<()> {
        let msg = rules::build(rule)?;
        let result = time::timeout(NETLINK_TIMEOUT, async {
            let mut sock = AuditSocket::open()?;
            sock.add_rule(msg).await
        })
        .await
        .context("AUDIT_ADD_RULE timed out")?;

        match result {
            Ok(()) => Ok(()),
            // Already present (e.g. added concurrently): that's the state we wanted.
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            Err(e) => Err(e).context("AUDIT_ADD_RULE failed"),
        }
    }

    // =========================================================================
    // Listeners
    // =========================================================================

    /// Reads audit records from the AUDIT_NLGRP_READLOG multicast group.
    async fn listen_multicast(&self, tx: mpsc::UnboundedSender<RawEvent>) -> anyhow::Result<()> {
        let mut sock = AuditSocket::open_multicast().context("joining audit multicast group")?;
        info!("Listening on audit multicast group.");
        loop {
            match sock.recv().await {
                Ok(messages) => {
                    for msg in messages {
                        if let Some(event) = netlink::audit_record(msg) {
                            tx.send(event).map_err(|_| anyhow!("event channel closed"))?;
                        }
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    warn!("Audit multicast receive buffer overflowed; some records were dropped.");
                }
                Err(e) => return Err(e).context("reading audit multicast socket"),
            }
        }
    }

    /// Tails /var/log/audit/audit.log, following rotation and truncation.
    async fn tail_audit_log(&self, tx: mpsc::UnboundedSender<RawEvent>) -> anyhow::Result<()> {
        use std::io::SeekFrom;
        use std::os::unix::fs::MetadataExt;
        use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

        async fn open_log(seek_end: bool) -> io::Result<(BufReader<tokio::fs::File>, u64)> {
            let mut file = tokio::fs::File::open(AUDIT_LOG).await?;
            let ino = file.metadata().await?.ino();
            if seek_end {
                file.seek(SeekFrom::End(0)).await?;
            }
            Ok((BufReader::new(file), ino))
        }

        // Start at the end: only new events matter, history was written before we started.
        let (mut reader, mut ino) = open_log(true).await.context("opening audit.log")?;
        info!("Tailing {}.", AUDIT_LOG);

        let send = |line: &str| -> anyhow::Result<()> {
            if let Some((kind, body)) = split_log_line(line) {
                tx.send(RawEvent::Audit { kind, body })
                    .map_err(|_| anyhow!("event channel closed"))?;
            }
            Ok(())
        };

        let mut line = String::new();
        loop {
            if reader.read_line(&mut line).await? > 0 {
                // A line without '\n' is still being written; keep it and read more.
                if line.ends_with('\n') {
                    send(line.trim_end())?;
                    line.clear();
                }
                continue;
            }

            // EOF: wait, then check for rotation or truncation.
            time::sleep(LOG_POLL).await;
            match tokio::fs::metadata(AUDIT_LOG).await {
                Ok(meta) if meta.ino() != ino => {
                    // Drain whatever was appended to the old file before it was rotated.
                    while reader.read_line(&mut line).await? > 0 {
                        if line.ends_with('\n') {
                            send(line.trim_end())?;
                            line.clear();
                        }
                    }
                    line.clear();
                    info!("audit.log rotated; reopening.");
                    (reader, ino) = open_log(false).await.context("reopening audit.log")?;
                }
                Ok(meta) => {
                    let pos = reader.stream_position().await?;
                    if meta.len() < pos {
                        info!("audit.log truncated; reading from the start.");
                        reader.seek(SeekFrom::Start(0)).await?;
                        line.clear();
                    }
                }
                // Between rotation and auditd creating the new file.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).context("stat audit.log"),
            }
        }
    }

    /// Registers as the audit daemon (AUDIT_SET with our PID) and reads records unicast.
    async fn listen_unicast_daemon(&self, tx: mpsc::UnboundedSender<RawEvent>) -> anyhow::Result<()> {
        let pid = std::process::id();
        let mut sock = AuditSocket::open()?;
        time::timeout(NETLINK_TIMEOUT, sock.set_daemon_pid(pid))
            .await
            .context("AUDIT_SET (register daemon) timed out")?
            .context("registering as audit daemon")?;
        info!("Registered as the audit daemon (pid {}).", pid);

        let result: anyhow::Result<()> = loop {
            match sock.recv().await {
                Ok(messages) => {
                    let mut closed = false;
                    for msg in messages {
                        if let Some(event) = netlink::audit_record(msg) {
                            if tx.send(event).is_err() {
                                closed = true;
                                break;
                            }
                        }
                    }
                    if closed {
                        break Err(anyhow!("event channel closed"));
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    warn!("Audit daemon socket overflowed; some records were dropped.");
                }
                Err(e) => break Err(anyhow::Error::new(e).context("reading audit daemon socket")),
            }
        };

        // Give the slot back so a real auditd (or our next negotiation) can take it.
        // The kernel also resets it on its own once sends to our closed socket fail.
        drop(sock);
        let release = time::timeout(NETLINK_TIMEOUT, async {
            let mut ctl = AuditSocket::open()?;
            ctl.set_daemon_pid(0).await
        })
        .await;
        match release {
            Ok(Ok(())) => info!("Released the audit daemon slot."),
            Ok(Err(e)) => warn!("Failed to release the audit daemon slot: {}", e),
            Err(_) => warn!("Timed out releasing the audit daemon slot."),
        }

        result
    }

    /// fanotify fallback: notification-class marks on every watchlist entry.
    async fn listen_fanotify(&self, tx: mpsc::UnboundedSender<RawEvent>) -> anyhow::Result<()> {
        use nix::fcntl::AT_FDCWD;
        use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
        use tokio::io::unix::AsyncFd;
        use tokio::io::Interest;

        let fan = Fanotify::init(
            InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC | InitFlags::FAN_NONBLOCK,
            EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE | EventFFlags::O_CLOEXEC,
        )
        .context("fanotify_init (needs CAP_SYS_ADMIN)")?;

        // Adds FAN marks for any tracked path not already marked. Called once up front and
        // again on a tick so paths added at runtime start being watched.
        let mark_new = |fan: &Fanotify, already: &mut HashSet<String>| -> usize {
            let mut added = 0usize;
            for path in self.watchlist() {
                if already.contains(&path) {
                    continue;
                }
                let p = Path::new(&path);
                let mut mask = MaskFlags::FAN_MODIFY | MaskFlags::FAN_CLOSE_WRITE;
                if is_secret(&path) {
                    mask |= MaskFlags::FAN_OPEN;
                }
                if p.is_dir() {
                    mask |= MaskFlags::FAN_EVENT_ON_CHILD;
                }
                match fan.mark(MarkFlags::FAN_MARK_ADD, mask, AT_FDCWD, Some(p)) {
                    Ok(()) => {
                        already.insert(path);
                        added += 1;
                    }
                    Err(e) => self.warn_once(
                        &format!("fanotify:{path}"),
                        &format!("fanotify_mark failed for {path}: {e}"),
                    ),
                }
            }
            added
        };

        let mut marked: HashSet<String> = HashSet::new();
        if mark_new(&fan, &mut marked) == 0 {
            bail!("no watchlist path could be marked with fanotify");
        }
        info!("fanotify watching {} path(s).", marked.len());

        let fan = AsyncFd::with_interest(fan, Interest::READABLE)?;
        let mut remark = ticker(Duration::from_secs(5));
        loop {
            let mut guard = tokio::select! {
                res = fan.readable() => res?,
                _ = remark.tick() => {
                    let added = mark_new(fan.get_ref(), &mut marked);
                    if added > 0 {
                        info!("fanotify now watching {} path(s).", marked.len());
                    }
                    continue;
                }
            };
            let events = match guard.try_io(|inner| inner.get_ref().read_events().map_err(io::Error::from)) {
                Ok(result) => result?,
                Err(_would_block) => continue,
            };

            for event in events {
                let mask = event.mask();
                if mask.contains(MaskFlags::FAN_Q_OVERFLOW) {
                    warn!("fanotify queue overflowed; events were lost.");
                    continue;
                }
                let Some(fd) = event.fd() else { continue };
                // The event carries an open fd for the file; its /proc link is the path.
                let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<unknown>".to_owned());

                let mut names = Vec::new();
                for (flag, name) in [
                    (MaskFlags::FAN_MODIFY, "modify"),
                    (MaskFlags::FAN_CLOSE_WRITE, "close_write"),
                    (MaskFlags::FAN_OPEN, "open"),
                    (MaskFlags::FAN_ACCESS, "access"),
                ] {
                    if mask.contains(flag) {
                        names.push(name);
                    }
                }

                tx.send(RawEvent::Fanotify { path, pid: event.pid(), mask: names.join("|") })
                    .map_err(|_| anyhow!("event channel closed"))?;
                // `event` drops here, closing its fd.
            }
        }
    }
}

// =============================================================================
// Event processing
// =============================================================================

#[derive(Debug, Default)]
struct Finding {
    kind: &'static str,
    path: String,
    pid: u32,
    ppid: String,
    uid: String,
    auid: String,
    exe: String,
    comm: String,
    cmdline: String,
    syscall: String,
    success: String,
    detail: String,
}

impl Finding {
    fn emit(&self) {
        warn!(
            target: "ch_monitor::finding",
            kind = self.kind,
            path = %self.path,
            pid = self.pid,
            ppid = %self.ppid,
            uid = %self.uid,
            auid = %self.auid,
            exe = %self.exe,
            comm = %self.comm,
            cmdline = %self.cmdline,
            syscall = %self.syscall,
            success = %self.success,
            "{}",
            self.detail
        );
    }
}

type Record = (String, HashMap<String, String>);

struct PendingGroup {
    first_seen: Instant,
    records: Vec<Record>,
}

/// Groups audit records by event serial, filters to our key, enriches from /proc, and
/// emits findings. Also feeds the canary and hash-attribution state.
struct EventProcessor {
    engine: AuditEngine,
    own_pid: u32,
    pending: HashMap<u64, PendingGroup>,
    recent: HashMap<(&'static str, String, u32), Instant>,
}

impl EventProcessor {
    fn new(engine: AuditEngine) -> Self {
        Self {
            engine,
            own_pid: std::process::id(),
            pending: HashMap::new(),
            recent: HashMap::new(),
        }
    }

    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<RawEvent>) {
        let mut tick = ticker(Duration::from_millis(500));
        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Some(event) => self.handle(event),
                    None => break,
                },
                _ = tick.tick() => self.housekeeping(),
            }
        }
        // Senders gone: flush what's left.
        let serials: Vec<u64> = self.pending.keys().copied().collect();
        for serial in serials {
            self.flush(serial);
        }
    }

    fn handle(&mut self, event: RawEvent) {
        match event {
            RawEvent::Audit { kind, body } => {
                let Some(serial) = record_serial(&body) else {
                    debug!("Unparseable audit record: {} {}", kind, body);
                    return;
                };
                let is_eoe = kind == "EOE";
                let group = self.pending.entry(serial).or_insert_with(|| PendingGroup {
                    first_seen: Instant::now(),
                    records: Vec::new(),
                });
                if !is_eoe {
                    group.records.push((kind, parse_fields(&body)));
                }
                if is_eoe {
                    self.flush(serial);
                } else if self.pending.len() > MAX_PENDING_GROUPS {
                    if let Some(oldest) = self
                        .pending
                        .iter()
                        .min_by_key(|(_, g)| g.first_seen)
                        .map(|(s, _)| *s)
                    {
                        self.flush(oldest);
                    }
                }
            }
            RawEvent::Fanotify { path, pid, mask } => {
                let pid = u32::try_from(pid).unwrap_or(0);
                if pid == self.own_pid {
                    return;
                }
                self.engine.note_activity(std::slice::from_ref(&path));
                let mut finding = Finding {
                    kind: "file_access",
                    path,
                    pid,
                    syscall: mask,
                    detail: "watched file accessed (fanotify)".to_owned(),
                    ..Finding::default()
                };
                enrich_from_proc(&mut finding);
                self.report(finding);
            }
        }
    }

    fn housekeeping(&mut self) {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, g)| g.first_seen.elapsed() >= GROUP_FLUSH_AFTER)
            .map(|(s, _)| *s)
            .collect();
        for serial in expired {
            self.flush(serial);
        }
        self.recent.retain(|_, t| t.elapsed() < DEDUP_WINDOW);
    }

    fn flush(&mut self, serial: u64) {
        let Some(group) = self.pending.remove(&serial) else { return };
        let records = group.records;
        let find = |kind: &str| records.iter().find(|(k, _)| k == kind).map(|(_, f)| f);

        // Tamper signal: someone removing rules or disabling audit (we never do either).
        if let Some(cc) = find("CONFIG_CHANGE") {
            let op = cc.get("op").map(String::as_str).unwrap_or("");
            let disabled = cc.get("audit_enabled").is_some_and(|v| v == "0");
            if op.contains("remove_rule") || disabled {
                self.report(Finding {
                    kind: "audit_config_change",
                    auid: cc.get("auid").cloned().unwrap_or_default(),
                    path: cc.get("key").cloned().unwrap_or_default(),
                    detail: format!(
                        "audit configuration changed: op={op} list={} res={}{}",
                        cc.get("list").map(String::as_str).unwrap_or("-"),
                        cc.get("res").map(String::as_str).unwrap_or("-"),
                        if disabled { " (audit disabled)" } else { "" },
                    ),
                    ..Finding::default()
                });
            }
        }

        let Some(sc) = find("SYSCALL") else { return };
        let ours = sc
            .get("key")
            .is_some_and(|k| k.split('\u{1}').any(|k| k == AUDIT_KEY));
        if !ours {
            return;
        }

        let cwd = find("CWD").and_then(|f| f.get("cwd")).map(String::as_str);
        let paths: Vec<String> = records
            .iter()
            .filter(|(k, f)| k == "PATH" && f.get("nametype").is_none_or(|t| t != "PARENT"))
            .filter_map(|(_, f)| f.get("name"))
            .map(|name| absolutize(name, cwd))
            .collect();

        // Canary first: our own write, but it is exactly what we need to see.
        if paths.contains(&self.engine.canary_path) {
            *lock(&self.engine.last_canary_seen) = Some(Instant::now());
            return;
        }

        let pid: u32 = sc.get("pid").and_then(|p| p.parse().ok()).unwrap_or(0);
        if pid == self.own_pid {
            // Our own hash rescans read watched files; that isn't a finding.
            return;
        }

        self.engine.note_activity(&paths);

        let module_name = find("KERN_MODULE").and_then(|f| f.get("name")).cloned();
        let syscall_name = rules::syscall_name(
            sc.get("arch").map(String::as_str),
            sc.get("syscall").map(String::as_str),
        );
        let is_module = module_name.is_some()
            || syscall_name.is_some_and(|n| rules::MODULE_SYSCALLS.contains(&n));

        let mut finding = Finding {
            kind: if is_module { "kernel_module" } else { "file_access" },
            path: if is_module {
                module_name.unwrap_or_default()
            } else {
                paths.join(",")
            },
            pid,
            ppid: sc.get("ppid").cloned().unwrap_or_default(),
            uid: sc.get("uid").cloned().unwrap_or_default(),
            auid: sc.get("auid").cloned().unwrap_or_default(),
            exe: sc.get("exe").cloned().unwrap_or_default(),
            comm: sc.get("comm").cloned().unwrap_or_default(),
            cmdline: find("PROCTITLE")
                .and_then(|f| f.get("proctitle"))
                .cloned()
                .unwrap_or_default(),
            syscall: syscall_name
                .map(str::to_owned)
                .or_else(|| sc.get("syscall").cloned())
                .unwrap_or_default(),
            success: sc.get("success").cloned().unwrap_or_default(),
            detail: if is_module {
                "kernel module load/unload".to_owned()
            } else {
                "watched file accessed".to_owned()
            },
        };
        enrich_from_proc(&mut finding);
        self.report(finding);
    }

    fn report(&mut self, finding: Finding) {
        let key = (finding.kind, finding.path.clone(), finding.pid);
        if self.recent.get(&key).is_some_and(|t| t.elapsed() < DEDUP_WINDOW) {
            return;
        }
        self.recent.insert(key, Instant::now());
        self.engine.emit(finding);
    }
}

/// Fills fields the event didn't carry from /proc (the process may already be gone).
fn enrich_from_proc(f: &mut Finding) {
    if f.pid == 0 {
        return;
    }
    let pid = f.pid;
    if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        if !raw.is_empty() {
            f.cmdline = String::from_utf8_lossy(&raw)
                .trim_end_matches('\0')
                .replace('\0', " ");
        }
    }
    if f.exe.is_empty() {
        if let Ok(p) = std::fs::read_link(format!("/proc/{pid}/exe")) {
            f.exe = p.display().to_string();
        }
    }
    if f.comm.is_empty() {
        if let Ok(c) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            f.comm = c.trim_end().to_owned();
        }
    }
    if f.ppid.is_empty() || f.uid.is_empty() {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            for line in status.lines() {
                if let Some(v) = line.strip_prefix("PPid:") {
                    if f.ppid.is_empty() {
                        f.ppid = v.trim().to_owned();
                    }
                } else if let Some(v) = line.strip_prefix("Uid:") {
                    if f.uid.is_empty() {
                        f.uid = v.split_whitespace().next().unwrap_or("").to_owned();
                    }
                }
            }
        }
    }
    if f.auid.is_empty() {
        if let Ok(a) = std::fs::read_to_string(format!("/proc/{pid}/loginuid")) {
            f.auid = a.trim().to_owned();
        }
    }
}

/// Splits an audit.log line (`[node=X ]type=KIND msg=audit(...): ...`) into kind and body.
fn split_log_line(line: &str) -> Option<(String, String)> {
    let start = line.find("type=")?;
    let rest = &line[start + "type=".len()..];
    let (kind, rest) = rest.split_once(' ')?;
    let body = rest.trim_start().strip_prefix("msg=")?;
    Some((kind.to_owned(), body.to_owned()))
}

/// Extracts the event serial from `audit(<sec>.<ms>:<serial>): ...`.
fn record_serial(body: &str) -> Option<u64> {
    let inner = body.strip_prefix("audit(")?;
    let end = inner.find(')')?;
    let (_, serial) = inner[..end].split_once(':')?;
    serial.parse().ok()
}

/// Fields the kernel hex-encodes when they contain spaces, quotes or control chars.
const HEX_FIELDS: &[&str] = &["name", "cwd", "exe", "comm", "proctitle", "key", "path"];

/// Parses `k=v` pairs from an audit record body. Handles `"quoted"` and `'quoted'`
/// values, hex-encoded fields, and the 0x1d separator of ENRICHED logs.
fn parse_fields(body: &str) -> HashMap<String, String> {
    let s = body.find("): ").map_or(body, |i| &body[i + 3..]);
    let b = s.as_bytes();
    let is_sep = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | 0x1d);
    let mut out = HashMap::new();
    let mut i = 0;

    while i < b.len() {
        while i < b.len() && is_sep(b[i]) {
            i += 1;
        }
        let key_start = i;
        while i < b.len() && b[i] != b'=' && !is_sep(b[i]) {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            continue; // bare token
        }
        let key = &s[key_start..i];
        i += 1;

        let (value, quoted) = if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
            let quote = b[i];
            i += 1;
            let start = i;
            while i < b.len() && b[i] != quote {
                i += 1;
            }
            let v = &s[start..i];
            i = (i + 1).min(b.len());
            (v, true)
        } else {
            let start = i;
            while i < b.len() && !is_sep(b[i]) {
                i += 1;
            }
            (&s[start..i], false)
        };

        let value = if !quoted && HEX_FIELDS.contains(&key) {
            decode_hex(value).unwrap_or_else(|| value.to_owned())
        } else {
            value.to_owned()
        };
        out.entry(key.to_owned()).or_insert(value);
    }
    out
}

fn decode_hex(s: &str) -> Option<String> {
    let pairs = s.as_bytes().chunks_exact(2);
    if s.is_empty() || !pairs.remainder().is_empty() || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Option<Vec<u8>> = pairs
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect();
    // proctitle is argv joined by NULs.
    Some(String::from_utf8_lossy(&bytes?).replace('\0', " "))
}

/// Makes `name` absolute against `cwd` and removes `.`/`..` lexically.
fn absolutize(name: &str, cwd: Option<&str>) -> String {
    let joined = match cwd {
        Some(cwd) if !name.starts_with('/') => Path::new(cwd).join(name),
        _ => PathBuf::from(name),
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out.display().to_string()
}

fn is_secret(path: &str) -> bool {
    path.contains("shadow") || path.contains("sshd_config")
}

// =============================================================================
// Integrity helpers
// =============================================================================

struct FileHash {
    watch: String,
    hash: blake3::Hash,
}

#[derive(Default)]
struct HashState {
    baseline: HashMap<PathBuf, FileHash>,
    last_scan: Option<Instant>,
}

/// Hashes every regular file under the watchlist (blocking; run on a blocking thread).
fn hash_watchlist(watchlist: &[String]) -> HashMap<PathBuf, FileHash> {
    let mut out = HashMap::new();
    for watch in watchlist {
        let mut stack = vec![(PathBuf::from(watch), 0usize)];
        while let Some((path, depth)) = stack.pop() {
            if out.len() >= HASH_MAX_FILES {
                warn!("Hash rescan stopped at {} files; narrow the watchlist.", HASH_MAX_FILES);
                return out;
            }
            // Follow a symlink only if it is the watchlist entry itself.
            let meta = if depth == 0 {
                std::fs::metadata(&path)
            } else {
                std::fs::symlink_metadata(&path)
            };
            let Ok(meta) = meta else { continue };

            if meta.is_dir() {
                if depth >= HASH_MAX_DEPTH {
                    continue;
                }
                if let Ok(entries) = std::fs::read_dir(&path) {
                    stack.extend(entries.flatten().map(|e| (e.path(), depth + 1)));
                }
            } else if meta.is_file() {
                match hash_file(&path, depth > 0) {
                    Ok(hash) => {
                        out.insert(path, FileHash { watch: watch.clone(), hash });
                    }
                    Err(e) => debug!("Cannot hash {}: {}", path.display(), e),
                }
            }
        }
    }
    out
}

fn hash_file(path: &Path, no_follow: bool) -> io::Result<blake3::Hash> {
    use std::os::unix::fs::OpenOptionsExt;

    // O_NONBLOCK: if the file was swapped for a FIFO since the stat, don't hang on it.
    let mut flags = libc::O_NONBLOCK;
    if no_follow {
        flags |= libc::O_NOFOLLOW;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    let mut hasher = blake3::Hasher::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(hasher.finalize())
}

/// Interval that doesn't burst-fire missed ticks after a slow iteration.
fn ticker(period: Duration) -> time::Interval {
    let mut t = time::interval(period);
    t.set_missed_tick_behavior(MissedTickBehavior::Delay);
    t
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_r<T>(m: &RwLockStd<T>) -> RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_w<T>(m: &RwLockStd<T>) -> RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Maps a finding kind to an operator-facing severity.
fn severity_for(kind: &str) -> AlertSeverity {
    match kind {
        "unattributed_change" | "kernel_module" | "audit_config_change" => AlertSeverity::Critical,
        "file_access" | "module_list_change" => AlertSeverity::Warn,
        _ => AlertSeverity::Info,
    }
}

/// Reports kernel taint changes and modules appearing/disappearing in /proc/modules.
impl AuditEngine {
    async fn check_modules(
        &self,
        last_tainted: &mut Option<String>,
        last_modules: &mut Option<HashSet<String>>,
    ) {
    if let Ok(tainted) = tokio::fs::read_to_string("/proc/sys/kernel/tainted").await {
        let tainted = tainted.trim().to_owned();
        if last_tainted.as_deref() != Some(tainted.as_str()) {
            if tainted != "0" {
                warn!("Kernel is tainted: {}", tainted);
            }
            *last_tainted = Some(tainted);
        }
    }

    if let Ok(modules) = tokio::fs::read_to_string("/proc/modules").await {
        let current: HashSet<String> = modules
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(str::to_owned)
            .collect();
        if let Some(prev) = last_modules.as_ref() {
            for m in current.difference(prev) {
                self.emit(Finding {
                    kind: "module_list_change",
                    path: m.clone(),
                    detail: "kernel module appeared in /proc/modules".to_owned(),
                    ..Finding::default()
                });
            }
            for m in prev.difference(&current) {
                self.emit(Finding {
                    kind: "module_list_change",
                    path: m.clone(),
                    detail: "kernel module disappeared from /proc/modules".to_owned(),
                    ..Finding::default()
                });
            }
        }
        *last_modules = Some(current);
    }
    }
}

// =============================================================================
// Rule text <-> audit_rule_data
// =============================================================================

/// Canonical form used to compare rules.
///
/// The kernel does not echo rules back the way they were written: `-k K` comes back as
/// `-F key=K`, `-w P -p wa` as `-F path=P -F perm=wa`, and syscall lists in number order.
/// Comparing raw strings therefore never matches, and every rule gets re-sent every pass.
fn canonical_rule(rule: &str) -> String {
    let mut action: Option<String> = None;
    let mut watch: Option<String> = None;
    let mut perms: BTreeSet<char> = BTreeSet::new();
    let mut syscalls: BTreeSet<String> = BTreeSet::new();
    let mut fields: BTreeSet<String> = BTreeSet::new();

    let mut toks = rule.split_whitespace();
    while let Some(tok) = toks.next() {
        match tok {
            "-a" | "-A" => {
                if let Some(a) = toks.next() {
                    let mut parts: Vec<&str> = a.split(',').collect();
                    parts.sort_unstable();
                    action = Some(parts.join(","));
                }
            }
            "-w" => watch = toks.next().map(str::to_owned),
            "-p" => perms.extend(toks.next().unwrap_or("").chars()),
            "-S" => syscalls.extend(
                toks.next()
                    .unwrap_or("")
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            ),
            "-k" => {
                if let Some(k) = toks.next() {
                    fields.insert(format!("key={k}"));
                }
            }
            "-F" => {
                if let Some(f) = toks.next() {
                    if let Some(p) = f.strip_prefix("perm=") {
                        perms.extend(p.chars());
                    } else if let Some(p) =
                        f.strip_prefix("path=").or_else(|| f.strip_prefix("dir="))
                    {
                        watch = Some(p.to_owned());
                    } else {
                        fields.insert(f.to_owned());
                    }
                }
            }
            other => {
                fields.insert(other.to_owned());
            }
        }
    }

    // A watch is an always,exit rule under the hood.
    if watch.is_some() && action.is_none() {
        action = Some("always,exit".to_owned());
    }

    format!(
        "a={}|w={}|p={}|S={}|F={}",
        action.unwrap_or_default(),
        watch.unwrap_or_default(),
        perms.into_iter().collect::<String>(),
        syscalls.into_iter().collect::<Vec<_>>().join(","),
        fields.into_iter().collect::<Vec<_>>().join(","),
    )
}

mod rules {
    use anyhow::{anyhow, bail};
    use netlink_packet_audit::{
        RuleAction, RuleField, RuleFieldFlags, RuleFlags, RuleMessage, RuleSyscalls,
        AUDIT_PERM_ATTR, AUDIT_PERM_EXEC, AUDIT_PERM_READ, AUDIT_PERM_WRITE,
    };

    /// One syscall ABI: its auditctl name, AUDIT_ARCH_* value, and the syscall numbers we use.
    pub struct ArchSyscalls {
        pub name: &'static str,
        pub arch: u32,
        pub syscalls: &'static [(&'static str, u32)],
    }

    impl ArchSyscalls {
        fn number(&self, name: &str) -> Option<u32> {
            self.syscalls.iter().find(|(n, _)| *n == name).map(|(_, nr)| *nr)
        }

        fn name_of(&self, nr: u32) -> Option<&'static str> {
            self.syscalls.iter().find(|(_, n)| *n == nr).map(|(name, _)| *name)
        }
    }

    /// Bits in a full mask minus the last 32-bit word.
    const ALL_SYSCALLS_THRESHOLD: usize = 2048 - 32;

    pub const MODULE_SYSCALLS: [&str; 3] = ["init_module", "finit_module", "delete_module"];

    #[cfg(target_arch = "x86_64")]
    pub const ARCHES: &[ArchSyscalls] = &[
        ArchSyscalls {
            name: "b64",
            arch: netlink_packet_audit::AUDIT_ARCH_X86_64,
            syscalls: &[("init_module", 175), ("delete_module", 176), ("finit_module", 313)],
        },
        ArchSyscalls {
            name: "b32",
            arch: netlink_packet_audit::AUDIT_ARCH_I386,
            syscalls: &[("init_module", 128), ("delete_module", 129), ("finit_module", 350)],
        },
    ];

    #[cfg(target_arch = "aarch64")]
    pub const ARCHES: &[ArchSyscalls] = &[
        ArchSyscalls {
            name: "b64",
            arch: netlink_packet_audit::AUDIT_ARCH_AARCH64,
            syscalls: &[("init_module", 105), ("delete_module", 106), ("finit_module", 273)],
        },
        ArchSyscalls {
            name: "b32",
            arch: netlink_packet_audit::AUDIT_ARCH_ARM,
            syscalls: &[("init_module", 128), ("delete_module", 129), ("finit_module", 379)],
        },
    ];

    /// Other architectures: file watches still work; module-syscall rules are skipped.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub const ARCHES: &[ArchSyscalls] = &[];

    /// Name of a syscall from a SYSCALL record's `arch=` (hex) and `syscall=` (decimal).
    pub fn syscall_name(arch: Option<&str>, syscall: Option<&str>) -> Option<&'static str> {
        let arch = u32::from_str_radix(arch?, 16).ok()?;
        let nr: u32 = syscall?.parse().ok()?;
        ARCHES.iter().find(|a| a.arch == arch)?.name_of(nr)
    }

    fn parse_perm(s: &str) -> anyhow::Result<u32> {
        let mut bits = 0;
        for c in s.chars() {
            bits |= match c {
                'r' => AUDIT_PERM_READ,
                'w' => AUDIT_PERM_WRITE,
                'x' => AUDIT_PERM_EXEC,
                'a' => AUDIT_PERM_ATTR,
                other => bail!("invalid permission {other:?}"),
            };
        }
        Ok(bits)
    }

    fn perm_string(bits: u32) -> String {
        [
            (AUDIT_PERM_READ, 'r'),
            (AUDIT_PERM_WRITE, 'w'),
            (AUDIT_PERM_EXEC, 'x'),
            (AUDIT_PERM_ATTR, 'a'),
        ]
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, c)| *c)
        .collect()
    }

    /// Builds an audit_rule_data from the auditctl-style subset this engine writes:
    /// `-w PATH -p PERMS -k KEY` and `-a always,exit -F arch=ABI -S a,b,c -k KEY`.
    pub fn build(rule: &str) -> anyhow::Result<RuleMessage> {
        let mut watch: Option<String> = None;
        let mut perm: Option<u32> = None;
        let mut key: Option<String> = None;
        let mut arch: Option<&ArchSyscalls> = None;
        let mut syscalls: Vec<String> = Vec::new();
        let mut is_exit_rule = false;

        let mut toks = rule.split_whitespace();
        while let Some(tok) = toks.next() {
            let mut value = || {
                toks.next()
                    .ok_or_else(|| anyhow!("`{tok}` needs a value in rule `{rule}`"))
            };
            match tok {
                "-w" => watch = Some(value()?.to_owned()),
                "-p" => perm = Some(parse_perm(value()?)?),
                "-k" => key = Some(value()?.to_owned()),
                "-a" => {
                    let mut parts: Vec<&str> = value()?.split(',').collect();
                    parts.sort_unstable();
                    if parts != ["always", "exit"] {
                        bail!("only `-a always,exit` is supported, in rule `{rule}`");
                    }
                    is_exit_rule = true;
                }
                "-F" => {
                    let field = value()?;
                    let (k, v) = field
                        .split_once('=')
                        .ok_or_else(|| anyhow!("bad field `{field}` in rule `{rule}`"))?;
                    match k {
                        "arch" => {
                            arch = Some(
                                ARCHES
                                    .iter()
                                    .find(|a| a.name == v)
                                    .ok_or_else(|| anyhow!("arch `{v}` unsupported on this platform"))?,
                            )
                        }
                        "key" => key = Some(v.to_owned()),
                        "perm" => perm = Some(parse_perm(v)?),
                        "path" | "dir" => watch = Some(v.to_owned()),
                        other => bail!("unsupported field `{other}` in rule `{rule}`"),
                    }
                }
                "-S" => syscalls.extend(
                    value()?
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                ),
                other => bail!("unsupported token `{other}` in rule `{rule}`"),
            }
        }

        let mut msg = RuleMessage::new();
        msg.flags = RuleFlags::FilterExit;
        msg.action = RuleAction::Always;

        if let Some(path) = watch {
            if arch.is_some() || !syscalls.is_empty() {
                bail!("watch rules with arch/syscalls are not supported: `{rule}`");
            }
            if !path.starts_with('/') || (path.len() > 1 && path.ends_with('/')) {
                bail!("watch path must be absolute without a trailing '/': `{path}`");
            }
            // Same as auditctl: a watch applies to all syscalls, filtered by permission.
            msg.syscalls = RuleSyscalls::new_maxed();
            let is_dir = std::fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false);
            let field = if is_dir { RuleField::Dir(path) } else { RuleField::Watch(path) };
            msg.fields.push((field, RuleFieldFlags::Equal));
            let perm = perm.unwrap_or(AUDIT_PERM_READ | AUDIT_PERM_WRITE | AUDIT_PERM_EXEC | AUDIT_PERM_ATTR);
            msg.fields.push((RuleField::Perm(perm), RuleFieldFlags::Equal));
        } else {
            if !is_exit_rule {
                bail!("rule needs `-w` or `-a always,exit`: `{rule}`");
            }
            let arch = arch.ok_or_else(|| anyhow!("syscall rules need `-F arch=`: `{rule}`"))?;
            if syscalls.is_empty() {
                bail!("syscall rule without `-S`: `{rule}`");
            }
            let mut mask = RuleSyscalls::new_zeroed();
            for name in &syscalls {
                let nr = arch
                    .number(name)
                    .ok_or_else(|| anyhow!("unknown syscall `{name}` for arch {}", arch.name))?;
                mask.set(nr);
            }
            msg.syscalls = mask;
            msg.fields.push((RuleField::Arch(arch.arch), RuleFieldFlags::Equal));
        }

        if let Some(key) = key {
            msg.fields.push((RuleField::Filterkey(key), RuleFieldFlags::Equal));
        }
        Ok(msg)
    }

    /// Renders a kernel rule as auditctl-style text (input for `canonical_rule`).
    pub fn render(rule: &RuleMessage) -> String {
        let action = match rule.action {
            RuleAction::Always => "always",
            RuleAction::Never => "never",
            RuleAction::Possible => "possible",
            _ => "unknown",
        };
        let list = match rule.flags {
            RuleFlags::FilterExit => "exit",
            RuleFlags::FilterTask => "task",
            RuleFlags::FilterUser => "user",
            RuleFlags::FilterType => "exclude",
            RuleFlags::FilterFs => "filesystem",
            _ => "other",
        };
        let mut parts = vec![format!("-a {action},{list}")];

        let arch = rule.fields.iter().find_map(|(f, _)| match f {
            RuleField::Arch(a) => ARCHES.iter().find(|x| x.arch == *a),
            _ => None,
        });

        for (field, flags) in &rule.fields {
            let op = match flags {
                RuleFieldFlags::Equal => "=",
                RuleFieldFlags::NotEqual => "!=",
                RuleFieldFlags::LessThan => "<",
                RuleFieldFlags::GreaterThan => ">",
                RuleFieldFlags::LessThanOrEqual => "<=",
                RuleFieldFlags::GreaterThanOrEqual => ">=",
                RuleFieldFlags::BitMask => "&",
                RuleFieldFlags::BitTest => "&=",
                _ => "?",
            };
            let kv = match field {
                RuleField::Arch(a) => match ARCHES.iter().find(|x| x.arch == *a) {
                    Some(x) => format!("arch{op}{}", x.name),
                    None => format!("arch{op}{a:#x}"),
                },
                RuleField::Watch(p) => format!("path{op}{p}"),
                RuleField::Dir(p) => format!("dir{op}{p}"),
                RuleField::Perm(p) => format!("perm{op}{}", perm_string(*p)),
                RuleField::Filterkey(k) => format!("key{op}{k}"),
                // Fields we never write; any rendering that can't collide with ours works.
                other => format!("{other:?}{op}").replace(' ', "_"),
            };
            parts.push(format!("-F {kv}"));
        }

        // A watch applies to all syscalls, but the kernel lists the mask back with the top
        // bits (reserved for syscall classes) cleared, so `is_all()` is false. Treat a mask
        // covering nearly every syscall number as "all", like auditctl's `-S all`.
        let set_bits = (&rule.syscalls).into_iter().count();
        if set_bits < ALL_SYSCALLS_THRESHOLD {
            let names: Vec<String> = (&rule.syscalls)
                .into_iter()
                .map(|nr| {
                    arch.and_then(|a| a.name_of(nr))
                        .map_or_else(|| nr.to_string(), str::to_owned)
                })
                .collect();
            if !names.is_empty() {
                parts.push(format!("-S {}", names.join(",")));
            }
        }

        parts.join(" ")
    }
}

// =============================================================================
// Netlink audit socket
// =============================================================================

mod netlink {
    use std::collections::VecDeque;
    use std::io;

    use netlink_packet_audit::{AuditMessage, RuleMessage, StatusMessage};
    use netlink_packet_core::{
        NetlinkBuffer, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
    };
    use netlink_sys::{
        protocols::NETLINK_AUDIT, AsyncSocket, AsyncSocketExt, Socket, SocketAddr, TokioSocket,
    };

    use super::RawEvent;

    const AUDIT_STATUS_PID: u32 = 0x0004;
    /// Multicast group number; `nl_groups` wants the bitmask `1 << (group - 1)`.
    const AUDIT_NLGRP_READLOG: u32 = 1;
    const MULTICAST_RCVBUF: libc::c_int = 8 * 1024 * 1024;

    type Message = NetlinkMessage<AuditMessage>;

    pub struct AuditSocket {
        sock: TokioSocket,
        seq: u32,
        /// Messages read while waiting for a reply that belong to someone else (events).
        backlog: VecDeque<Message>,
    }

    impl AuditSocket {
        /// A unicast socket for requests (and, after AUDIT_SET pid, daemon events).
        pub fn open() -> io::Result<Self> {
            let mut sock = TokioSocket::new(NETLINK_AUDIT)?;
            sock.socket_mut().bind_auto()?;
            Ok(Self { sock, seq: 0, backlog: VecDeque::new() })
        }

        /// A socket subscribed to the read-only log multicast group (needs CAP_AUDIT_READ).
        pub fn open_multicast() -> io::Result<Self> {
            let mut sock = TokioSocket::new(NETLINK_AUDIT)?;
            sock.socket_mut()
                .bind(&SocketAddr::new(0, 1 << (AUDIT_NLGRP_READLOG - 1)))?;
            // Bursts overflow the default buffer and the kernel drops records (ENOBUFS).
            if let Err(e) = sock.socket_ref().set_rx_buf_sz(MULTICAST_RCVBUF) {
                tracing::debug!("SO_RCVBUF on audit multicast socket: {}", e);
            }
            Ok(Self { sock, seq: 0, backlog: VecDeque::new() })
        }

        /// Checks that the multicast group can be joined, without keeping the socket.
        pub fn probe_multicast() -> io::Result<()> {
            let mut sock = Socket::new(NETLINK_AUDIT)?;
            sock.bind(&SocketAddr::new(0, 1 << (AUDIT_NLGRP_READLOG - 1)))
        }

        async fn send(&mut self, msg: AuditMessage, flags: u16) -> io::Result<u32> {
            self.seq = self.seq.wrapping_add(1).max(1);
            let mut header = NetlinkHeader::default();
            header.flags = flags;
            header.sequence_number = self.seq;
            let mut packet = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(msg));
            packet.finalize();
            let mut buf = vec![0u8; packet.buffer_len()];
            packet.serialize(&mut buf);
            self.sock.send_to(&buf, &SocketAddr::new(0, 0)).await?;
            Ok(self.seq)
        }

        async fn read_datagram(&mut self) -> io::Result<Vec<Message>> {
            let (mut data, _) = self.sock.recv_from_full().await?;
            Ok(decode_datagram(&mut data))
        }

        /// Next batch of messages: anything set aside while waiting for replies, else the socket.
        pub async fn recv(&mut self) -> io::Result<Vec<Message>> {
            if !self.backlog.is_empty() {
                return Ok(self.backlog.drain(..).collect());
            }
            self.read_datagram().await
        }

        /// Feeds replies to `seq` into `f` until it returns `Some`; other messages are kept.
        async fn wait_for<T>(
            &mut self,
            seq: u32,
            mut f: impl FnMut(NetlinkPayload<AuditMessage>) -> Option<io::Result<T>>,
        ) -> io::Result<T> {
            loop {
                let mut batch = self.read_datagram().await?.into_iter();
                while let Some(msg) = batch.next() {
                    if msg.header.sequence_number != seq {
                        self.backlog.push_back(msg);
                        continue;
                    }
                    if let Some(result) = f(msg.payload) {
                        self.backlog.extend(batch);
                        return result;
                    }
                }
            }
        }

        async fn wait_ack(&mut self, seq: u32) -> io::Result<()> {
            self.wait_for(seq, |payload| match payload {
                NetlinkPayload::Error(e) => Some(match e.code {
                    None => Ok(()),
                    Some(_) => Err(e.to_io()),
                }),
                _ => None,
            })
            .await
        }

        pub async fn get_status(&mut self) -> io::Result<StatusMessage> {
            let seq = self.send(AuditMessage::GetStatus(None), NLM_F_REQUEST).await?;
            self.wait_for(seq, |payload| match payload {
                NetlinkPayload::InnerMessage(AuditMessage::GetStatus(Some(s))) => Some(Ok(s)),
                NetlinkPayload::Error(e) if e.code.is_some() => Some(Err(e.to_io())),
                _ => None,
            })
            .await
        }

        pub async fn list_rules(&mut self) -> io::Result<Vec<RuleMessage>> {
            let seq = self.send(AuditMessage::ListRules(None), NLM_F_REQUEST).await?;
            let mut rules = Vec::new();
            self.wait_for(seq, |payload| match payload {
                NetlinkPayload::InnerMessage(AuditMessage::ListRules(Some(rule))) => {
                    rules.push(rule);
                    None
                }
                NetlinkPayload::Done(_) => Some(Ok(())),
                NetlinkPayload::Error(e) if e.code.is_some() => Some(Err(e.to_io())),
                _ => None,
            })
            .await?;
            Ok(rules)
        }

        pub async fn add_rule(&mut self, rule: RuleMessage) -> io::Result<()> {
            let seq = self
                .send(AuditMessage::AddRule(rule), NLM_F_REQUEST | NLM_F_ACK)
                .await?;
            self.wait_ack(seq).await
        }

        /// AUDIT_SET with AUDIT_STATUS_PID: our PID claims the daemon slot, 0 releases it.
        /// Events are then delivered to the socket that sent this.
        pub async fn set_daemon_pid(&mut self, pid: u32) -> io::Result<()> {
            let mut status = StatusMessage::new();
            status.mask = AUDIT_STATUS_PID;
            status.pid = pid;
            let seq = self
                .send(AuditMessage::SetStatus(status), NLM_F_REQUEST | NLM_F_ACK)
                .await?;
            self.wait_ack(seq).await
        }
    }

    /// Splits one datagram into netlink messages.
    ///
    /// Audit records are sent with an `nlmsg_len` that excludes the alignment padding
    /// (and on older kernels is short by more), so a message whose declared length runs
    /// to within 16 bytes of the end of the datagram is taken to be the rest of it.
    /// (`NetlinkAuditCodec` does the same, but logs a warning for every single record.)
    fn decode_datagram(data: &mut [u8]) -> Vec<Message> {
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let rest = &mut data[offset..];
            let remaining = rest.len();
            let declared = match NetlinkBuffer::new_checked(&*rest) {
                Ok(buf) => buf.length() as usize,
                Err(e) => {
                    tracing::debug!("Dropping malformed netlink data: {}", e);
                    break;
                }
            };
            let len = if remaining.saturating_sub(declared) <= 16 {
                NetlinkBuffer::new(&mut *rest).set_length(remaining as u32);
                remaining
            } else {
                (declared + 3) & !3
            };
            match NetlinkMessage::<AuditMessage>::deserialize(&rest[..len.min(remaining)]) {
                Ok(msg) => out.push(msg),
                Err(e) => tracing::debug!("Undecodable netlink audit message: {}", e),
            }
            offset += len.max(1);
        }
        out
    }

    /// Turns a netlink audit record into a `RawEvent` (ignores control replies).
    pub fn audit_record(msg: Message) -> Option<RawEvent> {
        match msg.payload {
            NetlinkPayload::InnerMessage(AuditMessage::Event((t, text)))
            | NetlinkPayload::InnerMessage(AuditMessage::Other((t, text))) => Some(RawEvent::Audit {
                kind: record_type_name(t),
                body: text,
            }),
            _ => None,
        }
    }

    /// Record type names as auditd writes them, for the types the processor cares about.
    fn record_type_name(t: u16) -> String {
        let name = match t {
            1300 => "SYSCALL",
            1302 => "PATH",
            1305 => "CONFIG_CHANGE",
            1307 => "CWD",
            1309 => "EXECVE",
            1320 => "EOE",
            1327 => "PROCTITLE",
            1330 => "KERN_MODULE",
            _ => return format!("UNKNOWN[{t}]"),
        };
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> AuditEngine {
        AuditEngine::new(
            vec!["/etc/shadow".into(), "/etc/ssh/sshd_config".into(), "/etc/passwd".into()],
            false,
        )
    }

    #[test]
    fn watch_matches_kernel_rendering() {
        assert_eq!(
            canonical_rule("-w /etc/shadow -p wa -k neccdc_fim"),
            canonical_rule("-a always,exit -F path=/etc/shadow -F perm=aw -F key=neccdc_fim"),
        );
    }

    #[test]
    fn syscall_order_is_ignored() {
        assert_eq!(
            canonical_rule("-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k k"),
            canonical_rule("-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -F key=k"),
        );
    }

    #[test]
    fn read_and_write_watches_differ() {
        assert_ne!(
            canonical_rule("-w /etc/shadow -p r -k k"),
            canonical_rule("-w /etc/shadow -p wa -k k"),
        );
    }

    /// What we send, read back as the kernel would list it, must match what we want;
    /// otherwise apply_rules would re-add every rule forever.
    #[test]
    fn built_rules_round_trip() {
        for rule in engine().desired_rules() {
            let msg = rules::build(&rule).unwrap();
            assert_eq!(
                canonical_rule(&rules::render(&msg)),
                canonical_rule(&rule),
                "rule: {rule}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_rules() {
        assert!(rules::build("-w relative/path -p wa").is_err());
        assert!(rules::build("-a never,exit -F arch=b64 -S init_module").is_err());
        assert!(rules::build("-w /etc/passwd -p z").is_err());
    }

    #[test]
    fn parses_log_lines_and_fields() {
        let line = "type=PATH msg=audit(1696526400.123:4567): item=0 name=\"/etc/shadow\" \
                    inode=12 nametype=NORMAL\u{1d}OUID=\"root\"";
        let (kind, body) = split_log_line(line).unwrap();
        assert_eq!(kind, "PATH");
        assert_eq!(record_serial(&body), Some(4567));
        let f = parse_fields(&body);
        assert_eq!(f["name"], "/etc/shadow");
        assert_eq!(f["nametype"], "NORMAL");
        assert_eq!(f["OUID"], "root");
    }

    #[test]
    fn decodes_hex_fields() {
        // name="/tmp/a b" is hex-encoded by the kernel because of the space.
        let f = parse_fields("audit(1.0:1): name=2F746D702F612062 proctitle=6C730061 key=\"k\"");
        assert_eq!(f["name"], "/tmp/a b");
        assert_eq!(f["proctitle"], "ls a");
        assert_eq!(f["key"], "k");
    }

    #[test]
    fn absolutizes_relative_paths() {
        assert_eq!(absolutize("../shadow", Some("/etc/ssh")), "/etc/shadow");
        assert_eq!(absolutize("./x", Some("/root")), "/root/x");
        assert_eq!(absolutize("/abs", Some("/root")), "/abs");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn names_module_syscalls() {
        assert_eq!(rules::syscall_name(Some("c000003e"), Some("313")), Some("finit_module"));
        assert_eq!(rules::syscall_name(Some("40000003"), Some("128")), Some("init_module"));
        assert_eq!(rules::syscall_name(Some("c000003e"), Some("2")), None);
    }

    #[tokio::test]
    async fn hash_changes_are_attributed() {
        let dir = std::env::temp_dir().join(format!("ch-monitor-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.conf");
        std::fs::write(&file, "1").unwrap();
        let watch = dir.display().to_string();
        let engine = AuditEngine::new(vec![watch], false);
        let mut state = HashState::default();

        assert!(engine.rescan_hashes(&mut state).await.is_empty(), "baseline");

        // Change with a matching event: attributed.
        std::fs::write(&file, "2").unwrap();
        engine.note_activity(&[file.display().to_string()]);
        assert!(engine.rescan_hashes(&mut state).await.is_empty());

        // Change with no event since the last scan: unattributed.
        std::fs::write(&file, "3").unwrap();
        assert_eq!(engine.rescan_hashes(&mut state).await, vec![file.clone()]);

        // Deletion with no event: unattributed.
        std::fs::remove_file(&file).unwrap();
        assert_eq!(engine.rescan_hashes(&mut state).await, vec![file]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn groups_records_and_tracks_canary() {
        let engine = engine();
        let mut p = EventProcessor::new(engine.clone());
        let canary = engine.canary_path.clone();
        let rec = |kind: &str, body: String| RawEvent::Audit { kind: kind.into(), body };
        p.handle(rec("SYSCALL", format!("audit(1.0:9): arch=c000003e syscall=257 pid=1 key=\"{AUDIT_KEY}\"")));
        p.handle(rec("PATH", format!("audit(1.0:9): item=0 name=\"{canary}\" nametype=NORMAL")));
        assert!(lock(&engine.last_canary_seen).is_none(), "not flushed before EOE");
        p.handle(rec("EOE", "audit(1.0:9): ".into()));
        assert!(lock(&engine.last_canary_seen).is_some());
        assert!(p.pending.is_empty());
    }
}