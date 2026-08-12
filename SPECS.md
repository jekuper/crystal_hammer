# Blue-Team Emergency Access & IR Tool - Feature Spec

Emergency/replacement-for-SSH tool deployed at competition start. SSH-like access,
compile-time embedded public keys, self-contained host defense and hunt tooling.
Design bias: **trust nothing on the box** (binaries may be trojaned) - parse `/proc`
and config files directly rather than shelling out to system tools.

---

## 1. Confirmed design decisions

- **Distro-agnostic**: works on RHEL, Ubuntu, Alpine, and other major distros. All
  behavior detects the environment rather than assuming it.
  - **Static, musl-linked binary** (Go `CGO_ENABLED=0`, or Rust
    `x86_64-unknown-linux-musl`). A glibc binary silently fails on Alpine - this is
    the detail that actually makes it distro-agnostic.
- **Compile-time embedded public keys** for client auth. Never embed a private key.
- **Single-Packet Authorization (SPA)** in front of the listener: the port does not
  respond at all until it sees a valid signed knock. Keeps the tool invisible to
  red-team scanning.
  - **No rate-limiting, no failed-auth lockout** - deliberately. Lockout is a
    self-DoS vector (red team spams bad knocks to lock the blue team out). SPA +
    strong signature crypto makes brute force infeasible, so lockout is pure downside.
- **Server key pinning / mutual auth**: client verifies the server's identity too, so
  red team can't stand up a fake listener and phish teammates onto it.
- **Firewall lockdown = allowlist, default-deny**, and:
  - Allowlist is **empty by default and must work when empty**. Empty means "only the
    tool itself is reachable," never "locked out."
  - The tool's own SPA/port allow-rule is inserted **first and atomically**, before any
    flush, so a flush can never strand access.
  - Outbound is default-deny except the tool's own connections (broadcast/self-update)
    and established/related return traffic (conntrack).
- **Anti-lockout / dead-man's switch**: applying lockdown arms an auto-revert timer
  (e.g. restore in 60s unless confirmed "keep").
- **Snapshot-based restore**: before touching the firewall, save the existing ruleset
  (`nft list ruleset` / `iptables-save`). Restore replays the exact snapshot rather
  than reconstructing rules.
- **Firewall backend detection**: detect and drive the active backend directly
  (nftables preferred, fall back to iptables-legacy); be aware of firewalld/ufw/awall.
- **Interactive UX**: default TUI / numbered-menu (pfSense style) plus fully
  interactive PTY shell (resize/SIGWINCH, job control). Build on an audited SSH
  transport lib (e.g. Go `x/crypto/ssh`) rather than rolling crypto/PTY handling.

---

## 2. Core commands (approved)

| Command | Notes / improvements |
|---|---|
| `shell` | Full interactive PTY. |
| `lockdown` | Allowlist default-deny; empty-safe; tool-rule inserted first; arms dead-man's switch. |
| `unlock` / `restore` | Renamed from "lock up" - restores the saved ruleset snapshot explicitly. |
| `info` | Expanded - see below. |
| `upload file` | Add hash verification + resume. |
| `download file` | Add hash verification + resume. |
| `upload & execute script` | Add hash verification; log to session audit. |

**Expanded `info`**: distro + kernel, firewall backend and current state, all listeners,
logged-in users, recent auth failures, and the health/status of the tool's own
persistence mechanisms.

---

## 3. Incident response / hunt commands

Self-contained, `/proc`-based, do not trust system binaries.

- `ports` - listening sockets with owning PID, process name, and binary path (from `/proc`).
- `conns` - established connections + conntrack table.
- `procs` - process tree; flag deleted/`memfd:` binaries, execution from `/tmp`,
  `/dev/shm`, `/var/tmp`, and orphaned/anomalous parents.
- `persistence` - one-shot sweep: `authorized_keys` everywhere, all crontabs + `at` +
  systemd timers/services, new/UID-0 accounts, sudoers, `/etc/ld.so.preload`,
  `rc.local`, `profile.d`, MOTD scripts, PAM modules, udev rules, kernel modules.
- `users` - who's logged in, tail of auth log, kill a session.
- `recent` - recently modified files under key dirs + SUID/SGID + capability sweep.
- `hunt` / `stealth` - no-open-port backdoor detection (see section 5).
- `baseline` / `diff` - snapshot state at start, diff later (feeds the alert engine, section 4).
- `attribute <pid>` / `dossier` - full "who did it" capture on a process (see section 10).
- `sentinel` - verify expected binaries own the scored ports (see section 11).
- `watchlist` - view/add/remove monitored file paths at runtime (see section 4).

---

## 4. Monitoring & alerting engine

Baseline-at-start + periodic poll + diff (portable default, no kernel deps). Optional
`fanotify` real-time layer on the highest-value files where supported. Baseline is
trust-on-first-use, so pair it with a one-time known-bad sweep at first run.

**Events to alert on:**

*Accounts & auth*
- New user in `/etc/passwd`; any UID changed to 0; user gaining a login shell.
- `/etc/shadow` change (password set/changed), esp. root/service accounts.
- `/etc/group` additions to `sudo`/`wheel`/`docker`/`lxd`.
- `sudoers` / `sudoers.d/*` edits.
- `authorized_keys` created/modified in any home, `/root`, or custom `AuthorizedKeysFile` paths.
- `sshd_config` changes - `PermitRootLogin`, `PasswordAuthentication`, and especially
  `AuthorizedKeysCommand` (invisible SSH backdoor).
- PAM (`/etc/pam.d/*`) and NSS (`/etc/nsswitch.conf`) edits.

*Privilege artifacts*
- New SUID/SGID binary anywhere.
- File **capabilities** added via `setcap` (`cap_setuid`, `cap_net_raw`, ...) - often missed.
- `chattr +i` immutable flag set on files that weren't immutable at baseline.

*Scheduled / boot execution*
- crontab changes (all users, `/etc/cron*`, `/var/spool/cron`), `at` jobs.
- systemd unit/timer created/modified (system + per-user), suspicious `ExecStart`.
- `rc.local`, init scripts, `/etc/ld.so.preload`, `LD_PRELOAD` in env/profiles.
- `/etc/profile.d/*`, shell rc files, `/etc/update-motd.d/*` (runs on login).
- udev rules; new kernel module in `/proc/modules`.

*Runtime / process*
- exe is `(deleted)` or `memfd:`; execution from `/tmp`, `/dev/shm`, `/var/tmp`.
- **Process-lineage anomalies** - shell/interpreter parented by `nginx`/`httpd`/
  `mysqld`/`postfix`, or unexpected root shell under PID 1 (webshell / injection tell).
- New listening socket; new webshell file under a served web root.

*Log tampering*
- `wtmp`/`btmp`/`auth.log`/`secure` shrinking or truncated; logging service stopped.

*File drops*
- **New binary dropped** - match on **ELF magic (`7F 45 4C 46`)**, not the `+x` bit (a
  payload isn't always executable at write time). Watch drop dirs (`/tmp`, `/dev/shm`,
  `/var/tmp`, home dirs, web roots) plus anywhere on the runtime watchlist. Flag ELFs not
  owned by the package manager.
- **New/changed webshell** under a served root (`.php`/`.jsp`/`.aspx`/`.py`).

**Detection backend & attribution.** Prefer **fanotify** - its event carries the
**actor's PID**, so a drop or a config edit arrives with "who wrote it" attached
(-> feeds section 10). Fall back to **auditd file-watches** (`-w path -p wa`), which also record
the actor. Last resort is **inotify or poll+hash**, which tells you *that* a file changed
but **not who** - so the poll path loses attribution. Use fanotify/auditd on the
highest-value paths.

### 4a. Runtime-editable watchlist

A config of file paths/globs monitored for modification, **editable while running** via
the `watchlist` command (add/remove/list), persisted across restarts, and reloaded
without downtime. Each entry is hashed; on change the alert includes a diff and the actor
PID (fanotify/auditd). Covers the config-troll class of attack - e.g. someone flipping a
router/service config, changing a UI language, or editing `sshd_config` - by letting you
declare exactly which critical files must never change unnoticed. Ships with sane
defaults (`shadow`, `sudoers`, `authorized_keys`, `sshd_config`, `ld.so.preload`, service
configs) and lets you add competition-specific paths on the fly.

---

## 5. No-open-port backdoor detection (`hunt` / `stealth`)

Principle: **if it can receive packets, the kernel has a delivery path - enumerate every
path.** One pass should cover:

1. **Packet/raw socket holders** - parse `/proc/net/packet`, `/proc/net/raw`,
   `/proc/net/raw6`; walk `/proc/*/fd`, resolve `socket:[inode]`, match inodes -> PID.
   Allowlist legit holders (`dhclient`, launched `tcpdump`); alert on the rest. Catches
   passive sniffer backdoors (cd00r/SAdoor lineage) and bpfdoor-style implants that show
   no listening port.
2. **BPF / XDP / tc enumeration** - loaded BPF progs, XDP progs on interfaces
   (`ip link` / netlink), tc filters, pinned progs under `/sys/fs/bpf`; flag non-baselined.
3. **Egress / beacon monitoring** - snapshot outbound connections; flag long-lived or
   periodic (beaconing) connections to non-baseline destinations. Egress allowlist both
   blocks and surfaces reverse shells.
4. **Process-lineage anomalies** - shells under service daemons; deleted/`memfd:` exe.
5. **Kernel module drift + hidden-PID cross-check** - new `/proc/modules` entries; brute
   PID scan vs `/proc` listing to reveal PIDs that respond but aren't listed (rootkit).
6. **Netfilter/nftables rule diff** - dump full ruleset, diff vs baseline (hidden accept
   rules for trigger packets).
7. **systemd socket-activation units** - enumerate `.socket` units where the port shows
   owned by systemd rather than the real handler.

---

## 6. Response / hardening commands

- `kill` by pid/name; `kick` all sessions except yours.
- `rotate` - back up then rotate/lock passwords, regenerate `authorized_keys`, disable
  SSH password auth.
- `service` - enable/disable/restart, abstracting `systemctl` / `rc-service` / `service`.
- **Auto-backup** of critical files (`passwd`, `shadow`, `sudoers`, web root) before any
  destructive change.

---

## 7. Self-preservation

- **Watchdog** respawns the tool if killed, installed via multiple independent mechanisms
  (systemd unit + cron fallback) so removing one doesn't cut access.
- **Self-update / re-deploy** to push a fixed binary mid-game.

---

## 8. Ops quality-of-life

- **Non-interactive one-shot mode** (`tool run <cmd>`) for scripting and fleet-wide fan-out.
- **Multi-host broadcast** - run one command across the whole fleet.
- **File transfer with hash verification + resume** (applies to all upload/download).
- **Session recording / audit log** (asciinema-style) for after-action review and
  scoring-dispute evidence.

---

## 9. Security of the tool itself

Treat it as hostile-facing - a vuln means red team owns you through your own tool.

- Authenticate **before** allocating resources or revealing presence (SPA handles this).
- Memory-safe language; least privilege where feasible.
- Embed only public keys at compile time; never a private key.
- Pin the server identity (mutual auth) to prevent impersonation.

---

## 10. Attribution & IR dossier (`attribute` / `dossier`)

Answers "who did it, from where, how" for a given PID or event. **Capture the dossier
before killing the process** - `kill` destroys `/proc/<pid>`.

**Key primitive - `loginuid`.** `/proc/<pid>/loginuid` (audit `auid`) is set once at login
by PAM, inherited by all children, and **does not change across `su`/`sudo`** - so it
survives privilege escalation and points at the original entry account. Immutable once set
on modern kernels (hard to forge). Map the number -> username via `/etc/passwd`.

**Dossier fields (single `/proc` read of the target):**
- `loginuid` + `sessionid` -> entry account + login session.
- `environ` -> `SSH_CONNECTION`/`SSH_CLIENT` (**source IP**), `SUDO_USER`, `SUDO_COMMAND`,
  `PWD` - inherited down the chain, so the rogue often still carries the attacker's IP.
- **Parent chain** (walk PPID -> 1) -> entry vector: child of `sshd` = credentials; child of
  `nginx`/`www-data` = web/webshell; child of `cron`/systemd = persistence firing.
- Controlling tty (`stat`) -> `/dev/pts/N` -> `utmp` (`/run/utmp`) for user + source host.
- Process **start time** -> the anchor for time-correlation.
- exe path + **hash**, cmdline, cwd, open fds (listening socket confirms port ownership).
- **Correlation**: match start time against `wtmp` (logins) and `auth.log`/`secure` within
  a window -> login + source IP tied to the action.

**Signals that are themselves IOCs:**
- `loginuid` unset (`4294967295`) on an interactive process -> entry bypassed PAM login
  (webshell / service exploit / raw backdoor); pivot to the parent chain + service logs.
- Interactive process with no controlling tty, or a shell under a service daemon.

**"What commands did they run" (reliability order):**
1. **auditd execve log** - definitive (records `auid`, tty, args, cwd) if running.
2. **Own execve monitor** - eBPF `execve` tracepoint or fast `/proc` birth-poller logging
   loginuid + parent + cmdline to append-only storage. The reliable version.
3. **Shell history** - grab fast, bonus only (cleared easily; absent for `sh`;
   space-prefixed commands excluded).

---

## 11. Service sentinel (scored-port protection)

Proactive guard against port-squat trolls (e.g. a stray `python -m http.server` on the
scored port so the real `nginx` can't bind).

- Declare expected bindings: `port 80 -> nginx`, `port 25 -> postfix`, etc.
- Continuously verify the **expected binary** owns each scored port. Alert on: wrong
  process bound, nothing bound, or the real service crashed.
- On trigger, auto-run the section 10 dossier, then **capture -> kill squatter -> restart the real
  service -> verify bind -> check for respawn**. A while-loop / cron / watcher will rebind,
  so trace and cut the supervisor (parent chain), not just the child.
- Turns the most common scoring-denial troll into an instant attributed alert + fix.

---

## 12. Tamper-resistant evidence capture (from T0)

Attribution is won at deployment time, not at incident time - red team wipes `auth.log`,
`wtmp`, and history, so the tool's own record must be the source of truth.

- On deploy, enable auditd execve + file-watch rules (or the tool's own eBPF/`/proc`
  execve monitor).
- Continuously append login records, process births (with loginuid + parent + cmdline),
  and watchlist/file-drop events to **append-only, tool-guarded storage**.
- **Ship off-box** to a teammate's collector where possible, so log-wiping on the host
  doesn't destroy the evidence.
- Baseline caveat (from section 4) applies: T0 state is trust-on-first-use; pair with a one-time
  known-bad sweep at first run.

---

## 13. Implementation architecture

Decisions locked during design review. The **how** for anything still open is deferred
to the roadmap, not fixed here.

### 13.1 Language, runtime, build
- **Rust**, memory-safe by default (`#![forbid(unsafe_code)]` outside the few audited
  syscall/FFI shims). Satisfies section 9's memory-safety requirement more strongly than a GC'd
  language would.
- Async on **Tokio** (required by the SSH transport).
- **Fully static musl** artifacts: `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl`. No glibc, Alpine-safe. One artifact per arch.
- eBPF bytecode is **arch-neutral**, so a single compiled BPF object serves both arches;
  only the userland shell is built twice.

### 13.2 Binary modes
One workspace, two shipped binaries sharing all library crates:
- **`agent`** - deployed on the host, runs as root, autonomous from T0.
- **`client`** - the operator's dedicated application; connects like SSH and drives
  everything.

There is **no relay/collector mode** (see section 13.4 reachability).

### 13.3 Front door - hybrid SPA
- **Hybrid Single-Packet Authorization.** Direct path: one signed **UDP** datagram. Over a
  TCP proxy/Teleport chain (UDP can't traverse it): the knock is the **opening bytes of the
  TCP stream**, and the socket looks dead until the knock validates, then it reveals the
  SSH server. Port stays invisible to scanners on either path.
- Knock payload: an **ed25519** signature over `{monotonic timestamp, random nonce,
  service id, key id}`. Anti-replay = timestamp window + LRU nonce cache. **No
  rate-limit / no lockout** (per section 1 - lockout is a self-DoS vector).

### 13.4 Session transport & reachability
- Transport is the audited **`russh`** SSH stack: interactive PTY (resize/SIGWINCH/job
  control), multiplexed channels for file transfer and the telemetry stream, and
  **mutual auth with a pinned server host key** (anti-phishing, section 1).
- Client reachability order: **direct -> proxy chain** (`ProxyJump`, generic
  `ProxyCommand`, Teleport `tsh proxy ssh`).
- **Accepted limitation:** with no relay, a box that is inbound-unreachable through every
  proxy chain (strict NAT / egress-only with no usable jump host) has **no operator path**.
  This is a deliberate trade for zero standing infrastructure.

### 13.5 Auth & keys
- **Single shared team ed25519 keypair.** The **same keypair signs the SPA knock and
  authenticates the SSH session** - one embedded public key, one operator-held secret.
  Consequence: the audit trail attributes actions to "the team," not an individual
  operator.
- **Self-update** is an authenticated-operator command (`update <path>`): the client
  uploads the binary (hash-verified, resumable), the agent atomically swaps and restarts.
  **No separate signing key** - the authenticated session is the authority. Persistence
  install is **idempotent**, so re-running it on restart cannot corrupt anything.

### 13.6 Sensing core
- A shared **read-only host model** built by parsing `/proc` and config files **directly**
  - never shelling out - feeds baseline/diff, the alert engine, hunt, and the dossier
  builder off one snapshot.
- eBPF is **opportunistic**: load an execve tracepoint where kernel BTF is present, else
  fall back to a fast `/proc` birth-poller + auditd. BPF/XDP/tc **enumeration** (section 5.2) is
  pure-syscall and always available.

### 13.7 Firewall driver
- Drive `nft`/`iptables` by **exec** (there is no mature pure-Rust legacy-iptables path).
  The read/detection side still parses `/proc` directly; as a mitigation the agent
  **hash-verifies the firewall binary before invoking it** and warns on mismatch, so a
  trojaned `nft` doesn't get blind trust.
- Backends are **registry-dispatched**: adding a new firewall implementation is
  implementing the backend trait and registering it in one place - no changes elsewhere.
- Behavior per section 1: snapshot before any change, insert the tool's own allow-rule **first
  and atomically**, arm the **dead-man's-switch auto-revert**, restore replays the exact
  snapshot.

### 13.8 State & storage
- **`redb`** (pure-Rust, ACID, crash-safe, no cgo) holds baseline, watchlist, sentinel
  bindings, and indices.
- The **evidence log is append-only and hash-chained** (each record commits the hash of
  the prior record -> tamper-evident) in its own segment.

### 13.9 Off-box evidence (section 12)
- No standing operator daemon. On client connect: **catch-up sync** of everything since
  the client's last-seen cursor, **then a live tail** for the duration of the connection.
  A client reopened an hour later just pulls the gap; a client left open sees events in
  real time.

### 13.10 Self-preservation (section 7)
- At T0 the agent **auto-installs multiple independent persistence mechanisms** (systemd
  unit + cron fallback, and others), each **idempotent**, so removing one does not cut
  access. Mechanisms are **registry-dispatched** for easy extension.

### 13.11 Extensibility principle
Pluggable subsystems (**firewall backends**, **persistence mechanisms**, **hunt/monitor
checks**) are built as **trait + registry dispatch**: a new implementation is a new type
plus one registration line. This is the primary extension seam of the codebase.

### 13.12 Chosen low-level defaults
- **Privilege:** the agent **requires root**; launched non-root it runs a degraded
  read-only mode with a loud capability warning rather than failing silently.
- **Session recording:** asciinema **cast v2**-compatible.
- **Config format:** TOML for watchlist / sentinel / expected-service maps.

### 13.13 Resolved / remaining

Resolved:
1. **State directory** - a documented, **configurable** path (default
   `/var/lib/crystal_hammer`), **created if it does not exist**. No obscured footprint.
2. **Dead-man "confirm keep"** is an **in-session confirmation**: applying lockdown arms
   the auto-revert timer, and the operator confirms "keep" from within the same session
   before it expires. Default window 60s.

Remaining:
3. Exact watchdog / supervision mechanism set (candidate menu below in 13.14).

### 13.14 Session-preserving lockdown

Applying lockdown must **not drop the operator's active session** (the whole point of the
in-session confirm is that the operator is still there to confirm). This is guaranteed by
the existing rules, not by luck:
- the tool's own allow-rule is inserted first and atomically (SPECS section 1);
- established/related return traffic is allowed via conntrack (SPECS section 1), so the
  in-flight SSH session keeps flowing while new inbound is denied.

The dead-man timer remains as the backstop for the case where the ruleset is wrong despite
this and the session does drop.

### 13.15 Watchdog / supervision (candidate menu)

Reliability-only: keep the defender's own agent alive and self-heal if it stops. Layered,
each layer independent so one failing does not take the others down. Reuses the
idempotent persistence registry (SPECS 13.10).

- **L1 - Init-system supervision (primary).** systemd unit with `Restart=always` plus a
  `sd_notify` heartbeat (`WatchdogSec`) so a *hung* agent is restarted, not only a crashed
  one; `StartLimit*` tuned so it is never rate-limited into staying down. On non-systemd
  hosts, the OpenRC / runit / s6 / inittab-respawn equivalent.
- **L2 - Scheduler fallback.** cron `@reboot` + a periodic entry that relaunches the agent
  if a liveness check fails. Independent of the init system.
- **L3 - Boot-time self-repair.** on start, the agent idempotently re-installs any of its
  own supervision entries that are missing, so removing one layer is healed by another.
- **L4 - Local liveness beacon.** the agent writes a heartbeat (timestamp file or local
  socket) that supervisors probe and that `info` reports as tool health.
- **L5 - Off-box liveness (operator-side).** because evidence ships on connect, the
  operator/collector notices an agent that has stopped checking in. Non-intrusive; no code
  on the host beyond what already runs.