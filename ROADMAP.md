# Crystal Hammer - Roadmap

Milestones are ordered by dependency and describe **what each delivers**, not the
mechanism. Anything whose "how" is still undecided (see SPECS section 13.13) is intentionally
described only by its outcome here.

Each milestone is a usable increment: after it lands, the tool does something real that
the previous milestone couldn't.

---

## M0 - Foundation & build pipeline

Delivers the skeleton everything else hangs on.

- Cargo workspace with the crate layout and the trait+registry extension seams in place.
- Reproducible **fully-static musl** builds for `x86_64` and `aarch64`, produced by a
  single command.
- Compile-time key embedding flow: a build takes the team public key and bakes it in.
- CI that builds both arches and runs the test suite.

**Done when:** `agent` and `client` binaries build statically for both arches and run
(doing nothing useful yet).

---

## M1 - Authenticated invisible access

Delivers the core value proposition: SSH-like access that red-team scanning can't see.

- Hybrid SPA knock (UDP direct + TCP-embedded over proxies); port is invisible until a
  valid knock arrives.
- `russh` session with mutual auth and pinned server host key.
- Full interactive **PTY `shell`** (resize, job control).
- Reachability through `ProxyJump` / `ProxyCommand` / Teleport chains.

**Done when:** an operator gets an authenticated interactive shell to the agent - direct
and through a proxy - while the port is dark to scanners.

---

## M2 - Firewall lockdown & anti-lockout

Delivers safe, reversible network containment.

- Registry-dispatched firewall backends with active-backend detection.
- `lockdown` - empty-safe allowlist, default-deny, tool-rule inserted first and
  atomically.
- `unlock` / `restore` - replays the exact saved snapshot.
- Dead-man's-switch auto-revert so a bad lockdown can never strand access.

**Done when:** an operator can lock down and restore a host with one command and is
never at risk of locking themselves out.

---

## M3 - Trustworthy host visibility

Delivers situational awareness that doesn't trust host binaries.

- `/proc`-based sensing core and shared host model.
- `info` (distro/kernel, firewall state, listeners, users, recent auth failures, tool
  health), `ports`, `conns`, `procs`, `users`, `recent`.

**Done when:** an operator can see processes, sockets, users, and recent changes without
relying on any system binary.

---

## M4 - Hunt: persistence & no-open-port backdoors

Delivers proactive threat discovery.

- `persistence` one-shot sweep across the full section 3 surface.
- `hunt` / `stealth`: packet/raw-socket holders, BPF/XDP/tc enumeration, beacon/egress
  anomalies, process-lineage anomalies, kernel-module & hidden-PID cross-check, ruleset
  diff, socket-activation units.

**Done when:** an operator can surface persistence footholds and backdoors that expose no
listening port.

---

## M5 - Continuous monitoring & alerting

Delivers the autonomous watch that runs whether or not anyone is connected.

- `redb`-backed state, tamper-evident hash-chained evidence log.
- `baseline` / `diff`; the alert engine over the section 4 event set.
- Runtime-editable `watchlist` (add/remove/list), persisted and hot-reloaded.
- Optional real-time file layer on high-value paths, with actor attribution where
  available.

**Done when:** the agent alerts on the specced account/auth/schedule/runtime/log/file-drop
events on its own from T0.

---

## M6 - Attribution & tamper-resistant evidence

Delivers "who did it" and evidence that survives log-wiping.

- `attribute <pid>` / `dossier` with `loginuid` correlation, parent-chain, source-IP,
  tty/utmp, exe hash, and time-correlation.
- Own execve monitor (opportunistic eBPF, `/proc`/auditd fallback).
- Off-box evidence via catch-up-on-connect **and** live tail while connected; asciinema
  cast v2 session recording.

**Done when:** for any process or event an operator gets a full attributed dossier, and
the evidence trail leaves the box on every connect.

---

## M7 - Active response & hardening

Delivers the ability to act on what was found.

- `kill` / `kick`, `rotate`, `service` abstraction, auto-backup before destructive change.
- `sentinel` - scored-port protection: verify the expected binary owns each scored port,
  auto-dossier + capture + kill squatter + restart + verify + respawn-trace on trigger.
- File transfer with hash verification + resume for all upload/download.

**Done when:** an operator can respond to squatters, rogue processes, and credential
abuse from within the tool, with backups taken automatically.

---

## M8 - Survivability & fleet ops

Delivers persistence of access and scale.

- Multi-mechanism idempotent self-preservation installed at T0.
- Self-update / redeploy of a fixed binary mid-game.
- Non-interactive one-shot mode (`run <cmd>`) and multi-host broadcast/fan-out.

**Done when:** removing one persistence mechanism doesn't cut access, fixes can be pushed
mid-game, and one command runs across the fleet.

---

## M9 - Audit & production hardening

Delivers confidence that the tool itself isn't the weak link (section 9).

- Security review of the whole external surface (SPA, transport, self-update, file
  transfer).
- Fuzzing of the knock/protocol parsers; degraded-mode and failure-path testing.
- Operator documentation and deployment runbook.

**Done when:** the tool has been adversarially reviewed and is safe to field.

---

## Design decisions

Resolved:

- **State directory** - configurable documented path (default `/var/lib/crystal_hammer`),
  created if missing. (SPECS 13.13)
- **Dead-man "confirm keep"** - in-session confirmation, default 60s window; lockdown is
  session-preserving. (SPECS 13.13, 13.14)

Still to pick before its milestone:

- **Watchdog / supervision layers** - which of the L1-L5 candidate layers to ship.
  (SPECS 13.15; blocks M8.)