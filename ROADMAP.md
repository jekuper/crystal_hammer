# Crystal Hammer - Roadmap

Milestones are ordered by dependency and describe **what each delivers**, not the
mechanism. Anything whose "how" is still undecided (see SPECS section 13.13) is intentionally
described only by its outcome here.

Each milestone is a usable increment: after it lands, the tool does something real that
the previous milestone couldn't.

Status legend: **[done]** shipped, **[partial]** some of it shipped, **[todo]** not started.

---

## M0 - Foundation & build pipeline  **[done]**

Delivers the skeleton everything else hangs on.

- Cargo workspace with the crate layout and the trait+registry extension seams in place.
- Reproducible **fully-static musl** builds for `x86_64` and `aarch64`, produced by a
  single command.
- Compile-time key embedding flow: a build takes the team public key and bakes it in.
- CI that builds both arches and runs the test suite.

**Done when:** `agent` and `client` binaries build statically for both arches and run.

---

## M1 - Authenticated invisible access  **[done]**

Delivers the core value proposition: SSH-like access that red-team scanning can't see.

- Hybrid SPA knock (UDP direct + TCP-embedded over proxies); port is invisible until a
  valid knock arrives.
- `russh` session with mutual auth and pinned server host key.
- Full interactive **PTY `shell`** (resize, job control).
- Reachability through `ProxyJump` / `ProxyCommand` / Teleport chains.

**Done when:** an operator gets an authenticated interactive shell to the agent - direct
and through a proxy - while the port is dark to scanners.

---

## M2 - Firewall lockdown & anti-lockout  **[partial]**

Delivers safe, reversible network containment.

- **[done]** Registry-dispatched firewall backends (eBPF) with active-backend detection.
- **[done]** `lockdown` - empty-safe allowlist, default-deny, tool-rule inserted first.
- **[done]** `unlock` / `restore` - replays the saved snapshot.

**Done when:** an operator can lock down and restore a host with one command and is
never at risk of locking themselves out.

---

## M3 - Trustworthy host visibility  **[partial]**

Delivers situational awareness that doesn't trust host binaries.

- **[done]** `/proc`-based sensing used by `info` (distro/kernel, firewall state,
  listeners, users, recent auth failures, tool health).
- **[todo]** Standalone `ports`, `conns`, `procs`, `users`, `recent` commands (today these
  live only as `info` sections).

**Done when:** an operator can see processes, sockets, users, and recent changes without
relying on any system binary.

---

## M4 - Hunt: persistence & no-open-port backdoors  **[partial]**

Delivers proactive threat discovery.

- **[done]** `persistence` one-shot sweep; persistence-mechanism registry.
- **[partial]** Monitor check registry exists (authorized-keys, packet-socket holders) but
  is **not yet run or exposed** as a `hunt` / `stealth` command.
- **[todo]** BPF/XDP/tc enumeration, beacon/egress anomalies, process-lineage anomalies,
  kernel-module & hidden-PID cross-check, ruleset diff, socket-activation units.

**Done when:** an operator can surface persistence footholds and backdoors that expose no
listening port.

---

## M5 - Continuous monitoring & alerting  **[partial]**

Delivers the autonomous watch that runs whether or not anyone is connected.

- **[done]** File tracker on the Linux audit subsystem with a fanotify fallback; reports
  who/what/when (uid, login auid, exe, comm, pid, ppid, cmdline).
- **[done]** Broad default watchlist across the service stack + every user's SSH key dir.
- **[done]** Live alert channel: findings broadcast to connected operators and render
  above the prompt with severity color, bell, and terminal-title attention.
- **[done]** Runtime watchlist `watch add` / `watch list`.
- **[todo]** `redb`-backed state and a tamper-evident **hash-chained evidence log**
  (foundation for everything below; `ch-store` is currently a stub).
- **[todo]** Watchlist persistence + hot-reload and `watch remove` (runtime edits survive
  an agent restart). *(new)*
- **[todo]** Route **all** signals into the live alert channel: hunt-check findings,
  lockdown/unlock events, auth-failure spikes, and the audit-canary "pipeline blinded"
  detection. *(new)*
- **[todo]** Agent-side alert **ring buffer + catch-up on connect** so a newly connected
  operator immediately gets recent history (reuses the `CatchUp`/`Cursor` wire types). *(new)*
- **[todo]** Alert **coalescing**: group bursts (e.g. a package upgrade touching many
  tracked files) into one summarized alert instead of flooding operators. *(new)*
- **[todo]** `baseline` / `diff`: snapshot watchlist hashes at T0 and diff on demand (the
  engine already hashes these files for unattributed-change detection). *(new)*
- **[todo]** Resolve uid/auid to usernames in alerts. *(new; source-IP/container
  attribution lands in M6)*

**Done when:** the agent alerts on the specced account/auth/schedule/runtime/log/file-drop
events on its own from T0, persists them, and a connecting operator catches up on anything
missed.

---

## M6 - Attribution & tamper-resistant evidence  **[todo]**

Delivers "who did it" and evidence that survives log-wiping.

- `attribute <pid>` / `dossier` with `loginuid` correlation, parent-chain, source-IP,
  tty/utmp, exe hash, and time-correlation.
- Enrich live alerts with the actor's source IP / SSH session and owning container (ties
  the file-tracker "who" to a real session and to the containerized stack). *(new)*
- Own execve monitor (opportunistic eBPF, `/proc`/auditd fallback).
- Off-box evidence via catch-up-on-connect **and** live tail while connected; asciinema
  cast v2 session recording.

**Done when:** for any process or event an operator gets a full attributed dossier, and
the evidence trail leaves the box on every connect.

---

## M7 - Active response & hardening  **[partial]**

Delivers the ability to act on what was found.

- **[done]** `kill` / `kick` (terminate a process / boot a user's whole session, with
  identity capture and host/agent safety guards).
- **[done]** `service` - start/stop/restart/status across systemd / OpenRC / SysV,
  init detected at runtime.
- **[done]** `rotate` - lock + force-reset a user's password, backing up /etc/shadow first.
- **[done]** Auto-backup before a destructive change (used by `rotate`).
- **[done]** File transfer with hash + size verification for all upload/download.
- **[todo]** Transfer **resume** (continue a partial transfer from its offset). Deferred -
  the current transfer is already hash-verified; resume is a large-file/flaky-link nicety.
- ~~`sentinel` - scored-port protection: verify the expected binary owns each scored port,
  auto-dossier + capture + kill squatter + restart + verify + respawn-trace on trigger.~~
  **[cancelled]** deferred; may return later.

**Done when:** an operator can respond to rogue processes and credential abuse from within
the tool, with backups taken automatically.

---

## M8 - Survivability & fleet ops  **[partial]**

Delivers persistence of access and scale.

- **[done]** Multi-mechanism idempotent self-preservation installed at T0.
- **[todo]** Self-update / redeploy of a fixed binary mid-game (the `Update` wire type and
  `restart` command exist but the swap is unwired).
- **[todo]** Non-interactive one-shot mode (`run <cmd>`) and multi-host broadcast/fan-out
  (the client CLI parses `run`/`shell` subcommands but does not act on them yet).

**Done when:** removing one persistence mechanism doesn't cut access, fixes can be pushed
mid-game, and one command runs across the fleet.

---

## M9 - Audit & production hardening  **[todo]**

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

Still to pick before its milestone:

- **Watchdog / supervision layers** - which of the L1-L5 candidate layers to ship.
  (SPECS 13.15; blocks M8.)
