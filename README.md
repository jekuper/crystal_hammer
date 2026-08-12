# Crystal Hammer

Blue-team emergency access & incident-response tool. An SSH-like replacement deployed at
competition start: authenticated invisible access, self-contained host defense, and hunt
tooling that **trusts nothing on the box** - it parses `/proc` and config files directly
rather than shelling out to (possibly trojaned) system binaries.

- **Spec:** [SPECS.md](SPECS.md) - features and the locked implementation architecture (section 13).
- **Roadmap:** [ROADMAP.md](ROADMAP.md) - milestones and what each delivers.

## At a glance

- **Rust**, memory-safe, fully-static **musl** binaries for `x86_64` and `aarch64`.
- **`agent`** runs on the host (root, autonomous from T0); **`client`** is the operator app.
- Front door: **hybrid SPA** (UDP direct + TCP-embedded knock through proxies) -> `russh`
  session with mutual auth and a pinned host key.
- Reachability: direct -> `ProxyJump` / `ProxyCommand` / Teleport chains.
- Extension seams are **trait + registry dispatch** (firewall backends, persistence
  mechanisms, hunt/monitor checks): add a type, register it in one place.

## Workspace layout

| Crate | Responsibility |
|---|---|
| `ch-common` | Shared types, errors, config, keys, wire protocol messages. |
| `ch-sense` | `/proc`/config parsing, shared host model, baseline & diff. |
| `ch-store` | `redb`-backed state + tamper-evident hash-chained evidence log. |
| `ch-firewall` | Firewall backend **trait + registry**; `nftables` / `iptables` backends. |
| `ch-spa` | Hybrid Single-Packet Authorization knock (encode / decode / verify). |
| `ch-transport` | `russh` session (server + client) and proxy-chain reachability. |
| `ch-persistence` | Self-preservation mechanism **trait + registry**. |
| `ch-monitor` | Alert engine, watchlist, and hunt/monitor **check registry**. |
| `ch-agent` | The on-host agent binary. |
| `ch-client` | The operator client binary. |

## Status

Early scaffold - see [ROADMAP.md](ROADMAP.md). Milestone **M0** (foundation) in progress.

## Building

Target hosts are Linux; the agent is Linux-only. Static builds:

```sh
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```