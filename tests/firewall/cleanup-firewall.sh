#!/usr/bin/env bash
#
# cleanup-firewall.sh
#
# Distro-agnostic cleanup for leftover state from the ch-firewall agent:
#   - TC clsact qdiscs/filters carrying our ch_firewall classifier
#   - Test veth pairs created by e2e-test.sh (name prefix: cwtest)
#   - Any pinned BPF objects under /sys/fs/bpf matching ch_firewall*
#   - Stray agent/client processes, if patterns are given
#
# Usage:
#   sudo ./cleanup-firewall.sh [-v|--verbose] [process-pattern ...]
#
# Examples:
#   sudo ./cleanup-firewall.sh
#   sudo ./cleanup-firewall.sh crystal-hammer-agent crystal-hammer-client
#
# This is a best-effort sweep, not a check -- it always exits 0.

set -u

VERBOSE=0
if [[ "${1:-}" == "-v" || "${1:-}" == "--verbose" ]]; then
    VERBOSE=1
    shift
fi

log()  { printf '%s\n' "$*"; }
vlog() { [[ "$VERBOSE" -eq 1 ]] && printf '%s\n' "$*"; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "cleanup-firewall.sh must run as root (needs tc/ip/bpftool)." >&2
    exit 1
fi

for bin in ip tc; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "required tool '$bin' not found in PATH; cannot continue." >&2
        exit 1
    fi
done

HAVE_BPFTOOL=0
command -v bpftool >/dev/null 2>&1 && HAVE_BPFTOOL=1

CLASSIFIER_NAME="ch_firewall"
TEST_IFACE_PREFIX="cwtest"

# --- 1. Kill any stray processes matching given patterns -------------------

if [[ $# -gt 0 ]]; then
    log "==> Checking for stray processes matching: $*"
    for pattern in "$@"; do
        [[ -z "$pattern" ]] && continue
        if command -v pgrep >/dev/null 2>&1; then
            pids=$(pgrep -f -- "$pattern" || true)
        else
            # pgrep isn't guaranteed on minimal distros; fall back to ps+awk.
            pids=$(ps -eo pid,args | awk -v pat="$pattern" '$0 ~ pat && $0 !~ /awk/ {print $1}')
        fi
        if [[ -n "${pids:-}" ]]; then
            log "    killing stale processes matching '$pattern': $pids"
            # shellcheck disable=SC2086
            kill $pids 2>/dev/null || true
            sleep 1
            # shellcheck disable=SC2086
            kill -9 $pids 2>/dev/null || true
        else
            vlog "    no stray processes matching '$pattern'"
        fi
    done
fi

# --- 2. Remove any clsact qdisc (and thus its filters) carrying our
#        classifier, on every interface currently present -------------------

log "==> Sweeping TC filters for '$CLASSIFIER_NAME' on all interfaces"

# ip -o link show gives one line per interface; strip the trailing "@peer"
# that veth/vlan-style names carry.
mapfile -t ALL_IFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1)

for iface in "${ALL_IFACES[@]}"; do
    [[ "$iface" == "lo" ]] && continue

    found=0
    for dir in ingress egress; do
        if tc filter show dev "$iface" "$dir" 2>/dev/null | grep -q "$CLASSIFIER_NAME"; then
            found=1
        fi
    done

    if [[ "$found" -eq 1 ]]; then
        log "    removing clsact qdisc on $iface (carries $CLASSIFIER_NAME)"
        tc qdisc del dev "$iface" clsact 2>/dev/null || true
    else
        vlog "    $iface: nothing to remove"
    fi
done

# --- 3. Remove any leftover test veth interfaces ----------------------------

log "==> Removing leftover test interfaces (prefix: $TEST_IFACE_PREFIX)"

mapfile -t ALL_IFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1)
for iface in "${ALL_IFACES[@]}"; do
    if [[ "$iface" == "$TEST_IFACE_PREFIX"* ]]; then
        log "    deleting $iface"
        ip link del "$iface" 2>/dev/null || true
    fi
done

# --- 4. Remove any pinned BPF objects belonging to us -----------------------

if [[ -d /sys/fs/bpf ]]; then
    log "==> Sweeping /sys/fs/bpf for pinned '$CLASSIFIER_NAME' objects"
    while IFS= read -r pin; do
        [[ -z "$pin" ]] && continue
        log "    removing pin: $pin"
        rm -f "$pin" 2>/dev/null || true
    done < <(find /sys/fs/bpf -maxdepth 3 -iname "*${CLASSIFIER_NAME}*" 2>/dev/null)
else
    vlog "==> bpffs not mounted at /sys/fs/bpf, skipping pin sweep"
fi

# --- 5. Report any remaining loaded ch_firewall programs (informational) ---

if [[ "$HAVE_BPFTOOL" -eq 1 ]]; then
    remaining=$(bpftool prog list 2>/dev/null | grep -c "name ${CLASSIFIER_NAME} " || true)
    if [[ "${remaining:-0}" -gt 0 ]]; then
        log "==> NOTE: $remaining '${CLASSIFIER_NAME}' program(s) still loaded in the kernel."
        log "    This is expected if they're no longer attached to anything (filters"
        log "    removed above) -- they get freed once nothing references them, or on"
        log "    next reboot. A loaded-but-unattached program is harmless."
    else
        log "==> No '${CLASSIFIER_NAME}' programs loaded."
    fi
else
    vlog "==> bpftool not found, skipping loaded-program report"
fi

log "==> Cleanup complete."
exit 0