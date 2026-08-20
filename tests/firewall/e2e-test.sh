#!/usr/bin/env bash
#
# e2e-test.sh -- end-to-end test harness for the ch-firewall agent + client
#
# Starts the agent, verifies it attaches to every interface present at
# startup, checks baseline internet connectivity, exercises hot-plug
# attach/detach (including the veth-pair simultaneous-delete race that
# triggers ENODEV on detach), drives the client through a lockdown/unlock
# cycle and checks connectivity changes accordingly, then verifies a clean
# shutdown detaches everything. Always sweeps up after itself via
# cleanup-firewall.sh, whether the run passes or fails.
#
# Usage:
#   sudo ./e2e-test.sh <agent-binary-path> <client-binary-path>
#
# Requires: bash 4+, ip, tc, curl or ping, awk, grep. bpftool is optional.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLEANUP_SCRIPT="${SCRIPT_DIR}/cleanup-firewall.sh"

AGENT_BIN="${1:-${SCRIPT_DIR}/../../target/debug/agent}"
CLIENT_BIN="${2:-${SCRIPT_DIR}/../../target/debug/client}"

TEST_IFACE_A="cwtest0"
TEST_IFACE_B="cwtest0-peer"

ATTACH_TIMEOUT=15      # seconds to wait for "attaching to new interface" log lines
SHUTDOWN_TIMEOUT=10    # seconds to wait for the agent to exit cleanly
LOCKDOWN_SETTLE=2      # seconds to wait after sending lockdown/unlock
CLIENT_STARTUP_WAIT=5  # per spec: wait 5s after launching the client before sending commands

WORKDIR="$(mktemp -d /tmp/ch-e2e.XXXXXX)"
AGENT_LOG="${WORKDIR}/agent.log"
CLIENT_LOG="${WORKDIR}/client.log"
CLIENT_FIFO="${WORKDIR}/client.stdin"

AGENT_PID=""
CLIENT_PID=""
CLIENT_FD=""

declare -A RESULTS   # test name -> PASS / FAIL / SKIP
declare -A REASONS   # test name -> failure detail

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

log()  { printf '[e2e] %s\n' "$*"; }
fail() { printf '[e2e] ERROR: %s\n' "$*" >&2; }

record() {
    # record <test-name> <PASS|FAIL|SKIP> [reason]
    RESULTS["$1"]="$2"
    REASONS["$1"]="${3:-}"
    if [[ "$2" == "FAIL" ]]; then
        fail "$1 -- ${3:-no detail}"
    else
        log "$1 -- $2"
    fi
}

is_pid_alive() {
    kill -0 "$1" 2>/dev/null
}

wait_for_log_pattern() {
    # wait_for_log_pattern <logfile> <pattern> <timeout-secs>
    local logfile="$1" pattern="$2" timeout="$3" waited=0
    while (( waited < timeout )); do
        grep -qF -- "$pattern" "$logfile" 2>/dev/null && return 0
        sleep 1
        waited=$((waited + 1))
    done
    grep -qF -- "$pattern" "$logfile" 2>/dev/null
}

check_internet() {
    # returns 0 if reachable, 1 if not, 2 if no tool available
    if command -v curl >/dev/null 2>&1; then
        curl -s -o /dev/null -m 5 --connect-timeout 5 https://1.1.1.1 && return 0
        curl -s -o /dev/null -m 5 --connect-timeout 5 http://1.1.1.1 && return 0
        return 1
    elif command -v ping >/dev/null 2>&1; then
        ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1
        return $?
    else
        return 2
    fi
}

# ---------------------------------------------------------------------------
# cleanup -- always runs, pass or fail
# ---------------------------------------------------------------------------

print_summary() {
    echo
    echo "================= E2E TEST SUMMARY ================="
    local overall=0
    for name in "${!RESULTS[@]}"; do
        printf '%-50s %s\n' "$name" "${RESULTS[$name]}"
        [[ "${RESULTS[$name]}" == "FAIL" ]] && overall=1
    done
    echo "======================================================"
    echo "Logs kept in: $WORKDIR"
    if [[ "$overall" -eq 1 ]]; then
        echo "RESULT: FAIL"
    else
        echo "RESULT: PASS"
    fi
    exit "$overall"
}

cleanup() {
    log "Cleaning up..."

    if [[ -n "$CLIENT_FD" ]]; then
        exec {CLIENT_FD}>&- 2>/dev/null || true
    fi
    if [[ -n "$CLIENT_PID" ]] && is_pid_alive "$CLIENT_PID"; then
        kill "$CLIENT_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$CLIENT_PID" 2>/dev/null || true
    fi
    if [[ -n "$AGENT_PID" ]] && is_pid_alive "$AGENT_PID"; then
        kill "$AGENT_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$AGENT_PID" 2>/dev/null || true
    fi

    if [[ -x "$CLEANUP_SCRIPT" ]]; then
        "$CLEANUP_SCRIPT" \
            "$(basename "$AGENT_BIN" 2>/dev/null)" \
            "$(basename "$CLIENT_BIN" 2>/dev/null)" \
            >>"${WORKDIR}/cleanup.log" 2>&1 || true
    else
        fail "cleanup-firewall.sh not found/executable at $CLEANUP_SCRIPT -- skipping automated sweep"
        ip link del "$TEST_IFACE_A" 2>/dev/null || true
    fi

    rm -f "$CLIENT_FIFO" 2>/dev/null || true

    print_summary
}

trap cleanup EXIT
trap 'fail "interrupted"; exit 130' INT TERM

# ---------------------------------------------------------------------------
# argument / environment validation
# ---------------------------------------------------------------------------

if [[ -z "$AGENT_BIN" || -z "$CLIENT_BIN" ]]; then
    echo "usage: sudo $0 <agent-binary-path> <client-binary-path>" >&2
    exit 2
fi
if [[ ! -x "$AGENT_BIN" ]]; then
    echo "agent binary not found or not executable: $AGENT_BIN" >&2
    exit 2
fi
if [[ ! -x "$CLIENT_BIN" ]]; then
    echo "client binary not found or not executable: $CLIENT_BIN" >&2
    exit 2
fi
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "this script needs root (tc/ip/bpf operations); re-run with sudo." >&2
    exit 2
fi
for bin in ip tc awk grep; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "required tool '$bin' not found in PATH." >&2
        exit 2
    fi
done
if ! command -v curl >/dev/null 2>&1 && ! command -v ping >/dev/null 2>&1; then
    echo "neither curl nor ping is available -- can't test connectivity." >&2
    exit 2
fi

log "Work directory: $WORKDIR"

# Opportunistic sweep before we start, in case a previous run left something behind.
if [[ -x "$CLEANUP_SCRIPT" ]]; then
    log "Pre-run sweep..."
    "$CLEANUP_SCRIPT" "$(basename "$AGENT_BIN")" "$(basename "$CLIENT_BIN")" \
        >>"${WORKDIR}/cleanup.log" 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 1. snapshot interfaces the agent should attach to on startup
# ---------------------------------------------------------------------------

mapfile -t EXPECTED_IFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v '^lo$')
log "Interfaces expected to be attached at startup: ${EXPECTED_IFACES[*]:-<none>}"

# ---------------------------------------------------------------------------
# 2. start the agent
# ---------------------------------------------------------------------------

log "Starting agent: $AGENT_BIN"
"$AGENT_BIN" >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!
sleep 2

if ! is_pid_alive "$AGENT_PID"; then
    record "agent starts and stays running" "FAIL" "agent exited immediately, see $AGENT_LOG"
    exit 1
fi
record "agent starts and stays running" "PASS"

# ---------------------------------------------------------------------------
# 3. verify it attached to every interface that existed at startup
# ---------------------------------------------------------------------------

all_attached=1
for iface in "${EXPECTED_IFACES[@]}"; do
    if ! wait_for_log_pattern "$AGENT_LOG" "attaching to new interface $iface" "$ATTACH_TIMEOUT"; then
        all_attached=0
        fail "no attach log line seen for interface '$iface' within ${ATTACH_TIMEOUT}s"
    fi
done
if [[ "$all_attached" -eq 1 ]]; then
    record "agent attaches to all pre-existing interfaces (log)" "PASS"
else
    record "agent attaches to all pre-existing interfaces (log)" "FAIL" "see $AGENT_LOG"
fi

tc_all_ok=1
for iface in "${EXPECTED_IFACES[@]}"; do
    if ! tc filter show dev "$iface" ingress 2>/dev/null | grep -q ch_firewall; then
        tc_all_ok=0
        fail "no ch_firewall tc filter found on $iface"
    fi
done
if [[ "$tc_all_ok" -eq 1 ]]; then
    record "tc filters present on all pre-existing interfaces" "PASS"
else
    record "tc filters present on all pre-existing interfaces" "FAIL" "see 'tc filter show dev <iface> ingress'"
fi

# ---------------------------------------------------------------------------
# 4. baseline connectivity (Regular mode should pass everything)
# ---------------------------------------------------------------------------

if check_internet; then
    record "baseline internet reachable in Regular mode" "PASS"
else
    record "baseline internet reachable in Regular mode" "FAIL" \
        "no internet reachability before any lockdown -- check the test environment's own network first"
fi

# ---------------------------------------------------------------------------
# 5. hot-plug: create a veth pair, confirm both ends get attached
# ---------------------------------------------------------------------------

log "Creating test veth pair: $TEST_IFACE_A / $TEST_IFACE_B"
if ip link add "$TEST_IFACE_A" type veth peer name "$TEST_IFACE_B" 2>>"${WORKDIR}/setup.log"; then
    hotplug_attach_ok=1
    for iface in "$TEST_IFACE_A" "$TEST_IFACE_B"; do
        if ! wait_for_log_pattern "$AGENT_LOG" "attaching to new interface $iface" "$ATTACH_TIMEOUT"; then
            hotplug_attach_ok=0
            fail "no attach log line for hot-plugged '$iface' within ${ATTACH_TIMEOUT}s"
        fi
    done
    if [[ "$hotplug_attach_ok" -eq 1 ]]; then
        record "hot-plugged veth pair both auto-attach" "PASS"
    else
        record "hot-plugged veth pair both auto-attach" "FAIL" "see $AGENT_LOG"
    fi
else
    record "hot-plugged veth pair both auto-attach" "SKIP" "could not create veth pair, see ${WORKDIR}/setup.log"
fi

# --- 5b. delete one end (destroys both simultaneously in the kernel -- this
#         is the known "peer vanishes without its own DelLink" race). The
#         agent must survive this without crashing.

if ip link show "$TEST_IFACE_A" >/dev/null 2>&1; then
    log "Deleting $TEST_IFACE_A (also destroys $TEST_IFACE_B -- simulates the simultaneous-delete race)"
    ip link del "$TEST_IFACE_A" 2>/dev/null || true
    sleep 3

    if is_pid_alive "$AGENT_PID"; then
        record "agent survives simultaneous veth-pair deletion" "PASS"
    else
        record "agent survives simultaneous veth-pair deletion" "FAIL" \
            "agent process exited, see $AGENT_LOG (look for ENODEV / 'run loop failed fatally')"
    fi

    if grep -qi "run loop failed fatally" "$AGENT_LOG"; then
        record "no fatal error logged for expected ENODEV race" "FAIL" \
            "agent logged a fatal error instead of treating ENODEV as expected, see $AGENT_LOG"
    else
        record "no fatal error logged for expected ENODEV race" "PASS"
    fi

    if ip link show "$TEST_IFACE_A" >/dev/null 2>&1 || ip link show "$TEST_IFACE_B" >/dev/null 2>&1; then
        record "both veth ends actually gone from the kernel" "FAIL" "one or both interfaces still present"
    else
        record "both veth ends actually gone from the kernel" "PASS"
    fi
else
    record "agent survives simultaneous veth-pair deletion" "SKIP" "veth pair was never created"
    record "no fatal error logged for expected ENODEV race" "SKIP" "veth pair was never created"
    record "both veth ends actually gone from the kernel" "SKIP" "veth pair was never created"
fi

# ---------------------------------------------------------------------------
# 6. lockdown / unlock cycle via the client
# ---------------------------------------------------------------------------

if is_pid_alive "$AGENT_PID"; then
    log "Starting client: $CLIENT_BIN"
    mkfifo "$CLIENT_FIFO"
    "$CLIENT_BIN" <"$CLIENT_FIFO" >"$CLIENT_LOG" 2>&1 &
    CLIENT_PID=$!

    # Open a writer on the fifo and keep it open for the whole session, so
    # the client's stdin doesn't see EOF between commands. This open blocks
    # until the client (launched above) opens its read end -- that's the
    # natural synchronization point, not a race.
    exec {CLIENT_FD}>"$CLIENT_FIFO"

    sleep 1
    if ! is_pid_alive "$CLIENT_PID"; then
        record "client starts and stays running" "FAIL" "client exited immediately, see $CLIENT_LOG"
    else
        record "client starts and stays running" "PASS"

        log "Waiting ${CLIENT_STARTUP_WAIT}s before sending 'lockdown'..."
        sleep "$CLIENT_STARTUP_WAIT"

        echo "lockdown" >&"$CLIENT_FD"
        sleep "$LOCKDOWN_SETTLE"

        if check_internet; then
            record "internet blocked while in lockdown" "FAIL" "connectivity still worked after 'lockdown'"
        else
            record "internet blocked while in lockdown" "PASS"
        fi

        echo "unlock" >&"$CLIENT_FD"
        sleep "$LOCKDOWN_SETTLE"

        if check_internet; then
            record "internet restored after unlock" "PASS"
        else
            record "internet restored after unlock" "FAIL" "connectivity still blocked after 'unlock'"
        fi
    fi

    exec {CLIENT_FD}>&-
    CLIENT_FD=""
    sleep 1
    if is_pid_alive "$CLIENT_PID"; then
        kill "$CLIENT_PID" 2>/dev/null || true
    fi
else
    record "client starts and stays running" "SKIP" "agent was not running"
    record "internet blocked while in lockdown" "SKIP" "agent was not running"
    record "internet restored after unlock" "SKIP" "agent was not running"
fi

# ---------------------------------------------------------------------------
# 7. clean shutdown detaches everything
# ---------------------------------------------------------------------------

if is_pid_alive "$AGENT_PID"; then
    log "Sending SIGTERM to agent and waiting for clean shutdown..."
    kill -TERM "$AGENT_PID" 2>/dev/null || true

    waited=0
    while is_pid_alive "$AGENT_PID" && (( waited < SHUTDOWN_TIMEOUT )); do
        sleep 1
        waited=$((waited + 1))
    done

    if is_pid_alive "$AGENT_PID"; then
        record "agent exits cleanly on SIGTERM" "FAIL" "still running after ${SHUTDOWN_TIMEOUT}s"
    else
        record "agent exits cleanly on SIGTERM" "PASS"
    fi

    detach_ok=1
    for iface in "${EXPECTED_IFACES[@]}"; do
        if ip link show "$iface" >/dev/null 2>&1 && \
           tc filter show dev "$iface" ingress 2>/dev/null | grep -q ch_firewall; then
            detach_ok=0
            fail "tc filter for ch_firewall still present on $iface after shutdown"
        fi
    done
    if [[ "$detach_ok" -eq 1 ]]; then
        record "all tc filters removed after shutdown" "PASS"
    else
        record "all tc filters removed after shutdown" "FAIL" "see 'tc filter show dev <iface> ingress'"
    fi
else
    record "agent exits cleanly on SIGTERM" "SKIP" "agent was not running"
    record "all tc filters removed after shutdown" "SKIP" "agent was not running"
fi

# cleanup() runs automatically via the EXIT trap from here, and prints the summary.