"""
File-tracker scenarios: the agent must track sensitive files, report WHO changed
them, and push that alert to a connected operator live.

Two of these are real intrusion simulations: a persistent operator session is held
open while a separate root shell tampers with a tracked file, and we assert the alert
shows up in the operator's output without anyone running a command to fetch it.
"""

from conftest import (
    AGENT_PORT, REMOTE_DIR, TGT_IP,
    fail_with_diagnostics, run_client,
)

# A client session that feeds `feed` on stdin (a printf format, so use \n for newlines),
# then holds the pipe open for `hold` seconds so the live alert stream keeps running
# before EOF ends the session.
def _persistent_client(feed, hold):
    return (
        f"{{ printf {feed!r}; sleep {hold}; }} | "
        f"./client --host {TGT_IP} --port {AGENT_PORT}"
    )


def test_watch_list_shows_defaults(agent):
    """The stock watchlist covers the common service stack and every user's SSH keys."""
    out, err, code = run_client(agent, b"watch list\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "watch list failed",
                              client_stdout=out, client_stderr=err, client_exit=code)

    expected = ["/etc/ssh", "/etc/sudoers", "/etc/cron.d", "/root/.ssh"]
    missing = [p for p in expected if p not in out]
    if missing:
        fail_with_diagnostics(agent, f"watch list missing defaults: {missing}",
                              client_stdout=out, client_stderr=err)


def test_watch_add_extends_list_at_runtime(agent):
    """A path added at runtime shows up in the live watchlist."""
    out, err, code = run_client(
        agent, b"watch add /tmp/ch_runtime_probe\nwatch list\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "watch add/list failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if "/tmp/ch_runtime_probe" not in out:
        fail_with_diagnostics(agent, "runtime-added path not reflected in watch list",
                              client_stdout=out, client_stderr=err)


def test_live_alert_channel_delivers(agent):
    """The alert channel end to end: a synthetic alert reaches a connected operator
    with no command run to pull it. Backend-independent (does not need audit/fanotify)."""
    script = (
        f"cd {REMOTE_DIR} && rm -f /tmp/ch-cout && "
        + _persistent_client("watch test SIMULATED_INTRUSION_XYZ\\n", 6)
        + " >/tmp/ch-cout 2>&1; cat /tmp/ch-cout"
    )
    out = agent.target.sh(script, timeout=45).stdout.decode(errors="replace")
    if "SIMULATED_INTRUSION_XYZ" not in out or "ALERT" not in out:
        fail_with_diagnostics(agent, "live alert channel did not deliver the test alert",
                              client_stdout=out)


def test_live_alert_on_tracked_file_change(agent):
    """Full intrusion simulation: operator connected, a separate root shell tampers
    with a tracked file, and the alert naming the file appears in the operator's
    session unprompted."""
    script = f"""
cd {REMOTE_DIR}
rm -f /tmp/ch-cout
mkdir -p /tmp/chfim
echo baseline > /tmp/chfim/app.conf
# Persistent operator session; adds the dir to the live watchlist then just listens.
{{ printf 'watch add /tmp/chfim\\n'; sleep 24; }} | ./client --host {TGT_IP} --port {AGENT_PORT} >/tmp/ch-cout 2>&1 &
CL=$!
sleep 11                                   # connect + enforce the new watch (<=5s sync)
echo "pwned by red team" >> /tmp/chfim/app.conf   # the tamper
sleep 9                                    # let the live alert propagate
wait $CL 2>/dev/null || true
cat /tmp/ch-cout
"""
    out = agent.target.sh(script, timeout=90).stdout.decode(errors="replace")
    if "app.conf" not in out or "ALERT" not in out:
        fail_with_diagnostics(
            agent,
            "no live alert for a change to a tracked file (needs a working audit/fanotify backend)",
            client_stdout=out)
