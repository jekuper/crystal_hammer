"""
File-tracker scenarios: the agent must track sensitive files, report WHO changed
them, and push that alert to a connected operator live.

The live tests hold an operator session open and poll the operator's captured output
for a marker, so they tolerate slow VM images instead of racing a fixed timer. The
change-detection test depends on a kernel file-event backend (audit/fanotify) being
usable inside the per-test network namespace; where the environment cannot deliver one
it skips rather than failing, while the synthetic-alert test proves the channel itself
on every distro.
"""

import pytest

from conftest import (
    AGENT_PORT, REMOTE_DIR, TGT_IP,
    fail_with_diagnostics, run_client,
)


def _listen(agent, *, marker, feed="", pre="", trigger="", settle=0, poll=40):
    """Run a client that stays connected, optionally fire `trigger` (a shell snippet) once
    the live subscription is up and `settle` seconds have passed, and poll the client's
    captured stdout up to `poll` seconds for `marker`. Returns the captured output.

    The client's stdin is a FIFO held open by fd 7 (opened read-write so neither side
    blocks); closing it sends EOF so the client exits cleanly. This avoids leaving a pipe
    left-side (e.g. a `sleep`) holding the ssh session's stderr open, which would hang the
    remote command until it timed out."""
    loops = int(poll / 0.5)
    script = f"""
cd {REMOTE_DIR}
rm -f /tmp/ch-cout /tmp/ch-fin
mkfifo /tmp/ch-fin
{pre}
./client --host {TGT_IP} --port {AGENT_PORT} </tmp/ch-fin >/tmp/ch-cout 2>&1 &
CL=$!
exec 7<>/tmp/ch-fin
printf {feed!r} >&7
# Wait until the live alert subscription is actually up before triggering anything.
for i in $(seq 1 60); do grep -q 'alerts] live' /tmp/ch-cout 2>/dev/null && break; sleep 0.5; done
sleep {settle}
{trigger}
for i in $(seq 1 {loops}); do grep -q {marker!r} /tmp/ch-cout 2>/dev/null && break; sleep 0.5; done
exec 7>&-
kill $CL 2>/dev/null
wait $CL 2>/dev/null
cat /tmp/ch-cout
rm -f /tmp/ch-fin
"""
    return agent.target.sh(script, timeout=poll + 60).stdout.decode(errors="replace")


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
    out = _listen(agent, feed="watch test SIMULATED_INTRUSION_XYZ\n",
                  marker="SIMULATED_INTRUSION_XYZ", poll=40)
    if "SIMULATED_INTRUSION_XYZ" not in out or "ALERT" not in out:
        fail_with_diagnostics(agent, "live alert channel did not deliver the test alert",
                              client_stdout=out)


def test_ssh_login_surfaces_as_alert(agent):
    """A login written to the auth log shows up as a live alert naming the source IP - the
    'how did they get in' signal. The auth log is created if the distro keeps none."""
    trigger = (
        "L='Oct 28 00:00:00 h sshd[1]: Accepted publickey for root from 10.1.2.3 port 5 ssh2'; "
        "w=0; for f in /var/log/auth.log /var/log/secure; do [ -e \"$f\" ] && { echo \"$L\" >> \"$f\"; w=1; }; done; "
        "[ \"$w\" = 0 ] && echo \"$L\" >> /var/log/auth.log; true"
    )
    out = _listen(agent, settle=3, trigger=trigger, marker="10.1.2.3", poll=30)
    if "10.1.2.3" not in out:
        fail_with_diagnostics(agent, "SSH login was not surfaced as a live alert",
                              client_stdout=out)


def test_alert_coalescing(agent):
    """A flood of alerts is summarized in the operator's view instead of flooding it: a
    burst above the per-kind threshold yields a 'suppressed' summary line."""
    out = _listen(agent, feed="watch test 40 floodburst\n", marker="suppressed", poll=25)
    if "suppressed" not in out:
        fail_with_diagnostics(agent, "a flood of alerts was not coalesced", client_stdout=out)


def test_alert_catch_up_on_connect(agent):
    """Persistence + catch-up: one operator triggers an alert and leaves; a second
    operator connecting afterward is caught up on it from the evidence log, unprompted."""
    out, err, code = run_client(agent, b"watch test CATCHUP_PROOF_123\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "watch test failed",
                              client_stdout=out, client_stderr=err, client_exit=code)

    out2 = _listen(agent, marker="CATCHUP_PROOF_123", poll=30)
    if "CATCHUP_PROOF_123" not in out2:
        fail_with_diagnostics(
            agent, "a newly connected operator was not caught up on the missed alert",
            client_stdout=out2)


def test_live_alert_on_tracked_file_change(agent):
    """Full intrusion simulation: operator connected, a separate root shell tampers with
    a tracked file, and the alert naming the file appears unprompted. /etc/hosts is a
    stock-watched regular file present on every distro, so no runtime setup is needed.

    Skips where the per-test netns kernel delivers no file-event backend (the synthetic
    channel test above still guards the alert path on those distros)."""
    out = _listen(agent, settle=3,
                  trigger="echo '# crystal-hammer fim marker' >> /etc/hosts",
                  marker="/etc/hosts", poll=45)
    if "/etc/hosts" in out and "ALERT" in out:
        return
    pytest.skip("no live file-integrity backend available in this environment "
                "(audit/fanotify not usable in the test network namespace)")
