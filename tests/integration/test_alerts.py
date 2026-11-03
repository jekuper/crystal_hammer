"""
Alert browser data path: `alerts dump` pages stored alerts out of the evidence log as
NDJSON. (The interactive TUI over this data is not exercised in CI.)
"""

from conftest import fail_with_diagnostics, run_client


def test_alerts_dump(agent):
    # Record an alert, then dump the history and confirm it's there with a cursor.
    run_client(agent, b"watch test DUMP_PROBE_123\nexit\n")
    out, err, code = run_client(agent, b"alerts dump 0 1000\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "alerts dump failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if "DUMP_PROBE_123" not in out or "cursor" not in out:
        fail_with_diagnostics(agent, "alerts dump did not return the recorded alert",
                              client_stdout=out, client_stderr=err)
