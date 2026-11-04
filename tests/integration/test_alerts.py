"""
Alert browser data path: `alerts dump` pages stored alerts out of the evidence log as
NDJSON. (The interactive TUI over this data is not exercised in CI.)
"""

from conftest import eventually, fail_with_diagnostics, run_client


def test_alerts_dump(agent):
    # Record an alert, then dump the history and confirm it's there with a cursor.
    # The emit -> evidence-log write is async (broadcast drained by a writer task), so
    # the first dump can race the write; poll until the marker lands.
    run_client(agent, b"watch test DUMP_PROBE_123\nexit\n")
    last = {}

    def dumped():
        out, err, code = run_client(agent, b"alerts dump\nexit\n")
        last.update(out=out, err=err, code=code)
        return code == 0 and "DUMP_PROBE_123" in out and "cursor" in out

    if not eventually(dumped):
        fail_with_diagnostics(agent, "alerts dump did not return the recorded alert",
                              client_stdout=last.get("out", ""),
                              client_stderr=last.get("err", ""),
                              client_exit=last.get("code"))
