"""
M4 hunt: a read-only sweep. On a CI VM, root's key-based login means
/root/.ssh/authorized_keys exists, so the authorized-keys check always has a finding.
"""

from conftest import fail_with_diagnostics, run_client


def test_hunt_reports_authorized_keys(agent):
    out, err, code = run_client(agent, b"hunt\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "hunt failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if "hunt:" not in out or "/root/.ssh/authorized_keys" not in out:
        fail_with_diagnostics(agent, "hunt did not report root's authorized_keys",
                              client_stdout=out, client_stderr=err)
