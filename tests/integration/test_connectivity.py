"""
Baseline scenario. The kernel/distro under test is chosen by the CI matrix
(CH_TARGET), not by parametrization: one job = one kernel = one VM.
"""

from conftest import fail_with_diagnostics, run_client


def test_agent_connectivity(agent):
    """The client can knock, authenticate, and run `info`."""
    out, err, code = run_client(agent, b"info\nexit\n")

    def bail(msg):
        fail_with_diagnostics(agent, msg, client_stdout=out,
                              client_stderr=err, client_exit=code)

    if code != 0:
        bail("Client returned non-zero.")
    if "Authenticated SSH session established" not in out:
        bail("Client failed to authenticate.")
    if "Host Information" not in out and "Firewall" not in out:
        bail("Missing 'info' output.")