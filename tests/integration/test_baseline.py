"""
M5 baseline/diff: snapshot known-good file hashes, then detect what changed.
"""

from conftest import fail_with_diagnostics, run_client


def test_baseline_and_diff(agent):
    out, err, code = run_client(agent, b"baseline\nexit\n")
    if code != 0 or "baseline captured" not in out:
        fail_with_diagnostics(agent, "baseline capture failed",
                              client_stdout=out, client_stderr=err, client_exit=code)

    # Change a watched file (/etc/hosts is in the default watchlist on every distro).
    agent.target.check("echo '# baseline-diff-test' >> /etc/hosts")

    out2, err2, code2 = run_client(agent, b"diff\nexit\n")
    if code2 != 0:
        fail_with_diagnostics(agent, "diff failed",
                              client_stdout=out2, client_stderr=err2, client_exit=code2)
    if "/etc/hosts" not in out2 or "MODIFIED" not in out2:
        fail_with_diagnostics(agent, "diff did not report the modified /etc/hosts",
                              client_stdout=out2, client_stderr=err2)
