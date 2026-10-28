"""
Active-response commands: `kill` terminates a process by pid, `kick` boots a user's
whole session. The agent shares the host pid namespace (it runs in a network namespace
only), so a process spawned on the target is visible to it.
"""

from conftest import eventually, fail_with_diagnostics, run_client


def test_kill_terminates_process(agent):
    """Spawn a victim, kill it by pid, and confirm it is gone and was named in the report."""
    pid = agent.target.check("setsid sleep 600 >/dev/null 2>&1 & echo $!").strip()
    if agent.target.sh(f"kill -0 {pid}").returncode != 0:
        fail_with_diagnostics(agent, f"victim process {pid} did not start")

    out, err, code = run_client(agent, f"kill {pid} --kill\nexit\n".encode())
    if code != 0:
        fail_with_diagnostics(agent, "kill command failed",
                              client_stdout=out, client_stderr=err, client_exit=code)

    if f"pid {pid}" not in out:
        fail_with_diagnostics(agent, f"kill report did not mention pid {pid}",
                              client_stdout=out, client_stderr=err)

    if not eventually(lambda: agent.target.sh(f"kill -0 {pid}").returncode != 0):
        fail_with_diagnostics(agent, f"process {pid} still alive after kill",
                              client_stdout=out, client_stderr=err)


def test_kick_refuses_root(agent):
    """`kick` must refuse uid 0: killing every root process would take down the host and
    the agent itself."""
    out, err, code = run_client(agent, b"kick root\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "kick command failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if "refusing to kick uid 0" not in out:
        fail_with_diagnostics(agent, "kick did not refuse root",
                              client_stdout=out, client_stderr=err)
