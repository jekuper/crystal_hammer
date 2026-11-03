"""
Non-interactive one-shot mode: `client ... run "<agent command>"` connects, runs a single
agent command, streams its output, and exits with the command's status - no console.
"""

from conftest import AGENT_PORT, REMOTE_DIR, TGT_IP, fail_with_diagnostics


def test_run_noninteractive(agent):
    r = agent.target.sh(
        f"cd {REMOTE_DIR} && ./client --host {TGT_IP} --port {AGENT_PORT} run 'info host'",
        timeout=30)
    out = (r.stdout + r.stderr).decode(errors="replace")
    if r.returncode != 0 or "Hostname" not in out:
        fail_with_diagnostics(
            agent, f"non-interactive run failed (rc={r.returncode})", client_stdout=out)
