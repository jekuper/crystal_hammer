"""
M3 standalone visibility commands: procs / ports / conns. The agent runs in the host pid
namespace and its own network namespace, so it sees all processes and its own sockets.
"""

from conftest import fail_with_diagnostics, run_client


def test_procs_lists_processes(agent):
    out, err, code = run_client(agent, b"procs\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "procs failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if "PID" not in out or "PPID" not in out:
        fail_with_diagnostics(agent, "procs produced no process table",
                              client_stdout=out, client_stderr=err)


def test_ports_shows_agent_listener(agent):
    out, err, code = run_client(agent, b"ports\nexit\n")
    if code != 0 or "2222" not in out:
        fail_with_diagnostics(agent, "ports did not list the agent's listener on 2222",
                              client_stdout=out, client_stderr=err, client_exit=code)


def test_conns_shows_established(agent):
    # The client's own SSH session to the agent (port 2222) is an established connection.
    out, err, code = run_client(agent, b"conns\nexit\n")
    if code != 0 or "2222" not in out:
        fail_with_diagnostics(agent, "conns did not show the live session",
                              client_stdout=out, client_stderr=err, client_exit=code)
