import contextlib

from conftest import (
    ALLOWED_PORT, BLOCKED_PORT,
    can_connect, eventually, fail_with_diagnostics, http_server, run_client,
)


def test_lockdown_allows_one_port_blocks_other(agent):
    with contextlib.ExitStack() as stack:
        stack.enter_context(http_server(agent, ALLOWED_PORT))
        stack.enter_context(http_server(agent, BLOCKED_PORT))

        # BEFORE: both reachable. This proves the servers are up, so a failed
        # connect later really means "blocked", not "never started".
        if not (eventually(lambda: can_connect(agent, ALLOWED_PORT))
                and eventually(lambda: can_connect(agent, BLOCKED_PORT))):
            fail_with_diagnostics(agent, "Test servers didn't come up before lockdown.")

        # ENABLE lockdown, leaving ALLOWED_PORT open
        out, err, code = run_client(agent, f"lockdown {ALLOWED_PORT}\nexit\n".encode())
        if code != 0:
            fail_with_diagnostics(agent, "lockdown command failed",
                                  client_stdout=out, client_stderr=err, client_exit=code)

        # UNDER lockdown. Poll rather than sleep: map updates land shortly
        # after the client exits, and a fixed sleep is either slow or flaky.
        if not eventually(lambda: not can_connect(agent, BLOCKED_PORT, timeout=1)):
            fail_with_diagnostics(agent, f"port {BLOCKED_PORT} reachable under lockdown.",
                                  client_stdout=out, client_stderr=err)
        if not can_connect(agent, ALLOWED_PORT):
            fail_with_diagnostics(agent, f"port {ALLOWED_PORT} unreachable under lockdown.",
                                  client_stdout=out, client_stderr=err)

        # DISABLE lockdown. This also proves the control port survives lockdown.
        out, err, code = run_client(agent, b"unlock\nexit\n")
        if code != 0:
            fail_with_diagnostics(agent, "unlock command failed",
                                  client_stdout=out, client_stderr=err, client_exit=code)

        # AFTER: both reachable again
        if not eventually(lambda: can_connect(agent, BLOCKED_PORT)):
            fail_with_diagnostics(agent, f"port {BLOCKED_PORT} unreachable after unlock.",
                                  client_stdout=out, client_stderr=err)
        if not can_connect(agent, ALLOWED_PORT):
            fail_with_diagnostics(agent, f"port {ALLOWED_PORT} unreachable after unlock.",
                                  client_stdout=out, client_stderr=err)