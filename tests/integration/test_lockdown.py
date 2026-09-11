# test_lockdown.py
import time
import contextlib
import pytest
from conftest import (
    IMAGES, run_client, fail_with_diagnostics,
    python_server_in_container, can_connect,
    ALLOWED_PORT, BLOCKED_PORT,
)


def _wait_up(ip, port, tries=10):
    for _ in range(tries):
        if can_connect(ip, port):
            return True
        time.sleep(0.5)
    return False


@pytest.mark.parametrize("image", IMAGES)
def test_lockdown_allows_one_port_blocks_other(running_agent, build_binaries):
    container = running_agent["container"]
    ctrl_port = running_agent["host_port"]  # mapped 2222, for lockdown/unlock

    with contextlib.ExitStack() as stack:
        ip, ap = stack.enter_context(
            python_server_in_container(container, ALLOWED_PORT))
        _, bp = stack.enter_context(
            python_server_in_container(container, BLOCKED_PORT))

        # BEFORE: both servers up and reachable (firewall not yet locked)
        if not _wait_up(ip, ap) or not _wait_up(ip, bp):
            fail_with_diagnostics(
                container,
                f"Servers didn't come up before lockdown "
                f"(allowed {ip}:{ap}, blocked {ip}:{bp}).")

        assert can_connect(ip, ap), "allowed port should be reachable before lockdown"
        assert can_connect(ip, bp), "blocked port should be reachable before lockdown"

        # ENABLE lockdown, leaving ALLOWED_PORT open
        out, err, code = run_client(
            build_binaries, container, ctrl_port,
            stdin=f"lockdown {ap}\nexit\n".encode())
        if code != 0:
            fail_with_diagnostics(
                container, "lockdown command failed",
                client_stdout=out, client_stderr=err, client_exit=code)
        time.sleep(1)  # let the MODE + ALLOWED_PORTS maps update

        # UNDER lockdown: allowed reachable, blocked not
        if not can_connect(ip, ap):
            fail_with_diagnostics(
                container,
                f"allowed port {ap} unreachable under lockdown — expected open.",
                client_stdout=out, client_stderr=err)
        if can_connect(ip, bp):
            fail_with_diagnostics(
                container,
                f"blocked port {bp} reachable under lockdown — expected blocked.",
                client_stdout=out, client_stderr=err)

        # DISABLE lockdown
        out, err, code = run_client(
            build_binaries, container, ctrl_port, stdin=b"unlock\nexit\n")
        if code != 0:
            fail_with_diagnostics(
                container, "unlock command failed",
                client_stdout=out, client_stderr=err, client_exit=code)
        time.sleep(1)

        # AFTER: both reachable again
        if not can_connect(ip, ap):
            fail_with_diagnostics(
                container, f"allowed port {ap} unreachable after unlock.",
                client_stdout=out, client_stderr=err)
        if not can_connect(ip, bp):
            fail_with_diagnostics(
                container, f"blocked port {bp} unreachable after unlock.",
                client_stdout=out, client_stderr=err)