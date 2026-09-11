"""
Integration scenarios that exercise a live ch-agent inside a container.

Everything reusable lives in conftest.py:
  - IMAGES                     the distros we emulate
  - running_agent (fixture)    a privileged container with ch-agent listening
  - run_client(...)            runs the client REPL, handles timeouts
  - fail_with_diagnostics(...) dumps agent log + client output on failure

To add a scenario, write a new `test_*` function that takes `running_agent`
and `build_binaries`, drive the client with run_client(), and route every
failure through fail_with_diagnostics() so you always get full logs.
"""

import pytest

from conftest import IMAGES, run_client, fail_with_diagnostics


@pytest.mark.parametrize("image", IMAGES)
def test_agent_connectivity(running_agent, build_binaries):
    """
    Baseline: the client can knock, authenticate, and run `info` against the
    agent on every supported distro.
    """
    container = running_agent["container"]
    stdout, stderr, code = run_client(
        build_binaries, container, running_agent["host_port"],
        stdin=b"info\nexit\n",
    )

    if code != 0:
        fail_with_diagnostics(
            container, "Client returned non-zero.",
            client_stdout=stdout, client_stderr=stderr, client_exit=code,
        )

    if "Authenticated SSH session established" not in stdout:
        fail_with_diagnostics(
            container, "Client failed to authenticate.",
            client_stdout=stdout, client_stderr=stderr, client_exit=code,
        )

    if "Host Information" not in stdout and "Firewall" not in stdout:
        fail_with_diagnostics(
            container, "Missing 'info' output.",
            client_stdout=stdout, client_stderr=stderr, client_exit=code,
        )


# ---------------------------------------------------------------------------
# Add further scenarios below. Template:
#
# @pytest.mark.parametrize("image", IMAGES)
# def test_<behavior>(running_agent, build_binaries):
#     container = running_agent["container"]
#     stdout, stderr, code = run_client(
#         build_binaries, container, running_agent["host_port"],
#         stdin=b"<repl commands>\nexit\n",
#     )
#     if <not what we expect>:
#         fail_with_diagnostics(
#             container, "<what went wrong>",
#             client_stdout=stdout, client_stderr=stderr, client_exit=code,
#         )
#
# If a scenario needs to change agent state first (e.g. flip to lockdown mode),
# use container.exec_run(...) before run_client, and assert on the agent log via
# read_agent_log(container) where relevant.
# ---------------------------------------------------------------------------