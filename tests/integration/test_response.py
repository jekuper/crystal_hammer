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


def test_service_invalid_action(agent):
    """An unknown action is rejected before any init tool is touched."""
    out, err, code = run_client(agent, b"service frobnicate somesvc\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "service command failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if "unknown action" not in out:
        fail_with_diagnostics(agent, "service did not reject an invalid action",
                              client_stdout=out, client_stderr=err)


def test_service_status_invokes_init(agent):
    """`service status` detects the host init system and drives it (the report echoes the
    init command line). Works whether the distro runs systemd, OpenRC, or SysV."""
    out, err, code = run_client(
        agent, b"service status definitely-not-a-real-service-xyz\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "service status failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if not any(tool in out for tool in ("systemctl", "rc-service", "service ")):
        fail_with_diagnostics(agent, "service status did not invoke a known init backend",
                              client_stdout=out, client_stderr=err)


def test_rotate_unknown_user(agent):
    """Rotating a user with no shadow entry is reported, not silently done."""
    out, err, code = run_client(agent, b"rotate ghost_user_xyz\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "rotate command failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if "user not found" not in out:
        fail_with_diagnostics(agent, "rotate did not report an unknown user",
                              client_stdout=out, client_stderr=err)


def test_rotate_locks_and_backs_up(agent):
    """Rotate a throwaway shadow entry: its password is locked, last-change is zeroed, and
    /etc/shadow is backed up. Uses an injected test entry so no real account is touched."""
    agent.target.check("echo 'chrot:$6$abc$def:19000:0:99999:7:::' >> /etc/shadow")

    out, err, code = run_client(agent, b"rotate chrot\nexit\n")
    if code != 0:
        fail_with_diagnostics(agent, "rotate command failed",
                              client_stdout=out, client_stderr=err, client_exit=code)
    if "rotated chrot" not in out or "backed up" not in out:
        fail_with_diagnostics(agent, "rotate did not report locking + backup",
                              client_stdout=out, client_stderr=err)

    line = agent.target.check("grep '^chrot:' /etc/shadow").strip()
    fields = line.split(":")
    if not fields[1].startswith("!"):
        fail_with_diagnostics(agent, f"password not locked: {line}", client_stdout=out)
    if fields[2] != "0":
        fail_with_diagnostics(agent, f"last-change not reset: {line}", client_stdout=out)
    # a shadow backup was created
    backups = agent.target.check("ls /etc/shadow.ch.bak.* 2>/dev/null | wc -l").strip()
    if backups == "0":
        fail_with_diagnostics(agent, "no /etc/shadow backup was created", client_stdout=out)


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
