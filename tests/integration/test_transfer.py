"""
Test file transfers (upload and download) over the SPA-gated SSH channel.
"""

import base64
from conftest import fail_with_diagnostics, run_client

# Deliberately includes a newline and non-ASCII so we'd catch any encoding or
# truncation bug, not just "a short string moved".
PAYLOAD = b"crystal-hammer transfer test\nline2\n\xe2\x9c\x93 \x00binary-ish\n"


def _success(out, err, marker):
    """The success line may land on either stream; check both."""
    return marker in out or marker in err


def _write_target_file(agent, path, data: bytes):
    """Create a file inside the VM with exact bytes, via base64 to dodge
    shell-quoting issues. base64 is present on every image (GNU or busybox)."""
    b64 = base64.b64encode(data).decode()
    agent.target.check(f"echo {b64} | base64 -d > {path}")


def _read_target_file(agent, path) -> bytes:
    """Read a VM file back as raw bytes (base64 over the wire so the
    ssh text layer can't mangle it)."""
    out = agent.target.check(f"base64 {path}")
    return base64.b64decode(out.strip())


def _file_exists(agent, path) -> bool:
    """Check if a file exists on the VM."""
    return agent.target.sh(f"test -f {path}").returncode == 0


def test_upload(agent):
    """upload <local> <remote>: file lands in the agent's filesystem with identical bytes."""
    client_path = "/tmp/ch_client_upload_src.bin"
    agent_path = "/tmp/ch_agent_upload_dst.bin"
    
    _write_target_file(agent, client_path, PAYLOAD)

    out, err, code = run_client(
        agent,
        stdin=f"upload {client_path} {agent_path}\nexit\n".encode(),
    )

    if code != 0:
        fail_with_diagnostics(
            agent, "upload command returned non-zero.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not _success(out, err, "Upload successful"):
        fail_with_diagnostics(
            agent, "Did not see 'Upload successful'.",
            client_stdout=out, client_stderr=err, client_exit=code)

    # The message is only a claim — verify the bytes actually arrived.
    if not _file_exists(agent, agent_path):
        fail_with_diagnostics(
            agent, f"Agent reported success but {agent_path} does not exist.",
            client_stdout=out, client_stderr=err, client_exit=code)

    got = _read_target_file(agent, agent_path)
    if got != PAYLOAD:
        fail_with_diagnostics(
            agent,
            f"Uploaded content mismatch: sent {len(PAYLOAD)} bytes, "
            f"remote has {len(got)}.",
            client_stdout=out, client_stderr=err, client_exit=code)


def test_download(agent):
    """download <remote> <local>: file lands on the client's filesystem with identical bytes."""
    agent_path = "/tmp/ch_agent_download_src.bin"
    client_path = "/tmp/ch_client_download_dst.bin"
    
    _write_target_file(agent, agent_path, PAYLOAD)

    out, err, code = run_client(
        agent,
        stdin=f"download {agent_path} {client_path}\nexit\n".encode(),
    )

    if code != 0:
        fail_with_diagnostics(
            agent, "download command returned non-zero.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not _success(out, err, "Download successful"):
        fail_with_diagnostics(
            agent, "Did not see 'Download successful'.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not _file_exists(agent, client_path):
        fail_with_diagnostics(
            agent, f"Client reported success but {client_path} does not exist.",
            client_stdout=out, client_stderr=err, client_exit=code)

    got = _read_target_file(agent, client_path)
    if got != PAYLOAD:
        fail_with_diagnostics(
            agent,
            f"Downloaded content mismatch: remote had {len(PAYLOAD)} bytes, "
            f"local has {len(got)}.",
            client_stdout=out, client_stderr=err, client_exit=code)


def test_upload_download_roundtrip(agent):
    """Upload a file, download it back to a different path, bytes must survive."""
    src = "/tmp/ch_roundtrip_orig.bin"
    remote = "/tmp/ch_roundtrip_agent.bin"
    dst = "/tmp/ch_roundtrip_final.bin"
    
    _write_target_file(agent, src, PAYLOAD)

    # Both commands in one session, in order.
    out, err, code = run_client(
        agent,
        stdin=(
            f"upload {src} {remote}\n"
            f"download {remote} {dst}\n"
            f"exit\n"
        ).encode(),
    )

    if code != 0:
        fail_with_diagnostics(
            agent, "round-trip session returned non-zero.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not _success(out, err, "Upload successful"):
        fail_with_diagnostics(
            agent, "round-trip: missing 'Upload successful'.",
            client_stdout=out, client_stderr=err, client_exit=code)
            
    if not _success(out, err, "Download successful"):
        fail_with_diagnostics(
            agent, "round-trip: missing 'Download successful'.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not _file_exists(agent, dst):
        fail_with_diagnostics(
            agent, f"round-trip: destination file {dst} was not created.",
            client_stdout=out, client_stderr=err, client_exit=code)

    got = _read_target_file(agent, dst)
    if got != PAYLOAD:
        fail_with_diagnostics(
            agent, "round-trip content did not survive upload+download.",
            client_stdout=out, client_stderr=err, client_exit=code)