# tests/integration/test_transfer.py
import base64
import time
import pytest
from conftest import (
    IMAGES, run_client, fail_with_diagnostics,
)

# Deliberately includes a newline and non-ASCII so we'd catch any encoding or
# truncation bug, not just "a short string moved".
PAYLOAD = "crystal-hammer transfer test\nline2\n\xe2\x9c\x93 \x00binary-ish\n".encode("utf-8", "surrogateescape")


def _success(out, err, marker):
    """The success line may land on either stream; check both."""
    return marker in out or marker in err


def _write_remote_file(container, path, data: bytes):
    """Create a file inside the container with exact bytes, via base64 to dodge
    shell-quoting issues. base64 is present on every image (GNU or busybox)."""
    b64 = base64.b64encode(data).decode()
    code, out = container.exec_run(["sh", "-c", f"echo {b64} | base64 -d > {path}"])
    assert code == 0, f"failed to seed remote file {path}: {out.decode(errors='replace')}"


def _read_remote_file(container, path) -> bytes:
    """Read a container file back as raw bytes (base64 over the wire so the
    exec_run text layer can't mangle it)."""
    code, out = container.exec_run(["sh", "-c", f"base64 {path}"])
    assert code == 0, f"failed to read remote file {path}: {out.decode(errors='replace')}"
    return base64.b64decode(out)


@pytest.mark.parametrize("image", IMAGES)
def test_upload(running_agent, build_binaries, tmp_path):
    """upload <local> <remote>: file lands in the container with identical bytes."""
    container = running_agent["container"]
    port = running_agent["host_port"]

    local = tmp_path / "to_upload.bin"
    local.write_bytes(PAYLOAD)
    remote = "/tmp/ch_uploaded.bin"

    out, err, code = run_client(
        build_binaries, container, port,
        stdin=f"upload {local} {remote}\nexit\n".encode(),
    )

    if code != 0:
        fail_with_diagnostics(
            container, "upload command returned non-zero.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not _success(out, err, "Upload successful"):
        fail_with_diagnostics(
            container, "Did not see 'Upload successful'.",
            client_stdout=out, client_stderr=err, client_exit=code)

    # The message is only a claim — verify the bytes actually arrived.
    got = _read_remote_file(container, remote)
    if got != PAYLOAD:
        fail_with_diagnostics(
            container,
            f"Uploaded content mismatch: sent {len(PAYLOAD)} bytes, "
            f"remote has {len(got)}.",
            client_stdout=out, client_stderr=err, client_exit=code)


@pytest.mark.parametrize("image", IMAGES)
def test_download(running_agent, build_binaries, tmp_path):
    """download <remote> <local>: file lands on the host with identical bytes."""
    container = running_agent["container"]
    port = running_agent["host_port"]

    remote = "/tmp/ch_to_download.bin"
    _write_remote_file(container, remote, PAYLOAD)
    local = tmp_path / "downloaded.bin"

    out, err, code = run_client(
        build_binaries, container, port,
        stdin=f"download {remote} {local}\nexit\n".encode(),
    )

    if code != 0:
        fail_with_diagnostics(
            container, "download command returned non-zero.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not _success(out, err, "Download successful"):
        fail_with_diagnostics(
            container, "Did not see 'Download successful'.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not local.exists():
        fail_with_diagnostics(
            container, f"Client reported success but {local} does not exist.",
            client_stdout=out, client_stderr=err, client_exit=code)

    got = local.read_bytes()
    if got != PAYLOAD:
        fail_with_diagnostics(
            container,
            f"Downloaded content mismatch: remote had {len(PAYLOAD)} bytes, "
            f"local has {len(got)}.",
            client_stdout=out, client_stderr=err, client_exit=code)


@pytest.mark.parametrize("image", IMAGES)
def test_upload_download_roundtrip(running_agent, build_binaries, tmp_path):
    """Upload a file, download it back to a different path, bytes must survive."""
    container = running_agent["container"]
    port = running_agent["host_port"]

    src = tmp_path / "orig.bin"
    src.write_bytes(PAYLOAD)
    remote = "/tmp/ch_roundtrip.bin"
    dst = tmp_path / "roundtrip.bin"

    # Both commands in one session, in order.
    out, err, code = run_client(
        build_binaries, container, port,
        stdin=(
            f"upload {src} {remote}\n"
            f"download {remote} {dst}\n"
            f"exit\n"
        ).encode(),
    )

    if code != 0:
        fail_with_diagnostics(
            container, "round-trip session returned non-zero.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not _success(out, err, "Upload successful"):
        fail_with_diagnostics(
            container, "round-trip: missing 'Upload successful'.",
            client_stdout=out, client_stderr=err, client_exit=code)
    if not _success(out, err, "Download successful"):
        fail_with_diagnostics(
            container, "round-trip: missing 'Download successful'.",
            client_stdout=out, client_stderr=err, client_exit=code)

    if not dst.exists() or dst.read_bytes() != PAYLOAD:
        fail_with_diagnostics(
            container, "round-trip content did not survive upload+download.",
            client_stdout=out, client_stderr=err, client_exit=code)