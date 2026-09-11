import pytest
import docker
import tarfile
import io
import time
import subprocess

# The list of target distributions to emulate
IMAGES = [
    "alpine:latest",
    "ubuntu:24.04",
    "ubuntu:16.04",
    "debian:12",
    "rockylinux:9",
    "opensuse/leap:latest",       # Enterprise stable SUSE
    "opensuse/tumbleweed:latest"  # Bleeding-edge SUSE
]

AGENT_LOG = "/tmp/agent.log"


def copy_executable_to_container(container, src_path, dest_dir, dest_name="agent"):
    """Copies a binary from the host into the container and makes it executable."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as tar:
        tarinfo = tarfile.TarInfo(name=dest_name)
        with open(src_path, 'rb') as f:
            data = f.read()
        tarinfo.size = len(data)
        tarinfo.mode = 0o755  # Make it executable
        tar.addfile(tarinfo, io.BytesIO(data))

    stream.seek(0)
    container.put_archive(dest_dir, stream)


def read_agent_log(container):
    """Reads the agent's captured stdout/stderr from inside the container."""
    try:
        code, out = container.exec_run(f"cat {AGENT_LOG}")
        text = out.decode(errors="replace")
        if code != 0 and not text.strip():
            return "(no agent log — file missing or agent never wrote anything)"
        return text
    except Exception as e:  # container gone, daemon hiccup, etc.
        return f"(could not read agent log: {e})"


def fail_with_diagnostics(container, message, *, client_stdout="", client_stderr="",
                          client_exit=None):
    """
    Aborts the test with everything we know: the message, the agent's own log,
    and whatever the client printed. One place that formats all failures the
    same way, so no matter which step breaks you get the full picture.
    """
    agent_log = read_agent_log(container)
    report = [
        message,
        "",
        "================ AGENT LOG (inside container) ================",
        agent_log.rstrip() or "(empty)",
        "================ CLIENT STDOUT ==============================",
        client_stdout.rstrip() or "(empty)",
        "================ CLIENT STDERR ==============================",
        client_stderr.rstrip() or "(empty)",
    ]
    if client_exit is not None:
        report.append(f"================ CLIENT EXIT: {client_exit} ================")
    pytest.fail("\n".join(report), pytrace=False)


@pytest.mark.parametrize("image", IMAGES)
def test_agent_connectivity(docker_client, build_binaries, image):
    """
    Drops the agent into a specific OS container, launches it, and ensures
    the client can successfully knock, connect, and execute a command.
    """
    # Pull image if it doesn't exist locally
    try:
        docker_client.images.get(image)
    except docker.errors.ImageNotFound:
        docker_client.images.pull(image)

    # Spin up the container (privileged and with BPF mounted for ch-firewall eBPF)
    container = docker_client.containers.run(
        image,
        command="sleep infinity",
        detach=True,
        privileged=True,
        volumes={'/sys/fs/bpf': {'bind': '/sys/fs/bpf', 'mode': 'rw'}},
        ports={'2222/tcp': None}  # Map 2222 to a random ephemeral host port
    )

    try:
        # 1. Drop the agent into the container
        copy_executable_to_container(
            container, build_binaries["agent"], "/usr/local/bin", "ch-agent"
        )

        # 2. Run the agent in the background, capturing its output to a file so
        #    we can actually see why it failed (container.logs() only sees the
        #    main `sleep infinity` process, not this exec).
        container.exec_run(
            f"sh -c '/usr/local/bin/ch-agent > {AGENT_LOG} 2>&1'",
            detach=True,
        )

        # 3. Wait for the agent to initialize eBPF and bind to the port
        started = False
        for _ in range(10):
            if "Listening on TCP port 2222" in read_agent_log(container):
                started = True
                break
            time.sleep(1)

        if not started:
            fail_with_diagnostics(
                container,
                "Agent failed to start within timeout.",
            )

        # 4. Get the mapped host port so the client can connect
        container.reload()
        mapped_port = container.attrs['NetworkSettings']['Ports']['2222/tcp'][0]['HostPort']

        # 5. Execute the client and pass 'info' then 'exit' into the REPL via stdin
        cmd = [
            build_binaries["client"],
            "--host", "127.0.0.1",
            "--port", str(mapped_port),
        ]

        try:
            result = subprocess.run(
                cmd,
                input=b"info\nexit\n",
                cwd=build_binaries["repo_root"],  # Must run here to find `id_rsa`
                capture_output=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired as e:
            # On timeout the partial output is on the exception, not `result`.
            fail_with_diagnostics(
                container,
                "Client timed out (never returned).",
                client_stdout=(e.stdout or b"").decode(errors="replace"),
                client_stderr=(e.stderr or b"").decode(errors="replace"),
            )

        stdout = result.stdout.decode(errors="replace")
        stderr = result.stderr.decode(errors="replace")

        # 6. Assertions — every failure routes through the same diagnostics dump.
        if result.returncode != 0:
            fail_with_diagnostics(
                container, "Client returned non-zero.",
                client_stdout=stdout, client_stderr=stderr,
                client_exit=result.returncode,
            )

        if "Authenticated SSH session established" not in stdout:
            fail_with_diagnostics(
                container, "Client failed to authenticate.",
                client_stdout=stdout, client_stderr=stderr,
                client_exit=result.returncode,
            )

        if "Host Information" not in stdout and "Firewall" not in stdout:
            fail_with_diagnostics(
                container, "Missing 'info' output.",
                client_stdout=stdout, client_stderr=stderr,
                client_exit=result.returncode,
            )

    finally:
        # Ensure we always clean up the container, even on test failure
        container.remove(force=True)