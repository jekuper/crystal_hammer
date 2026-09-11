import pytest
import docker
import tarfile
import io
import time
import os
import subprocess

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# The list of target distributions to emulate. Referenced by tests via the
# `image` parametrize marker; kept here so every test file shares one list.
IMAGES = [
    "alpine:latest",
    "ubuntu:24.04",
    "ubuntu:16.04",
    "debian:12",
    "rockylinux:9",
    "opensuse/leap:latest",       # Enterprise stable SUSE
    "opensuse/tumbleweed:latest"  # Bleeding-edge SUSE
]

# Where the agent's stdout/stderr is captured inside each container.
AGENT_LOG = "/tmp/agent.log"


# ---------------------------------------------------------------------------
# Session-scoped fixtures (Docker + build)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def docker_client():
    """Provides a Docker client connected to the host's daemon."""
    return docker.from_env()


@pytest.fixture(scope="session")
def build_binaries():
    """
    Ensures that the agent and client binaries exist.
    If they don't, it generates the keypair and triggers 'make build-all'.
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    agent_path = os.path.join(repo_root, "target/agent")
    client_path = os.path.join(repo_root, "target/client")
    key_path = os.path.join(repo_root, "id_rsa")

    # 1. Generate keypair if missing (required at compile-time by agent & runtime by client)
    if not os.path.exists(key_path):
        print("\nNo team key found. Generating temporary test keypair...")
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", "id_rsa", "-C", "local-test-key"],
            cwd=repo_root,
            check=True,
        )

    # 2. Build binaries if missing
    if not os.path.exists(agent_path) or not os.path.exists(client_path):
        print("\nBinaries not found. Running 'make build-all'...")
        subprocess.run(["make", "build-all"], cwd=repo_root, check=True)

    return {
        "agent": agent_path,
        "client": client_path,
        "repo_root": repo_root,
    }


# ---------------------------------------------------------------------------
# Container helpers
# ---------------------------------------------------------------------------

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


def run_client(build_binaries, container, mapped_port, stdin, timeout=10):
    """
    Runs the client against a mapped port, feeding `stdin` to its REPL.

    Returns (stdout, stderr, returncode) as decoded strings/int. On timeout it
    dumps full diagnostics (agent log + partial client output) and fails the
    test — it never returns in that case.
    """
    cmd = [
        build_binaries["client"],
        "--host", "127.0.0.1",
        "--port", str(mapped_port),
    ]
    try:
        result = subprocess.run(
            cmd,
            input=stdin,
            cwd=build_binaries["repo_root"],  # Must run here to find `id_rsa`
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        fail_with_diagnostics(
            container,
            "Client timed out (never returned).",
            client_stdout=(e.stdout or b"").decode(errors="replace"),
            client_stderr=(e.stderr or b"").decode(errors="replace"),
        )

    return (
        result.stdout.decode(errors="replace"),
        result.stderr.decode(errors="replace"),
        result.returncode,
    )


# ---------------------------------------------------------------------------
# The running-agent fixture: one privileged container with ch-agent bound
# ---------------------------------------------------------------------------

@pytest.fixture
def running_agent(docker_client, build_binaries, image):
    """
    Yields a dict describing a container that has ch-agent running and listening
    on port 2222, plus the ephemeral host port it's mapped to.

    Any test that needs a live agent depends on this fixture and receives:
        {
            "container":   <docker container object>,
            "host_port":   <str, the mapped 127.0.0.1 port>,
        }

    The container is always torn down afterward, even on failure.
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
        ports={'2222/tcp': None},  # Map 2222 to a random ephemeral host port
    )

    try:
        # Drop the agent in
        copy_executable_to_container(
            container, build_binaries["agent"], "/usr/local/bin", "ch-agent"
        )

        # Run it in the background, capturing output to a file we can read
        # (container.logs() only sees the main `sleep infinity` process).
        container.exec_run(
            f"sh -c '/usr/local/bin/ch-agent > {AGENT_LOG} 2>&1'",
            detach=True,
        )

        # Wait for it to initialize eBPF and bind
        started = False
        for _ in range(10):
            if "Listening on TCP port 2222" in read_agent_log(container):
                started = True
                break
            time.sleep(1)

        if not started:
            fail_with_diagnostics(container, "Agent failed to start within timeout.")

        # Resolve the mapped host port
        container.reload()
        host_port = container.attrs['NetworkSettings']['Ports']['2222/tcp'][0]['HostPort']

        yield {"container": container, "host_port": host_port}

    finally:
        container.remove(force=True)