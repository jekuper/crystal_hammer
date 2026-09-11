import pytest
import docker
import tarfile
import io
import time
import os
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

    # Spin up the container (Privileged and with BPF mounted for ch-firewall eBPF)
    container = docker_client.containers.run(
        image,
        command="sleep infinity",
        detach=True,
        privileged=True,
        volumes={'/sys/fs/bpf': {'bind': '/sys/fs/bpf', 'mode': 'rw'}},
        ports={'2222/tcp': None} # Map 2222 to a random ephemeral host port
    )

    try:
        # 1. Drop the agent into the container
        copy_executable_to_container(container, build_binaries["agent"], "/usr/local/bin", "ch-agent")

        # 2. Run the agent in the background
        container.exec_run("/usr/local/bin/ch-agent", detach=True)

        # 3. Wait for the agent to initialize eBPF and bind to the port
        started = False
        for _ in range(10):
            logs = container.logs().decode()
            if "Listening on TCP port 2222" in logs:
                started = True
                break
            time.sleep(1)
        
        assert started, f"Agent failed to start within timeout. Container Logs:\n{container.logs().decode()}"

        # 4. Get the mapped host port so the client can connect
        container.reload()
        mapped_port = container.attrs['NetworkSettings']['Ports']['2222/tcp'][0]['HostPort']

        # 5. Execute the client and pass 'info' followed by 'exit' into the REPL interface via stdin
        cmd = [
            build_binaries["client"], 
            "--host", "127.0.0.1", 
            "--port", str(mapped_port)
        ]
        
        result = subprocess.run(
            cmd,
            input=b"info\nexit\n",
            cwd=build_binaries["repo_root"], # Must run here to find `id_rsa`
            capture_output=True,
            timeout=10
        )

        stdout = result.stdout.decode()
        stderr = result.stderr.decode()

        # 6. Assertions
        assert result.returncode == 0, f"Client returned non-zero!\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        
        # Verify SSH connection worked
        assert "Authenticated SSH session established" in stderr, "Client failed to authenticate."
        
        # Verify the `info` command successfully gathered metrics
        assert "Host Information" in stdout or "Firewall" in stdout, f"Missing 'info' output. STDOUT:\n{stdout}"

    finally:
        # Ensure we always clean up the container, even on test failure
        container.remove(force=True)