import pytest
import docker
import os
import subprocess

@pytest.fixture(scope="session")
def docker_client():
    """Provides a Docker client connected to the host's daemon."""
    return docker.from_env()

@pytest.fixture(scope="session")
def build_binaries():
    """
    Ensures that the agent and client binaries exist. 
    If they don't (e.g. during local testing), it triggers 'make build-all'.
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    agent_path = os.path.join(repo_root, "target/agent")
    client_path = os.path.join(repo_root, "target/client")

    # Build if missing
    if not os.path.exists(agent_path) or not os.path.exists(client_path):
        print("\nBinaries not found. Running 'make build-all'...")
        subprocess.run(["make", "build-all"], cwd=repo_root, check=True)

    return {
        "agent": agent_path,
        "client": client_path,
        "repo_root": repo_root
    }