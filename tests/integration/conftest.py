"""
Integration harness for ch-agent. Runs against a real kernel.

Every test talks to a *target*: a machine (normally a VM) where we can run
shell commands as root. Choose it with CH_TARGET:

    ssh://root@127.0.0.1:2200   a VM booted by CI (one kernel/distro per job)
    docker://debian:12          a privileged container for a fast local loop
                                (NOTE: this uses YOUR host kernel)

Optional env:
    CH_SSH_KEY       private key for ssh targets
    CH_BIN_DIR       dir holding prebuilt `agent`, `client`, `id_rsa`
                     (default: build from the repo with `make build-all`)
    CH_AGENT_ARGS    extra args for ch-agent (e.g. an interface flag)
    CH_DOCKER_PREP   setup command for docker targets

Inside the target the agent runs in its own network namespace, wired to the
root namespace with a veth pair:

    root netns: client + probes            netns "chtest": agent + servers
    ch-host 10.99.0.1/24  <==== veth ====>  ch-tgt 10.99.0.2/24

Every probe is a real packet through the target kernel's datapath. The
firewall only ever sees ch-tgt, so a lockdown bug cannot cut off the SSH
session that is driving the test.
"""

import contextlib
import os
import shlex
import subprocess
import time
import uuid
from urllib.parse import urlparse

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NETNS = "chtest"
HOST_IF, TGT_IF = "ch-host", "ch-tgt"
HOST_IP, TGT_IP = "10.99.0.1", "10.99.0.2"

AGENT_PORT = 2222
ALLOWED_PORT = 8001   # passed to `lockdown`, must stay reachable
BLOCKED_PORT = 8002   # NOT passed, must be blocked under lockdown

REMOTE_DIR = "/opt/ch"
AGENT_LOG = "/tmp/ch-agent.log"
AGENT_PID = "/tmp/ch-agent.pid"
AGENT_ARGS = os.environ.get("CH_AGENT_ARGS", "")

# Where the agent pins its eBPF maps/programs/links. A bpffs pin is a refcount
# independent of the netns, so it OUTLIVES the per-test netns teardown and the
# next agent trips over it while "Loading persistence mechanisms...". We wipe
# it in teardown. Point this at the agent's real pin path (grep the source for
# bpf_obj_pin / aya's map.pin(...) / PinnedLink). "" disables the wipe.
BPF_PIN_DIR = os.environ.get("CH_BPF_PIN_DIR", "/sys/fs/bpf/crystal_hammer")

# Belt-and-suspenders: give each agent its own private bpffs so nothing can
# leak even if the wipe misses. Costs a mount namespace per agent. Set
# CH_FRESH_BPFFS=0 to fall back to the shared host /sys/fs/bpf.
FRESH_BPFFS = os.environ.get("CH_FRESH_BPFFS", "1") == "1"

# Enter ONLY the network namespace. `ip netns exec` would also unshare the
# mount namespace and remount /sys, which hides /sys/fs/bpf from the agent.
# With FRESH_BPFFS we DO unshare the mount ns ourselves and remount a private
# bpffs over /sys/fs/bpf — that gives isolation without hiding the fs.
if FRESH_BPFFS:
    IN_NS = (f"nsenter --net=/var/run/netns/{NETNS} "
             f"unshare --mount -- sh -c "
             f"'mount --make-rprivate / 2>/dev/null; "
             f"mount -t bpf bpf /sys/fs/bpf; exec \"$@\"' --")
else:
    IN_NS = f"nsenter --net=/var/run/netns/{NETNS}"

REQUIRED_TOOLS = ["ip", "nsenter", "setsid", "timeout", "python3"]

_NETNS_DOWN = f"""
ip netns del {NETNS} 2>/dev/null
ip link del {HOST_IF} 2>/dev/null
true
"""

_NETNS_UP = _NETNS_DOWN + f"""
set -e
ip netns add {NETNS}
ip link add {HOST_IF} type veth peer name {TGT_IF}
ip link set {TGT_IF} netns {NETNS}
ip addr add {HOST_IP}/24 dev {HOST_IF}
ip link set {HOST_IF} up
{IN_NS} ip link set lo up
{IN_NS} ip addr add {TGT_IP}/24 dev {TGT_IF}
{IN_NS} ip link set {TGT_IF} up
"""

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


class Target:
    """Something with its own kernel that we can run root shell scripts on."""

    name = "target"

    def sh(self, script, *, stdin=None, timeout=60):
        raise NotImplementedError

    def close(self):
        pass

    def check(self, script, **kw):
        r = self.sh(script, **kw)
        if r.returncode != 0:
            raise RuntimeError(
                f"[{self.name}] command failed (rc={r.returncode}):\n{script}\n"
                f"--- stdout ---\n{r.stdout.decode(errors='replace')}\n"
                f"--- stderr ---\n{r.stderr.decode(errors='replace')}")
        return r.stdout.decode(errors="replace")

    def put(self, local_path, remote_path, mode="755"):
        with open(local_path, "rb") as f:
            data = f.read()
        d = os.path.dirname(remote_path)
        self.check(f"mkdir -p {d} && cat > {remote_path} && chmod {mode} {remote_path}",
                   stdin=data)


class SshTarget(Target):
    def __init__(self, user, host, port, key=None):
        self.name = f"ssh:{user}@{host}:{port}"
        self.dest = f"{user}@{host}"
        # ControlMaster reuses one TCP+auth handshake for every command.
        self._ctl = f"/tmp/ch-ssh-{uuid.uuid4().hex[:8]}"
        self._ssh = [
            "ssh", "-p", str(port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "BatchMode=yes",
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={self._ctl}",
            "-o", "ControlPersist=300",
        ]
        if key:
            self._ssh += ["-i", key]

    def sh(self, script, *, stdin=None, timeout=60):
        return subprocess.run(
            self._ssh + [self.dest, "sh -c " + shlex.quote(script)],
            input=stdin if stdin is not None else b"",
            capture_output=True, timeout=timeout)

    def close(self):
        subprocess.run(self._ssh + ["-O", "exit", self.dest], capture_output=True)


class DockerTarget(Target):
    """Local convenience only: shares the host kernel, so it proves nothing
    about other kernels. Use it to iterate on tests quickly."""

    DEFAULT_PREP = ("apt-get update -qq && DEBIAN_FRONTEND=noninteractive "
                    "apt-get install -y -qq iproute2 python3 util-linux >/dev/null")

    def __init__(self, image):
        self.name = f"docker:{image}"
        self.cid = subprocess.check_output([
            "docker", "run", "-d", "--privileged",
            "-v", "/sys/fs/bpf:/sys/fs/bpf",
            image, "sleep", "infinity"]).decode().strip()
        prep = os.environ.get("CH_DOCKER_PREP", self.DEFAULT_PREP)
        if prep:
            self.check(prep, timeout=600)

    def sh(self, script, *, stdin=None, timeout=60):
        return subprocess.run(
            ["docker", "exec", "-i", self.cid, "sh", "-c", script],
            input=stdin if stdin is not None else b"",
            capture_output=True, timeout=timeout)

    def close(self):
        subprocess.run(["docker", "rm", "-f", self.cid], capture_output=True)


def make_target(spec):
    u = urlparse(spec)
    if u.scheme == "ssh":
        return SshTarget(u.username or "root", u.hostname, u.port or 22,
                         os.environ.get("CH_SSH_KEY"))
    if u.scheme == "docker":
        return DockerTarget(spec[len("docker://"):])
    raise pytest.UsageError(f"Unsupported CH_TARGET: {spec!r}")


# ---------------------------------------------------------------------------
# Session fixtures: binaries + one target for the whole run
# ---------------------------------------------------------------------------


def _build_locally():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    key_path = os.path.join(repo_root, "id_rsa")
    agent = os.path.join(repo_root, "target/agent")
    client = os.path.join(repo_root, "target/client")

    if not os.path.exists(key_path):
        print("\nNo team key found. Generating temporary test keypair...")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", "id_rsa",
                        "-C", "local-test-key"], cwd=repo_root, check=True)
    if not (os.path.exists(agent) and os.path.exists(client)):
        print("\nBinaries not found. Running 'make build-all'...")
        subprocess.run(["make", "build-all"], cwd=repo_root, check=True)

    return {"agent": agent, "client": client, "id_rsa": key_path}


@pytest.fixture(scope="session")
def binaries():
    bin_dir = os.environ.get("CH_BIN_DIR")
    if bin_dir:
        paths = {n: os.path.abspath(os.path.join(bin_dir, n))
                 for n in ("agent", "client", "id_rsa")}
    else:
        paths = _build_locally()
    missing = [p for p in paths.values() if not os.path.exists(p)]
    if missing:
        pytest.exit(f"Missing binaries: {missing}", returncode=2)
    return paths


@pytest.fixture(scope="session")
def target(binaries):
    t = make_target(os.environ.get("CH_TARGET", "docker://debian:12"))
    try:
        missing = t.sh(
            "for c in " + " ".join(REQUIRED_TOOLS) +
            "; do command -v $c >/dev/null || echo $c; done").stdout.decode().split()
        if missing:
            pytest.exit(f"[{t.name}] harness tools missing on target: {missing}", returncode=2)

        t.put(binaries["agent"], f"{REMOTE_DIR}/ch-agent")
        t.put(binaries["client"], f"{REMOTE_DIR}/client")
        t.put(binaries["id_rsa"], f"{REMOTE_DIR}/id_rsa", mode="600")
        yield t
    finally:
        t.close()


# ---------------------------------------------------------------------------
# The running-agent fixture
# ---------------------------------------------------------------------------


class Agent:
    def __init__(self, target):
        self.target = target


def _agent_alive(target):
    return target.sh(f"kill -0 $(cat {AGENT_PID}) 2>/dev/null").returncode == 0


def bpf_snapshot(target, when):
    """Dump everything that could leak between agents. Printed to the captured
    test log (visible with -s or on failure) so a repeat hang is diagnosable
    without another round-trip: compare the BEFORE of the failing test to the
    AFTER of the one before it."""
    script = f"""
    echo '--- bpf mounts ---'; mount 2>/dev/null | grep -i bpf || echo '(none)'
    echo '--- /sys/fs/bpf tree ---'; ls -lAR /sys/fs/bpf 2>/dev/null || echo '(missing)'
    echo '--- pin dir ({BPF_PIN_DIR}) ---'
    ls -lA {BPF_PIN_DIR} 2>/dev/null || echo '(absent)'
    echo '--- bpftool prog/map (if present) ---'
    command -v bpftool >/dev/null && {{ bpftool prog show 2>/dev/null; bpftool map show 2>/dev/null; }} || echo '(no bpftool)'
    echo '--- stray ch-agent procs ---'; ps -eo pid,ppid,args 2>/dev/null | grep -F ch-agent | grep -v grep || echo '(none)'
    echo '--- port {AGENT_PORT} listeners ---'; ss -ltnp 2>/dev/null | grep ':{AGENT_PORT} ' || echo '(none)'
    echo '--- GLOBAL (non-netns) leak surfaces ---'
    echo 'cgroup-attached bpf:'
    if command -v bpftool >/dev/null; then bpftool cgroup tree 2>/dev/null | head -n 30 || echo '(query failed)'; else echo '(no bpftool — install to see cgroup progs)'; fi
    echo 'kernel bpf prog/map ids (leak = growing count):'
    if command -v bpftool >/dev/null; then echo "progs=$(bpftool prog show 2>/dev/null | grep -c '^[0-9]') maps=$(bpftool map show 2>/dev/null | grep -c '^[0-9]')"; else echo '(no bpftool)'; fi
    echo 'SysV IPC:'; ipcs -a 2>/dev/null | grep -A3 -iE 'semaphore|shared' | grep '^0x' || echo '(none)'
    echo 'ch-* systemd units:'; systemctl list-units --all --no-legend 2>/dev/null | grep -iE 'crystal|ch-' || echo '(none)'
    echo 'agent-owned lock/pid files (common dirs):'
    ls -lt /run /var/run /tmp /var/lib 2>/dev/null | grep -iE 'crystal|ch[-_]?agent|ch[.](lock|pid)' || echo '(none obvious)'
    """
    print(f"\n======== BPF SNAPSHOT [{when}] on {target.name} ========")
    print(_try(target, script).rstrip())
    print("======== END SNAPSHOT ========")


def hung_agent_report(target):
    """The agent is alive but stuck. Capture WHERE. /proc/<pid>/{stack,wchan,
    syscall} and the per-thread states name the exact block: a futex means a
    userspace lock/mutex; flock in syscall + a lock file in fd means a file
    lock; a connect/read on a socket points at IPC or dbus. strace (if present)
    shows the syscall it's spinning or sleeping in live."""
    script = f"""
    pid=$(pgrep -f '{REMOTE_DIR}/ch-agent' | head -1)
    [ -z "$pid" ] && pid=$(cat {AGENT_PID} 2>/dev/null)
    echo "agent pid: ${{pid:-<none>}}"
    [ -z "$pid" ] && exit 0
    echo '--- status ---'; grep -E '^(State|Threads|VmLck|SigBlk):' /proc/$pid/status 2>/dev/null
    echo '--- wchan (kernel sleep symbol) ---'; cat /proc/$pid/wchan 2>/dev/null; echo
    echo '--- syscall (nr + args; first field is the syscall number) ---'; cat /proc/$pid/syscall 2>/dev/null
    echo '--- kernel stack ---'; cat /proc/$pid/stack 2>/dev/null || echo '(needs root + CONFIG_STACKTRACE)'
    echo '--- per-thread state/wchan/stack ---'
    for t in /proc/$pid/task/*; do
      echo "thread ${{t##*/}}: wchan=$(cat $t/wchan 2>/dev/null)"
      cat $t/stack 2>/dev/null
    done
    echo '--- open fds (a lock file / socket the agent waits on shows here) ---'; ls -l /proc/$pid/fd 2>/dev/null
    echo '--- fdinfo flock lines ---'; grep -l . /proc/$pid/fdinfo/* 2>/dev/null | xargs grep -H -i 'lock' 2>/dev/null | head
    echo '--- strace 2s ---'
    if command -v strace >/dev/null; then timeout 2 strace -f -tt -p $pid 2>&1 | tail -n 40; else echo '(no strace — install strace in the VM)'; fi
    """
    print(f"\n======== HUNG AGENT REPORT on {target.name} ========")
    print(_try(target, script).rstrip())
    print("======== END HUNG AGENT REPORT ========")


def _kill_agent_tree(target):
    """Kill the whole process group, not just the recorded PID.

    `setsid X & echo $!` records setsid's PID, which may differ from ch-agent's
    and, since setsid starts a new session/group, `kill $pid` won't reach the
    child. Killing the negative PGID gets the agent and anything it spawned."""
    return target.sh(f"""
        p=$(cat {AGENT_PID} 2>/dev/null) || true
        if [ -n "$p" ]; then
            pgid=$(ps -o pgid= -p "$p" 2>/dev/null | tr -d ' ')
            [ -n "$pgid" ] && kill -TERM -"$pgid" 2>/dev/null
            kill -TERM "$p" 2>/dev/null
            sleep 0.5
            [ -n "$pgid" ] && kill -KILL -"$pgid" 2>/dev/null
            kill -KILL "$p" 2>/dev/null
        fi
        # Sweep any ch-agent that escaped the pgid bookkeeping.
        pkill -KILL -f '{REMOTE_DIR}/ch-agent' 2>/dev/null
        rm -f {AGENT_PID}
        true
    """)


@pytest.fixture
def agent(target):
    """
    Fresh netns + fresh agent per test. The agent sees exactly one
    non-loopback interface (ch-tgt). If it needs a flag to pick an interface,
    set CH_AGENT_ARGS.
    """
    # Snapshot BEFORE we start: if a previous test leaked bpffs pins or a stray
    # process, it shows up here as the actual cause of the coming failure.
    bpf_snapshot(target, "before start")

    target.check(_NETNS_UP)
    target.check(
        f"setsid {IN_NS} {REMOTE_DIR}/ch-agent {AGENT_ARGS} "
        f"</dev/null >{AGENT_LOG} 2>&1 & echo $! > {AGENT_PID}")
    a = Agent(target)
    try:
        deadline = time.monotonic() + 15
        while f"Listening on TCP port {AGENT_PORT}" not in read_agent_log(a):
            if not _agent_alive(target):
                fail_with_diagnostics(a, "Agent exited during startup.")
            if time.monotonic() > deadline:
                # Snapshot again on the hang so the failure report carries the
                # live state, not just the log that stops at "Loading...".
                bpf_snapshot(target, "on startup timeout")
                # And capture exactly where the alive-but-stuck agent is blocked.
                hung_agent_report(target)
                fail_with_diagnostics(a, "Agent failed to start within 15s.")
            time.sleep(0.3)
        yield a
    finally:
        _kill_agent_tree(target)
        target.sh(_NETNS_DOWN)
        # Remove the pin dir so eBPF state can't leak into the next test. This
        # is the missing cleanup that let a stale pin block the second agent.
        if BPF_PIN_DIR:
            target.sh(f"rm -rf {BPF_PIN_DIR} 2>/dev/null; true")
        bpf_snapshot(target, "after teardown")


# ---------------------------------------------------------------------------
# Helpers used by tests
# ---------------------------------------------------------------------------


def _try(target, script):
    try:
        r = target.sh(script, timeout=20)
        return (r.stdout + r.stderr).decode(errors="replace")
    except Exception as e:  # VM gone, ssh hiccup, etc.
        return f"(could not run: {e})"


def read_agent_log(agent):
    return _try(agent.target, f"cat {AGENT_LOG} 2>/dev/null")


def fail_with_diagnostics(agent, message, *, client_stdout="", client_stderr="",
                          client_exit=None):
    """Abort with everything we know, formatted the same way for every failure."""
    t = agent.target
    # Plain netns enter (no mount unshare) for read-only inspection.
    netns = f"nsenter --net=/var/run/netns/{NETNS}"
    sections = [
        ("TARGET", t.name),
        ("KERNEL", _try(t, "uname -a; . /etc/os-release 2>/dev/null; echo \"$PRETTY_NAME\"")),
        ("AGENT LOG", read_agent_log(agent)),
        (f"{TGT_IF} (attached programs)", _try(t, f"{netns} ip -d link show {TGT_IF} 2>/dev/null")),
        ("BPF PINS / PROCS",
         _try(t, f"echo 'mounts:'; mount 2>/dev/null | grep -i bpf || echo '(none)'; "
                 f"echo 'pin dir {BPF_PIN_DIR}:'; ls -lA {BPF_PIN_DIR} 2>/dev/null || echo '(absent)'; "
                 f"echo 'ch-agent procs:'; ps -eo pid,ppid,pgid,args 2>/dev/null | grep -F ch-agent | grep -v grep || echo '(none)'")),
        ("DMESG (tail)", _try(t, "dmesg 2>/dev/null | tail -n 40")),
        ("CLIENT STDOUT", client_stdout),
        ("CLIENT STDERR", client_stderr),
    ]
    report = [message, ""]
    for title, body in sections:
        report += [f"================ {title} ================", body.rstrip() or "(empty)"]
    if client_exit is not None:
        report.append(f"================ CLIENT EXIT: {client_exit} ================")
    pytest.fail("\n".join(report), pytrace=False)


def run_client(agent, stdin, timeout=15):
    """Run the client from the root netns against the agent. Returns
    (stdout, stderr, returncode); on a hang it fails with full diagnostics."""
    script = (f"cd {REMOTE_DIR} && exec timeout {timeout} "
              f"./client --host {TGT_IP} --port {AGENT_PORT}")
    try:
        r = agent.target.sh(script, stdin=stdin, timeout=timeout + 15)
    except subprocess.TimeoutExpired as e:
        fail_with_diagnostics(
            agent, "Client/ssh session hung.",
            client_stdout=(e.stdout or b"").decode(errors="replace"),
            client_stderr=(e.stderr or b"").decode(errors="replace"))
    out = r.stdout.decode(errors="replace")
    err = r.stderr.decode(errors="replace")
    if r.returncode == 124:
        fail_with_diagnostics(agent, f"Client timed out after {timeout}s.",
                              client_stdout=out, client_stderr=err, client_exit=124)
    return out, err, r.returncode


@contextlib.contextmanager
def http_server(agent, port):
    """Simple python server inside the agent's netns, i.e. behind the firewall."""
    t = agent.target
    pid = f"/tmp/ch-srv-{port}.pid"
    py_cmd = (
        f"import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
        f"s.bind(('0.0.0.0', {port})); s.listen(5); "
        f"[c.close() for c, _ in iter(s.accept, None)]"
    )
    t.check(f"setsid {IN_NS} python3 -c {shlex.quote(py_cmd)} "
            f"</dev/null >/tmp/ch-srv-{port}.log 2>&1 & echo $! > {pid}")
    try:
        yield TGT_IP, port
    finally:
        t.sh(f"kill $(cat {pid}) 2>/dev/null; rm -f {pid}; true")


def can_connect(agent, port, timeout=2.0):
    """True if a TCP connect from the root netns to the agent's netns completes.
    A dropped SYN shows up as a timeout, which counts as blocked."""
    probe = f"import socket; socket.create_connection(('{TGT_IP}', {port}), {timeout}).close()"
    r = agent.target.sh(f"python3 -c {shlex.quote(probe)}", timeout=timeout + 15)
    return r.returncode == 0


def eventually(pred, tries=10, delay=0.5):
    for _ in range(tries):
        if pred():
            return True
        time.sleep(delay)
    return False