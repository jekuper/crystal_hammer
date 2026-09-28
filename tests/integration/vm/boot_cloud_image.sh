#!/usr/bin/env bash
# Boot a distro's *stock* cloud image (its own kernel, its own init, its own
# defaults) under KVM, inject an SSH key via cloud-init NoCloud, and wait
# until root can SSH in on 127.0.0.1:$SSH_PORT.
#
# usage: boot_cloud_image.sh <name> <image-url> ["extra packages"]
set -euo pipefail

NAME=$1
URL=$2
PKGS=${3:-}
CACHE=${CACHE_DIR:-$HOME/.cache/ch-vm}
WORK=${WORK_DIR:-/tmp/ch-vm}
SSH_PORT=${SSH_PORT:-2200}
MEM=${VM_MEM:-4G}

mkdir -p "$CACHE" "$WORK"

BASE="$CACHE/$NAME.img"
if [ ! -s "$BASE" ]; then
  echo "Downloading $URL"
  curl -fL --retry 3 -o "$BASE.tmp" "$URL"
  mv "$BASE.tmp" "$BASE"
fi

# Copy-on-write overlay: the cached base image is never modified.
FMT=$(qemu-img info --output=json "$BASE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')
qemu-img create -q -f qcow2 -F "$FMT" -b "$BASE" "$WORK/disk.qcow2"

[ -f "$WORK/key" ] || ssh-keygen -q -t ed25519 -N "" -f "$WORK/key"

{
  echo "#cloud-config"
  echo "disable_root: false"
  echo "ssh_pwauth: false"
  echo "ssh_authorized_keys:"
  echo "  - $(cat "$WORK/key.pub")"
  if [ -n "$PKGS" ]; then
    echo "packages:"
    for p in $PKGS; do echo "  - $p"; done
  fi
  # Deliberately NOT mounting /sys/fs/bpf or tweaking anything else:
  # the point of this tier is to see what the agent meets on a stock box.
} > "$WORK/user-data"
printf 'instance-id: ch-%s\nlocal-hostname: ch-%s\n' "$NAME" "$NAME" > "$WORK/meta-data"
genisoimage -quiet -output "$WORK/seed.iso" -volid cidata -joliet -rock \
  "$WORK/user-data" "$WORK/meta-data"

qemu-system-x86_64 \
  -enable-kvm -cpu host -smp "$(nproc)" -m "$MEM" \
  -drive file="$WORK/disk.qcow2",if=virtio \
  -drive file="$WORK/seed.iso",format=raw,if=virtio,readonly=on \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22 \
  -device virtio-net-pci,netdev=n0 \
  -serial file:"$WORK/console.log" \
  -display none -daemonize -pidfile "$WORK/qemu.pid"

SSH=(ssh -p "$SSH_PORT" -i "$WORK/key" -o BatchMode=yes -o ConnectTimeout=5
     -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
     root@127.0.0.1)

echo "Waiting for SSH..."
for i in $(seq 1 120); do
  if "${SSH[@]}" true 2>/dev/null; then break; fi
  if [ "$i" -eq 120 ]; then
    echo "VM never became reachable. Console:"; tail -n 100 "$WORK/console.log"; exit 1
  fi
  sleep 2
done

# Wait for package installs etc. to finish before tests start.
"${SSH[@]}" 'cloud-init status --wait >/dev/null 2>&1 || true'

# Diagnostic tools for the harness's hung-agent probe. Best-effort: a distro
# without them just yields "(no strace)"/"(no bpftool)" in the report. Set
# CH_SKIP_DIAG_TOOLS=1 to keep the box maximally stock.
if [ "${CH_SKIP_DIAG_TOOLS:-0}" != "1" ]; then
  "${SSH[@]}" 'sh -s' <<'DIAG' || echo "warn: diagnostic-tool install failed (probe will show fewer details)"
set +e
if   command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq strace linux-tools-common "linux-tools-$(uname -r)" iproute2 >/dev/null 2>&1 \
    || apt-get install -y -qq strace iproute2 >/dev/null 2>&1
elif command -v dnf     >/dev/null; then dnf install -y -q strace bpftool iproute >/dev/null 2>&1
elif command -v zypper  >/dev/null; then zypper -n in strace bpftool iproute2 >/dev/null 2>&1
elif command -v apk     >/dev/null; then apk add --no-cache strace bpftool iproute2 >/dev/null 2>&1
fi
true
DIAG
fi

"${SSH[@]}" 'echo "kernel: $(uname -r)"; . /etc/os-release; echo "distro: $PRETTY_NAME"'
"${SSH[@]}" 'echo "diag tools:"; for t in strace bpftool ss; do printf "  %s: " "$t"; command -v "$t" || echo "(missing)"; done'