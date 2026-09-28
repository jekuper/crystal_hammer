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
# Cloud images ship a ~2GB root that's nearly full; grow the GUEST disk so the
# fs (expanded on first boot by cloud-init growpart) has room for apt installs.
DISK_SIZE=${VM_DISK:-20G}

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
# Grow the overlay's virtual size. The backing image is untouched; the new
# range reads as zeros until cloud-init's growpart/resize2fs claims it.
qemu-img resize -q "$WORK/disk.qcow2" "$DISK_SIZE"

[ -f "$WORK/key" ] || ssh-keygen -q -t ed25519 -N "" -f "$WORK/key"
PUBKEY=$(cat "$WORK/key.pub")

{
  echo "#cloud-config"
  echo "disable_root: false"
  echo "ssh_pwauth: false"
  # Default-user key (user varies: alpine/ubuntu/debian/...). Not enough on its
  # own — the harness logs in as root, and not every image copies this to root.
  echo "ssh_authorized_keys:"
  echo "  - $PUBKEY"
  if [ -n "$PKGS" ]; then
    echo "packages:"
    for p in $PKGS; do echo "  - $p"; done
  fi
  # Put the key into ROOT explicitly so `ssh root@...` works everywhere, and
  # make sure sshd permits key-based root login. Alpine's cloud-init doesn't
  # seed root the way the systemd distros do; this makes them all uniform.
  # (Still NOT mounting /sys/fs/bpf — the box stays stock in every other way.)
  echo "runcmd:"
  echo "  - install -d -m 700 /root/.ssh"
  echo "  - printf '%s\\n' '$PUBKEY' >> /root/.ssh/authorized_keys"
  echo "  - chmod 600 /root/.ssh/authorized_keys"
  echo "  - command -v restorecon >/dev/null && restorecon -R /root/.ssh || true"
  echo "  - passwd -d root || true"
  echo "  - sed -i 's/^root:!/root:/' /etc/shadow || true"
  echo "  - mkdir -p /etc/ssh/sshd_config.d"
  echo "  - echo 'PermitRootLogin prohibit-password' > /etc/ssh/sshd_config.d/00-ch-permit.conf"
  echo "  - sh -c \"grep -qE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config && sed -i 's/^[[:space:]]*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config\""
  echo "  - sh -c \"rc-service sshd restart 2>/dev/null || systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true\""
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
    echo "VM never became reachable."
    # One verbose attempt so an auth rejection (publickey vs connection refused)
    # is visible instead of guessed at.
    echo "=== verbose ssh attempt ==="
    ssh -vv -p "$SSH_PORT" -i "$WORK/key" -o BatchMode=yes -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        root@127.0.0.1 true 2>&1 | grep -iE 'permission denied|auth|offer|refused|connect|no route|banner' | tail -n 20 || true
    echo "=== console tail ==="; tail -n 100 "$WORK/console.log"
    exit 1
  fi
  sleep 2
done

# Wait for package installs etc. to finish before tests start.
"${SSH[@]}" 'cloud-init status --wait >/dev/null 2>&1 || true'

# Most cloud images auto-grow root on first boot. If one didn't (so root is
# still tiny), try to grow it explicitly. Root is the last partition on these
# images, so growpart + the fs-specific resize is safe. Best-effort.
"${SSH[@]}" 'sh -s' <<'GROW' || echo "warn: explicit fs-grow step failed"
set +e
root_src=$(findmnt -no SOURCE / 2>/dev/null); root_fs=$(findmnt -no FSTYPE / 2>/dev/null)
avail_kb=$(df -Pk / | awk 'NR==2{print $4}')
# Only bother if less than ~2GB free.
if [ "${avail_kb:-0}" -lt 2000000 ] && [ -n "$root_src" ]; then
  dev=$(lsblk -npo PKNAME "$root_src" 2>/dev/null | head -1)
  partnum=$(echo "$root_src" | grep -o '[0-9]*$')
  command -v growpart >/dev/null && [ -n "$dev" ] && growpart "$dev" "$partnum" 2>/dev/null
  case "$root_fs" in
    ext*) resize2fs "$root_src" 2>/dev/null ;;
    xfs)  xfs_growfs / 2>/dev/null ;;
    btrfs) btrfs filesystem resize max / 2>/dev/null ;;
  esac
fi
true
GROW

echo "guest disk usage:"; "${SSH[@]}" 'df -h / | sed "s/^/  /"'

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