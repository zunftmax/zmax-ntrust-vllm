#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
qa=${NTRUST_QA_DIR:-build/boot-check}
mkdir -p "$qa"
test ! -e "$qa/root.qcow2"
qemu-img create -f qcow2 -F qcow2 -b "${NTRUST_QA_IMAGE:-$PWD/dist/qemu/ntrust.qcow2}" "$qa/root.qcow2"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$qa/OVMF_VARS.fd"
python3 - "$qa" <<'PY'
from pathlib import Path
import socket
import sys
qa = Path(sys.argv[1])
pubkey = Path('build/image-key.pub').read_text().strip()
(qa / 'user-data').write_text('''#cloud-config
users:
  - name: operator
    primary_group: users
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - ''' + pubkey + '''
ssh_pwauth: false
disable_root: true
write_files:
  - path: /etc/ntrust/runtime.env
    permissions: '0644'
    content: |
      NTRUST_DOMAIN=inference.example.com
      NTRUST_EMAIL=admin@example.com
      NTRUST_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory
''')
(qa / 'meta-data').write_text('instance-id: ntrust-final-image-boot-check\nlocal-hostname: ntrust-check\n')
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    (qa / 'port').write_text(str(sock.getsockname()[1]))
PY
xorriso -as mkisofs -quiet -V cidata -J -r -o "$qa/seed.iso" "$qa/user-data" "$qa/meta-data"
port=$(cat "$qa/port")
qemu-system-x86_64 -name ntrust-boot-check -enable-kvm -machine q35 -cpu host -smp 2 -m 4096 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$qa/OVMF_VARS.fd" \
  -device virtio-scsi-pci,id=scsi0 \
  -drive if=none,id=root,format=qcow2,file="$qa/root.qcow2",discard=unmap \
  -device scsi-hd,drive=root,bus=scsi0.0 \
  -drive if=virtio,format=raw,readonly=on,file="$qa/seed.iso" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$port"-:22 -device virtio-net-pci,netdev=net0 \
  -display none -serial file:"$qa/serial.log" -daemonize -pidfile "$qa/qemu.pid"
trap 'test ! -f "$qa/qemu.pid" || kill "$(cat "$qa/qemu.pid")" 2>/dev/null || true' EXIT
guest_ssh=(ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile="$qa/known-hosts" -i build/image-key -p "$port" operator@127.0.0.1)
for _attempt in $(seq 1 90); do
  if "${guest_ssh[@]}" true 2>/dev/null; then break; fi
  sleep 2
done
"${guest_ssh[@]}" 'sudo bash -s' <<'GUEST' | tee "$qa/results.log"
set -euo pipefail
cloud-init status --wait
uname -r
systemd-detect-virt
cvm=$(systemd-detect-virt --cvm || true)
test "$cvm" = none
printf 'CPU confidential mode: %s\n' "$cvm"
test "$(wc -l < /proc/swaps)" -eq 1
test "$(sysctl -n fs.suid_dumpable)" = 0
test "$(sysctl -n kernel.core_pattern)" = '|/bin/false'
test "$(sshd -T | sed -n 's/^permitrootlogin //p')" = no
test "$(sshd -T | sed -n 's/^passwordauthentication //p')" = no
systemd-analyze verify /etc/systemd/system/ntrust-*.service
modinfo -F version nvidia
modinfo -F signer nvidia
nvattest version
if /usr/local/lib/ntrust/gpu-ready; then
  echo 'ERROR: GPU gate admitted ordinary VM' >&2
  exit 1
fi
systemctl start ntrust-inference.service ntrust-https.service && {
  echo 'ERROR: inference service admitted ordinary VM' >&2
  exit 1
}
for service in ntrust-gpu ntrust-inference ntrust-https; do
  state=$(systemctl show -p ActiveState --value "$service")
  printf '%s: %s\n' "$service" "$state"
  test "$state" != active
done
test ! -e /run/ntrust-gpu/api-key
test ! -e /run/ntrust-gpu/attestation.json
test -z "$(ss -H -ltn 'sport = :443 or sport = :8080')"
test "$(systemctl is-enabled nginx.service)" = masked
test "$(systemctl show -p LoadState --value walinuxagent.service)" = not-found
for unit in sleep.target suspend.target hibernate.target systemd-pstore.service nvidia-suspend.service cloud-init-hotplugd.socket; do
  test "$(systemctl is-enabled "$unit")" = masked
done
for module in nfsd kvm nvmet_tcp ib_srpt sctp amdgpu openvswitch scsi_debug kafs bluetooth vxlan target_core_iblock idpf vmwgfx ip_vs snd_pcm; do
  if modprobe "$module"; then echo "ERROR: loaded forbidden module $module" >&2; exit 1; fi
done
modinfo -F filename gve
printf 'Kernel configuration for architecture and allocator triage:\n'
grep -E 'CONFIG_(X86_64|S390|NEED_PER_CPU_KM|NEED_PER_CPU_PAGE_FIRST_CHUNK|NEED_PER_CPU_EMBED_FIRST_CHUNK|MSM_MDP)' "/boot/config-$(uname -r)" || true
printf 'Root filesystem features:\n'
tune2fs -l "$(findmnt -n -o SOURCE /)" | sed -n '/Filesystem features:/p'
for package in walinuxagent ubuntu-pro-client pollinate lxd-installer ubuntu-drivers-common linux-firmware; do
  test "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)" != installed
done
/usr/local/bin/ntrust-status
printf 'PASS: unwanted packages absent; sleep/pstore disabled; optional subsystems reject module loads.\n'

systemctl show -p ActiveState -p SubState systemd-timesyncd.service
ss -ltn
df -B1 /
printf 'PASS: completed image boots; ordinary VM rejected; no inference listener or API key.\n'
GUEST
"${guest_ssh[@]}" 'sudo /opt/ntrust/venv/bin/python -' < image/check-engine.py | tee "$qa/engine-parser.log"
"${guest_ssh[@]}" sudo poweroff || true
