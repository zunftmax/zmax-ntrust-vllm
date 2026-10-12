#!/bin/bash
set -euo pipefail
cd /tmp/ntrust
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get upgrade -y --no-install-recommends
# Configure initramfs-tools before NVIDIA's postinst invokes it. The minimal
# cloud image does not ship its configuration, and apt may otherwise order the
# two packages in the opposite direction during a kernel-family change.
apt-get install -y --no-install-recommends initramfs-tools
# Signed, precompiled NVIDIA modules avoid DKMS; compilers below serve engine JIT.
apt-get install -y --no-install-recommends \
  linux-image-virtual-hwe-24.04 linux-modules-nvidia-580-server-open-generic-hwe-24.04 \
  nvidia-utils-580-server libnvidia-compute-580-server nvidia-compute-utils-580-server \
  libnvidia-cfg1-580-server nvidia-modprobe \
  ca-certificates curl openssl gettext-base libgomp1 libssl3t64 libcurl4t64 initramfs-tools \
  python3-venv python3-dev gcc g++ libc6-dev ninja-build libnuma1 libibverbs1 \
  cloud-init lsb-release openssh-server systemd-resolved systemd-timesyncd

# GVE moved from modules-extra into the main HWE module package. Check the
# selected kernel and install extras only if needed, without desktop firmware.
kernel_image=$(printf '%s\n' /boot/vmlinuz-*-generic | sort -V | tail -n 1)
test -f "$kernel_image"
kernel=${kernel_image##*/vmlinuz-}
if ! modinfo -k "$kernel" gve >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends "linux-modules-extra-$kernel"
  apt-mark manual "linux-modules-extra-$kernel"
fi
apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  apport snapd walinuxagent ubuntu-pro-client ubuntu-drivers-common \
  ubuntu-release-upgrader-core unattended-upgrades pollinate lxd-agent-loader \
  lxd-installer unminimize ssh-import-id python3-apport python3-problem-report \
  python3-update-manager python3-launchpadlib linux-image-generic linux-firmware \
  console-setup console-setup-linux keyboard-configuration kbd \
  xkb-data wget
# The base's old GA kernel must not remain as a vulnerable boot alternative.
# This runs only in the disposable builder; the finished guest boots HWE.
old_kernels=()
while read -r status package; do
  if [ "$status" = ii ]; then old_kernels+=("$package"); fi
done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' \
  'linux-image-6.8.*' 'linux-modules-6.8.*' 'linux-modules-extra-6.8.*' 2>/dev/null || true)
apt-get purge -y linux-image-virtual linux-virtual "${old_kernels[@]}"

fetch() {
  curl --fail --location --retry 3 --proto '=https' "$1" -o "$3"
  printf '%s  %s\n' "$2" "$3" | sha256sum --check --status
}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Match the NGINX core/module ABI. Only our restricted service may listen.
systemctl mask nginx.service nginx-debug.service
fetch https://nginx.org/packages/ubuntu/pool/nginx/n/nginx/nginx_1.30.5-1~noble_amd64.deb \
  2ed3c0c4c5e24fe6c2bb46a5fc255d7e0de718e5ff5d8d6c9e17c79a1313dc05 "$work/nginx.deb"
fetch https://nginx.org/packages/ubuntu/pool/nginx/n/nginx-module-acme/nginx-module-acme_1.30.5+0.4.1-1~noble_amd64.deb \
  8de5d185d363d88f8639d198126922c536d9d99563611f54600a7cfce2ffb2c5 "$work/nginx-acme.deb"
fetch https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/libnvat_2.0.0.1790976895-1_amd64.deb \
  d6ae20d7f0d90c62c5e99bcac29cb66f3d9e18c7ee2c4de3aee40134edd70353 "$work/libnvat.deb"
fetch https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/nvattest_2.0.0.1790976895-1_amd64.deb \
  77eaec7644b6a221147245a1c0643bac7317265815e3483ef12f283fc91badb0 "$work/nvattest.deb"
apt-get install -y --no-install-recommends "$work"/*.deb
rm -f /usr/sbin/nginx-debug /usr/lib/nginx/modules/ngx_http_acme_module-debug.so \
  /etc/nginx/conf.d/default.conf
# uv is build-only; all engine wheels are pinned and hash verified.
install -d /opt/ntrust /usr/share/doc/ntrust
fetch https://files.pythonhosted.org/packages/c3/75/1901383808ba0d421f32060ba0e9884169b685a722e1af5d87fdd4225ba6/uv-0.13.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl \
  52c7da0fd9056d9551124777ec77de53f0df7017daf8f98a19e947b7837416ed "$work/uv.whl"
python3 - "$work" <<'PY'
from pathlib import Path
import sys, zipfile
work = Path(sys.argv[1])
with zipfile.ZipFile(work / 'uv.whl') as z:
    name = next(n for n in z.namelist() if n.endswith('/uv'))
    (work / 'uv').write_bytes(z.read(name))
(work / 'uv').chmod(0o755)
PY
export UV_CACHE_DIR="$work/uv-cache" UV_CONCURRENT_DOWNLOADS=2 UV_CONCURRENT_INSTALLS=1
"$work/uv" venv --python /usr/bin/python3 /opt/ntrust/venv
"$work/uv" pip sync --python /opt/ntrust/venv/bin/python --require-hashes --only-binary=:all: image/requirements.lock
"$work/uv" pip check --python /opt/ntrust/venv/bin/python
cp image/requirements.lock /usr/share/doc/ntrust/requirements.lock
# CUDA 13 wheels share NVIDIA's cu13 prefix. JIT compilation stays in RAM.
test -x /opt/ntrust/venv/lib/python3.12/site-packages/nvidia/cu13/bin/nvcc
ln -s /opt/ntrust/venv/lib/python3.12/site-packages/nvidia/cu13 /usr/local/cuda
# Preserve upstream wheel metadata and license files for the inventory.
rm -rf "$work/uv-cache"

id -u ntrust >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin ntrust
id -u ntrust-web >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin ntrust-web
getent group render >/dev/null || groupadd --system render
install -d -m 0755 /usr/local/lib/ntrust /etc/ntrust /var/lib/ntrust
install -m 0755 guest/gpu-ready guest/https-start guest/inference-ready guest/inference-start guest/fetch-model /usr/local/lib/ntrust/
install -m 0755 guest/status /usr/local/bin/ntrust-status
install -m 0644 guest/nginx.conf.template guest/runtime.env.example guest/model.json /etc/ntrust/
install -m 0644 guest/systemd/*.service /etc/systemd/system/
install -m 0644 guest/blocked-modules.conf /etc/modprobe.d/ntrust-blocked.conf
install -d /etc/systemd/system/systemd-time-wait-sync.service.d
printf '[Service]\nTimeoutStartSec=90\n' > /etc/systemd/system/systemd-time-wait-sync.service.d/ntrust.conf

# NVIDIA's documented LKCA + UVM persistence setup establishes the SPDM session.
printf '%s\n' 'install nvidia /sbin/modprobe ecdsa_generic; /sbin/modprobe ecdh; /sbin/modprobe --ignore-install nvidia' > /etc/modprobe.d/nvidia-lkca.conf
install -d /etc/systemd/system/nvidia-persistenced.service.d
cat > /etc/systemd/system/nvidia-persistenced.service.d/ntrust.conf <<'EOF'
[Service]
ExecStartPre=/usr/bin/nvidia-modprobe -u -c 0
ExecStart=
ExecStart=/usr/bin/nvidia-persistenced --user nvidia-persistenced --uvm-persistence-mode
EOF
# Include each cloud's storage/network drivers in the same initramfs.
printf '%s\n' nvme virtio_pci virtio_blk virtio_scsi virtio_net hv_vmbus hv_storvsc hv_netvsc gve > /etc/initramfs-tools/modules
# The minimal cloud base boots without an initrd. Create one for cloud drivers.
rm -f /etc/default/grub.d/40-force-partuuid.cfg
for kernel_image in /boot/vmlinuz-*; do
  kernel=${kernel_image##*/vmlinuz-}
  if [ -f "/boot/initrd.img-$kernel" ]; then
    update-initramfs -u -k "$kernel"
  else
    update-initramfs -c -k "$kernel"
  fi
done
update-grub

# Cloud-init alone provisions both clouds; no extension/telemetry daemon.
rm -f /etc/cloud/cloud.cfg.d/10-azure-kvp.cfg
cat > /etc/cloud/cloud.cfg.d/99-ntrust-datasources.cfg <<'EOF'
datasource_list: [ NoCloud, Azure, GCE ]
reporting:
  telemetry: false
  logging:
    type: log
EOF
install -d /etc/systemd/coredump.conf.d
printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/ntrust.conf
printf '* hard core 0\n* soft core 0\n' > /etc/security/limits.d/ntrust.conf
printf 'kernel.core_pattern=|/bin/false\nfs.suid_dumpable=0\n' > /etc/sysctl.d/99-ntrust-no-core.conf
sed -i '/[[:space:]]swap[[:space:]]/d' /etc/fstab
swapoff -a
systemctl mask swap.target
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target \
  suspend-then-hibernate.target systemd-suspend.service systemd-hibernate.service \
  systemd-hybrid-sleep.service systemd-suspend-then-hibernate.service \
  nvidia-suspend.service nvidia-resume.service nvidia-hibernate.service \
  systemd-pstore.service apt-daily.timer apt-daily-upgrade.timer \
  apt-daily.service apt-daily-upgrade.service motd-news.timer motd-news.service \
  cloud-init-hotplugd.socket cloud-init-hotplugd.service dpkg-db-backup.timer
install -d /etc/systemd/sleep.conf.d /etc/systemd/pstore.conf.d
printf '[Sleep]\nAllowSuspend=no\nAllowHibernation=no\nAllowHybridSleep=no\nAllowSuspendThenHibernate=no\n' > /etc/systemd/sleep.conf.d/ntrust.conf
printf '[PStore]\nStorage=none\n' > /etc/systemd/pstore.conf.d/ntrust.conf
# Prevent userspace-triggered pstore writes and persistent application journals.
printf 'kernel.dmesg_restrict=1\nkernel.kptr_restrict=2\nkernel.unprivileged_bpf_disabled=1\nkernel.perf_event_paranoid=3\n' > /etc/sysctl.d/99-ntrust-kernel.conf
install -d /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=32M\nForwardToSyslog=no\n' > /etc/systemd/journald.conf.d/ntrust.conf
systemctl enable systemd-resolved.service systemd-timesyncd.service
systemctl enable ntrust-inference.service ntrust-https.service

# Exercise installed CPU-side binaries/configuration during the Linux build.
# This deliberately does not bypass the GPU gate or claim GPU execution.
bash image/check-installed.sh

# Record the actual package tuple; reproducible snapshot builds are deferred.
dpkg-query -W -f='${Package}\t${Version}\n' > /usr/share/doc/ntrust/packages.tsv
apt-get clean
rm -rf /var/lib/apt/lists/*
