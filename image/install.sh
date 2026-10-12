#!/bin/bash
set -euo pipefail
cd /tmp/ntrust
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get upgrade -y --no-install-recommends
# Temporary build dependency for stock Ubuntu/NVIDIA maintainer scripts;
# removed with the stock kernel before the final image is checked.
apt-get install -y --no-install-recommends initramfs-tools
# Kernel/modules are compiled on the Linux builder, never by DKMS in the guest.
# Pin all NVIDIA userspace and firmware to the open-module source version.
nvidia_version=580.178.04-0ubuntu0.24.04.1
apt-get install -y --no-install-recommends \
  "nvidia-utils-580-server=$nvidia_version" "libnvidia-compute-580-server=$nvidia_version" \
  "nvidia-compute-utils-580-server=$nvidia_version" "libnvidia-cfg1-580-server=$nvidia_version" \
  "nvidia-kernel-common-580-server=$nvidia_version" \
  "nvidia-firmware-580-server-580.178.04=$nvidia_version" nvidia-modprobe \
  ca-certificates curl openssl gettext-base libgomp1 libssl3t64 libcurl4t64 \
  python3-venv python3-dev gcc g++ libc6-dev ninja-build libnuma1 libibverbs1 \
  cloud-init lsb-release openssh-server systemd-resolved systemd-timesyncd

apt-get install -y --no-install-recommends ./ntrust-kernel.deb ./ntrust-linux-headers.deb
python3 kernel/check-config.py /boot/config-7.2.10-ntrust
apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  apport snapd walinuxagent ubuntu-pro-client ubuntu-drivers-common \
  ubuntu-release-upgrader-core unattended-upgrades pollinate lxd-agent-loader \
  lxd-installer unminimize ssh-import-id python3-apport python3-problem-report \
  python3-update-manager python3-launchpadlib linux-image-generic linux-firmware \
  console-setup console-setup-linux keyboard-configuration kbd \
  xkb-data wget
# The base's old GA kernel must not remain as a vulnerable boot alternative.
# This runs only in the disposable builder; the finished guest boots Ntrust.
old_kernels=()
while read -r status package; do
  if [ "$status" = ii ]; then old_kernels+=("$package"); fi
done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' \
  'linux-image-[0-9]*' 'linux-modules-*' 'linux-main-modules-*' 2>/dev/null || true)
apt-get purge -y linux-image-virtual linux-virtual "${old_kernels[@]}"
# Root/cloud drivers are built in, so no initramfs or its parsers are needed.
apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  initramfs-tools initramfs-tools-core initramfs-tools-bin busybox-initramfs \
  klibc-utils libklibc cpio dracut-install

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
install -d /etc/systemd/system/systemd-time-wait-sync.service.d
printf '[Service]\nTimeoutStartSec=90\n' > /etc/systemd/system/systemd-time-wait-sync.service.d/ntrust.conf

# NVIDIA's documented LKCA + UVM persistence setup establishes the SPDM session.
printf '%s\n' 'install nvidia /sbin/modprobe ecdsa_generic && /sbin/modprobe ecdh_generic && /sbin/modprobe --ignore-install nvidia' > /etc/modprobe.d/nvidia-lkca.conf
install -d /etc/systemd/system/nvidia-persistenced.service.d
cat > /etc/systemd/system/nvidia-persistenced.service.d/ntrust.conf <<'EOF'
[Service]
ExecStartPre=/usr/bin/nvidia-modprobe -u -c 0
ExecStart=
ExecStart=/usr/bin/nvidia-persistenced --user nvidia-persistenced --uvm-persistence-mode
EOF
# The kernel can resolve PARTUUID itself; UUID requires initramfs userspace.
rm -f /boot/initrd.img-* /initrd.img /initrd.img.old
cat > /etc/default/grub.d/40-force-partuuid.cfg <<'EOF'
GRUB_FORCE_PARTUUID=
GRUB_DISABLE_LINUX_UUID=true
GRUB_DISABLE_LINUX_PARTUUID=false
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX rootwait"
EOF
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
# CONFIG_COREDUMP=n removes the dump implementation and its sysctl interface.
rm -f /etc/sysctl.d/99-ntrust-no-core.conf
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
# Prevent userspace-triggered pstore writes, ptrace, and network redirect abuse.
cat > /etc/sysctl.d/99-ntrust-kernel.conf <<'EOF'
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.unprivileged_bpf_disabled=1
kernel.perf_event_paranoid=3
kernel.yama.ptrace_scope=3
kernel.sysrq=0
dev.tty.ldisc_autoload=0
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
EOF
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
