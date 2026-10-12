#!/bin/bash
set -euo pipefail

nvattest version
test "$(dpkg-query -W -f='${Version}' linux-libc-dev)" = '7.2.10-1+ntrust1'
# persistenced loads this with dlopen, so ordinary ldd checks cannot catch it.
test -r /usr/lib/x86_64-linux-gnu/libnvidia-cfg.so.1
for package in walinuxagent ubuntu-pro-client pollinate lxd-installer ubuntu-drivers-common linux-firmware \
    initramfs-tools initramfs-tools-core busybox-initramfs klibc-utils libklibc cpio; do
    test "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)" != installed
done
test -z "$(find /boot -name 'initrd.img-*' -print)"
grep -q 'root=PARTUUID=' /boot/grub/grub.cfg
test "$(find /boot -name 'vmlinuz-*' | wc -l)" -eq 1
for kernel_image in /boot/vmlinuz-*-ntrust; do
    test -f "$kernel_image"
    kernel=${kernel_image##*/vmlinuz-}
    test "$(find "/usr/lib/modules/$kernel" -type f -name '*.ko' | wc -l)" -eq 6
    for driver in gve nvme hv_vmbus hv_storvsc hv_netvsc mlx5_core ecdsa_generic ecdh_generic nvidia nvidia_uvm; do
        modinfo -k "$kernel" "$driver" > /dev/null
    done
    test -n "$(modinfo -k "$kernel" -F signer nvidia)"
    test -n "$(modinfo -k "$kernel" -F signer nvidia_uvm)"
    python3 /tmp/ntrust/kernel/check-config.py "/boot/config-$kernel"
done
python3 - <<'PY'
from cloudinit import reporting
reporting.update_configuration({'telemetry': False})
assert 'telemetry' not in reporting.instantiated_handler_registry.registered_items
PY
systemd-analyze verify /etc/systemd/system/ntrust-*.service
for binary in /usr/sbin/nginx /usr/lib/nginx/modules/ngx_http_acme_module.so \
    /usr/bin/nvattest; do
    deps=$(ldd "$binary")
    if [[ "$deps" == *'not found'* ]]; then
        printf '%s\n%s\n' "$binary" "$deps" >&2
        exit 1
    fi
done

# NGINX -t loads the real ACME module with the service's port-binding capability.
install -d -o ntrust-web -g ntrust-web -m 0700 /run/ntrust-web
trap 'rm -rf /run/ntrust-web' EXIT
setpriv --reuid=ntrust-web --regid=ntrust-web --init-groups \
    --inh-caps=-all,+net_bind_service --ambient-caps=-all,+net_bind_service \
    --bounding-set=-all,+net_bind_service -- env NTRUST_DOMAIN=inference.example.com \
    NTRUST_EMAIL=admin@example.com \
    NTRUST_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory \
    /usr/local/lib/ntrust/https-start -t

# Verify the installed Python closure and CUDA toolkit without asserting GPU execution.
/usr/local/cuda/bin/nvcc --version
/opt/ntrust/venv/bin/python - <<'PY'
import importlib.metadata as md
import torch
print('torch', torch.__version__, 'CUDA', torch.version.cuda)
assert torch.version.cuda.startswith('13.')
print('vllm', md.version('vllm'))
PY

/opt/ntrust/venv/bin/python /tmp/ntrust/image/check-engine.py
rm -rf /run/ntrust-inference
