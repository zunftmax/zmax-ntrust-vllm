#!/bin/bash
set -euo pipefail

nvattest version
# persistenced loads this with dlopen, so ordinary ldd checks cannot catch it.
test -r /usr/lib/x86_64-linux-gnu/libnvidia-cfg.so.1
for package in walinuxagent ubuntu-pro-client pollinate lxd-installer ubuntu-drivers-common linux-firmware; do
    test "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)" != installed
done
for kernel_image in /boot/vmlinuz-*-generic; do
    kernel=${kernel_image##*/vmlinuz-}
    for driver in gve nvme hv_vmbus hv_storvsc hv_netvsc ecdsa_generic ecdh nvidia; do
        modinfo -k "$kernel" "$driver" > /dev/null
    done
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
