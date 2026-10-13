#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD/build/inspect-final"
mkdir -p "$root"
loop=$(sudo -n losetup --find --show --read-only --partscan dist/gcp/disk.raw)
trap 'sudo -n umount "$root" 2>/dev/null || true; sudo -n losetup -d "$loop"' EXIT
sudo -n mount -o ro,noload "${loop}p1" "$root"
sudo -n python3 - "$root" <<'PY'
from pathlib import Path
import hashlib
import json
import re
import sys
root = Path(sys.argv[1])
uq_record = json.loads((root / 'usr/share/doc/ntrust/uq-release.json').read_text())
uq = root / 'usr/local/bin/uq'
assert uq.is_file() and not uq.is_symlink()
with uq.open('rb') as stream:
    assert hashlib.file_digest(stream, 'sha256').hexdigest() == uq_record['binary_sha256']
assert not (root / 'etc/systemd/system/multi-user.target.wants/ntrust-attest.service').exists(), 'Attestation must await hardware acceptance'
for name in ('root/.ssh/authorized_keys', 'var/lib/systemd/random-seed',
             'var/lib/cloud/instance', 'var/lib/cloud/seed/nocloud',
             'etc/ntrust/runtime.env', 'var/lib/ntrust/model',
             'usr/share/doc/ntrust/kernel/signing_key.pem'):
    assert not (root / name).exists(), name
assert not list((root / 'etc/ssh').glob('ssh_host_*'))
assert not list((root / 'var/lib/cloud/instances').glob('*'))
assert (root / 'etc/machine-id').read_text().strip() in ('', 'uninitialized')
assert (root / 'etc/ssh/sshd_config.d/00-ntrust.conf').read_text().startswith('PermitRootLogin no\nPasswordAuthentication no\n')
key_header = re.compile(rb'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----')
for dirname in ('etc', 'root', 'home', 'var/lib', 'tmp', 'var/tmp', 'usr/share/doc/ntrust'):
    for path in (root / dirname).rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        if path.name == 'authorized_keys':
            assert not path.read_bytes().strip(), f'Authorized key: {path.relative_to(root)}'
        if path.stat().st_size <= 10 * 1024 * 1024:
            assert not key_header.search(path.read_bytes()), f'Private key: {path.relative_to(root)}'
print('PASS: no build SSH authorization, SSH host keys, cloud-init instance/seed, saved random seed, runtime configuration or model.')
print('PASS: no PEM/OpenSSH private key headers in regular files <=10 MiB under etc, root, home, var/lib, tmp, var/tmp and usr/share/doc/ntrust.')
print('PASS: machine ID reset; root/password SSH disabled.')
PY
sudo -n cp "$root/usr/share/doc/ntrust/packages.tsv" dist/packages.tsv
sudo -n cp "$root/usr/share/doc/ntrust/value_x.sha384" dist/value_x.sha384
sudo -n chown "$(id -u):$(id -g)" dist/packages.tsv dist/value_x.sha384
sudo -n du -sx --block-size=1 "$root"
