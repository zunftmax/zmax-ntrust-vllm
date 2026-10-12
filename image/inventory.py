#!/usr/bin/python3
"""Inventory the built guest, including installed Python metadata and native files."""
import datetime
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote

root = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)
components = []
packages = subprocess.check_output(['dpkg-query', '--admindir=' + str(root / 'var/lib/dpkg'), '-W', '-f', '${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n'], text=True)
debian = []
for line in packages.splitlines():
    status, name, version, arch = line.split('\t')
    if not status.startswith('ii'):
        continue
    debian.append({'name': name, 'version': version, 'architecture': arch})
    purl = f'pkg:deb/ubuntu/{quote(name)}@{quote(version, safe="")}?arch={arch}&distro=ubuntu-24.04'
    components.append({'type': 'library', 'name': name, 'version': version, 'purl': purl, 'bom-ref': purl})
python = []
for dist in sorted(importlib.metadata.distributions(path=[str(root / 'opt/ntrust/venv/lib/python3.12/site-packages')]), key=lambda d: d.metadata['Name'].lower()):
    name, version = dist.metadata['Name'], dist.version
    license_text = dist.metadata.get('License-Expression') or dist.metadata.get('License') or 'See installed upstream license files'
    item = {'name': name, 'version': version, 'license': license_text, 'requires': dist.requires or []}
    python.append(item)
    purl = f'pkg:pypi/{name.lower().replace("_", "-")}@{version}'
    component = {'type': 'library', 'name': name, 'version': version, 'purl': purl, 'bom-ref': purl}
    components.append(component)
native = []
print(f'Installed: {len(debian)} Debian packages and {len(python)} Python distributions; enumerating native-file candidates', flush=True)
paths = [root / p for p in ['usr/sbin/nginx', 'usr/bin/nvattest', 'usr/lib/nginx/modules/ngx_http_acme_module.so']]
paths += list((root / 'opt/ntrust/venv').rglob('*'))
print(f'Inspecting {len(paths)} paths for ELF headers', flush=True)
for index, path in enumerate(paths, 1):
    if index % 2500 == 0:
        print(f'Examining path {index}/{len(paths)}; {len(native)} ELF files inventoried', flush=True)
    if path.is_symlink() or not path.is_file():
        continue
    with path.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            continue
        size = path.stat().st_size
        if size >= 256 * 1024 * 1024:
            print(f'Hashing {path.relative_to(root)} ({size:,} bytes)', flush=True)
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    name = '/' + str(path.relative_to(root))
    native.append({'path': name, 'sha256': digest, 'bytes': size})
    components.append({'type': 'file', 'name': name, 'bom-ref': 'file:' + name, 'hashes': [{'alg': 'SHA-256', 'content': digest}]})
inventory = {'generated': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'debian': debian, 'python': python, 'native_files': native, 'native_scope': 'ELF files in the inference venv plus NGINX, its ACME module and nvattest; Debian package contents are otherwise identified at package level'}
(out / 'inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'metadata': {'timestamp': inventory['generated']}, 'components': components}
(out / 'sbom.cdx.json').write_text(json.dumps(bom, indent=2) + '\n')
print(f'Inventory: {len(debian)} Debian packages, {len(python)} Python distributions, {len(native)} native ELF files (overlapping package contents)')
