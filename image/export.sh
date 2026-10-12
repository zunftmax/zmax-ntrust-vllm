#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
image=dist/qemu/ntrust.qcow2
test -f "$image"
stage=$(mktemp -d dist/.export.XXXXXX)
trap 'rm -rf "$stage"' EXIT
qemu-img check -f qcow2 "$image"
# Convert and compare before publishing any final filename.
qemu-img convert -f qcow2 -O raw "$image" "$stage/disk.raw"
test "$(( $(stat -c %s "$stage/disk.raw") % 1048576 ))" -eq 0
qemu-img compare -f qcow2 -F raw "$image" "$stage/disk.raw"
tar --format=oldgnu --sparse -C "$stage" -czf "$stage/ntrust-gcp.tar.gz" disk.raw
test "$(tar -tzf "$stage/ntrust-gcp.tar.gz")" = disk.raw
tar -xOf "$stage/ntrust-gcp.tar.gz" disk.raw | cmp - "$stage/disk.raw"
qemu-img convert -f raw -O vpc -o subformat=fixed,force_size \
  "$stage/disk.raw" "$stage/ntrust-azure.vhd"
qemu-img compare -f raw -F vpc "$stage/disk.raw" "$stage/ntrust-azure.vhd"
sha256sum "$image" > "$stage/SHA256SUMS"
for name in ntrust-gcp.tar.gz ntrust-azure.vhd; do
  hash=$(sha256sum "$stage/$name")
  printf '%s  dist/%s\n' "${hash%% *}" "$name" >> "$stage/SHA256SUMS"
done
mkdir -p dist/gcp
# The manifest is the completion marker; consumers must verify all its hashes.
rm -f dist/SHA256SUMS
mv "$stage/disk.raw" dist/gcp/disk.raw
mv "$stage/ntrust-gcp.tar.gz" "$stage/ntrust-azure.vhd" dist/
mv "$stage/SHA256SUMS" dist/SHA256SUMS
