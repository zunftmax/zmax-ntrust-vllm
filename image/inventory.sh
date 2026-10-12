#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD/build/inventory-root"
out="${NTRUST_SBOM_DIR:-sbom/$(date -u +%F)}"
mkdir -p "$root" "$out"
loop=$(sudo -n losetup --find --show --read-only --partscan dist/gcp/disk.raw)
trap 'sudo -n umount "$root" 2>/dev/null || true; sudo -n losetup -d "$loop"' EXIT
sudo -n mount -o ro,noload "${loop}p1" "$root"
sudo -n python3 image/inventory.py "$root" "$out"
sudo -n chown "$(id -u):$(id -g)" "$out/inventory.json" "$out/sbom.cdx.json"
cp dist/SHA256SUMS "$out/image-SHA256SUMS"
