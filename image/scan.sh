#!/bin/bash
# Scan a completed image read-only; scanners never enter the runtime guest.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${NTRUST_SCAN_TOOLS:?Path containing verified syft and trivy executables}"
: "${NTRUST_TRIVY_CACHE:?Scanner cache outside the mounted guest}"
out="${NTRUST_SBOM_DIR:-sbom/$(date -u +%F)}"
root="$PWD/build/scan-root"
mkdir -p "$root" "$out"
out=$(realpath "$out")
loop=$(sudo -n losetup --find --show --read-only --partscan dist/gcp/disk.raw)
trap 'sudo -n umount "$root/boot/efi" "$root/boot" "$root" 2>/dev/null || true; sudo -n losetup -d "$loop"' EXIT
sudo -n mount -o ro,noload "${loop}p1" "$root"
sudo -n mount -o ro,noload "${loop}p16" "$root/boot"
sudo -n mount -o ro "${loop}p15" "$root/boot/efi"
sudo -n env SYFT_CHECK_FOR_APP_UPDATE=false "$NTRUST_SCAN_TOOLS/syft" scan "dir:$root" \
  -o "cyclonedx-json=$out/sbom.syft.cdx.json" 2> "$out/syft.log"
sudo -n "$NTRUST_SCAN_TOOLS/trivy" rootfs --cache-dir "$NTRUST_TRIVY_CACHE" \
  --scanners vuln --format json --output "$out/vulnerabilities.trivy.json" --timeout 15m "$root" \
  2> "$out/trivy.log"
sudo -n cp "$NTRUST_TRIVY_CACHE/db/metadata.json" "$out/trivy-db-metadata.json"
sudo -n systemctl --root="$root" list-unit-files --no-legend --no-pager | tee "$out/unit-files.txt" > /dev/null
sudo -n cp "$root"/boot/config-*-ntrust "$out/"
cp dist/SHA256SUMS "$out/image-SHA256SUMS"
sudo -n chown -R "$(id -u):$(id -g)" "$out"
