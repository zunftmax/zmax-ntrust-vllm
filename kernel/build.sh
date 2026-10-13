#!/bin/bash
# Existing upstream Kbuild + dpkg packaging; run only on the Linux builder.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$PWD
test "$(uname -s)/$(uname -m)" = Linux/x86_64
work=${NTRUST_KERNEL_WORK:-$repo/build/kernel}
mkdir -p "$work" "$repo/build"
work=$(realpath "$work")
mkdir -p "$work"/{sources,build,artifacts,evidence}
version=7.2.10
nvidia_version=580.178.04
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1760000000
export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00 UTC"
export KBUILD_BUILD_USER=ntrust
export KBUILD_BUILD_HOST=ntrust
export KBUILD_BUILD_VERSION=1
src="$work/sources/linux-$version"
obj="$work/build/linux"
nvsrc="$work/sources/open-gpu-kernel-modules-$nvidia_version"
jobs=${NTRUST_BUILD_JOBS:-3}
fetch() {
    if [ ! -f "$3" ]; then
        curl --fail --location --retry 3 --proto '=https' "$1" -o "$3.tmp"
        mv "$3.tmp" "$3"
    fi
    printf '%s  %s\n' "$2" "$3" | sha256sum --check --status
}
fetch "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$version.tar.xz" \
    2feaa70453e91f541be6a5c9078d8168e081af45a3d9718054850538cff2ebf3 \
    "$work/sources/linux-$version.tar.xz"
curl --fail --location --retry 3 --proto '=https' \
    "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$version.tar.sign" \
    -o "$work/sources/linux-$version.tar.sign"
export GNUPGHOME="$work/build/gnupg"
install -d -m 0700 "$GNUPGHOME"
gpg --batch --auto-key-locate clear,wkd --locate-keys gregkh@kernel.org
xz -cd "$work/sources/linux-$version.tar.xz" | \
    gpg --batch --status-fd 1 --verify "$work/sources/linux-$version.tar.sign" - \
    > "$work/evidence/kernel-signature.log" 2>&1
grep -q '^\[GNUPG:\] VALIDSIG 647F28654894E3BD457199BE38DBBDC86092693E ' \
    "$work/evidence/kernel-signature.log"
fetch "https://github.com/NVIDIA/open-gpu-kernel-modules/archive/refs/tags/$nvidia_version.tar.gz" \
    f30d4c20feda9f570a69084573a72423067e1e2d46c50ca58c391664872a9e01 \
    "$work/sources/nvidia-$nvidia_version.tar.gz"
test -d "$src" || tar -xf "$work/sources/linux-$version.tar.xz" -C "$work/sources"
test -d "$nvsrc" || tar -xf "$work/sources/nvidia-$nvidia_version.tar.gz" -C "$work/sources"
for fix in "$repo"/kernel/patches/*.patch; do
    if patch --batch --fuzz=0 --forward --dry-run -d "$src" -p1 < "$fix" >/dev/null; then
        patch --batch --fuzz=0 --forward -d "$src" -p1 < "$fix"
    else
        # Only accept the precise already-applied patch, never a failed hunk.
        patch --batch --fuzz=0 --reverse --dry-run -d "$src" -p1 < "$fix" >/dev/null
    fi
done
# Append an out-of-tree UVM dependency declaration without patching kernel code.
cat "$src/Kconfig" kernel/Kconfig > "$work/build/Kconfig"
mkdir -p "$obj"
kmake=(make -C "$src" O="$obj" ARCH=x86_64 KBUILD_KCONFIG="$work/build/Kconfig")
"${kmake[@]}" KCONFIG_ALLCONFIG="$repo/kernel/required.config" allnoconfig
python3 kernel/check-config.py "$obj/.config" "$src"
nice -n 10 "${kmake[@]}" -j"$jobs" bzImage modules
release=$("${kmake[@]}" -s kernelrelease)
test "$release" = "$version-ntrust"
# Build only the compute resource manager, not the modeset object.
nice -n 10 make -C "$nvsrc" -j"$jobs" kernel-open/nvidia/nv-kernel.o_binary
nice -n 10 make -C "$nvsrc/kernel-open" -j"$jobs" \
    SYSSRC="$src" SYSOUT="$obj" KBUILD_KCONFIG="$work/build/Kconfig" \
    NV_KERNEL_MODULES='nvidia nvidia-uvm' modules
# NVIDIA otherwise silently compiles error stubs when LKCA is unavailable.
nm -u "$nvsrc/kernel-open/nvidia.ko" > "$work/evidence/nvidia-kernel-symbols.txt"
grep -q ' crypto_alloc_aead$' "$work/evidence/nvidia-kernel-symbols.txt"
grep -q ' crypto_alloc_sig$' "$work/evidence/nvidia-kernel-symbols.txt"
pkg=$(mktemp -d "$work/build/package.XXXXXX")
trap 'rm -rf "$pkg"' EXIT
mods="$pkg/usr/lib/modules/$release"
"${kmake[@]}" MODLIB="$mods" INSTALL_MOD_STRIP=1 DEPMOD=/bin/true modules_install
rm -f "$mods/build" "$mods/source"
install -d "$mods/updates/nvidia"
for module in nvidia nvidia-uvm; do
    install -m 0644 "$nvsrc/kernel-open/$module.ko" "$mods/updates/nvidia/"
    strip --strip-debug "$mods/updates/nvidia/$module.ko"
    "$obj/scripts/sign-file" sha512 "$obj/certs/signing_key.pem" \
        "$obj/certs/signing_key.x509" "$mods/updates/nvidia/$module.ko"
done
# Ubuntu 24.04 kmod looks below /lib; the guest uses merged /usr.
ln -s usr/lib "$pkg/lib"
depmod -b "$pkg" "$release"
rm "$pkg/lib"
find "$mods" -type f -name '*.ko' -printf '%P\n' | sort > "$work/evidence/kernel-modules.txt"
diff -u <(printf '%s\n' kernel/crypto/{ecc,ecdh_generic,ecdsa_generic,kpp}.ko \
    updates/nvidia/{nvidia,nvidia-uvm}.ko | sort) "$work/evidence/kernel-modules.txt"
install -d "$pkg/boot" "$pkg/usr/share/doc/ntrust/kernel" "$pkg/DEBIAN"
install -m 0644 "$obj/arch/x86/boot/bzImage" "$pkg/boot/vmlinuz-$release"
install -m 0644 "$obj/.config" "$pkg/boot/config-$release"
install -m 0644 "$obj/System.map" "$pkg/boot/System.map-$release"
install -m 0644 kernel/required.config kernel/Kconfig "$src/COPYING" \
    "$obj/certs/signing_key.x509" "$pkg/usr/share/doc/ntrust/kernel/"
install -m 0644 "$src/LICENSES/preferred/GPL-2.0" \
    "$src/LICENSES/exceptions/Linux-syscall-note" "$pkg/usr/share/doc/ntrust/kernel/"
cp "$nvsrc/COPYING" "$pkg/usr/share/doc/ntrust/kernel/NVIDIA-COPYING"
cp -R kernel/patches "$pkg/usr/share/doc/ntrust/kernel/"
printf '%s\n' "$version" > "$pkg/usr/share/doc/ntrust/kernel/upstream-version"
printf '%s\n' "$nvidia_version" > "$pkg/usr/share/doc/ntrust/kernel/nvidia-version"
cat > "$pkg/DEBIAN/control" <<EOF
Package: ntrust-kernel
Version: $version-1
Architecture: amd64
Maintainer: Zmax Ntrust <noreply@github.com>
Depends: kmod, linux-base
Description: Minimal cloud guest Linux and headless NVIDIA compute modules
 Built from an explicit feature allowlist for the Ntrust GPU guest image.
 Includes only NVIDIA compute and UVM modules. Cloud validation is pending.
EOF
dpkg-deb --root-owner-group --build "$pkg" "$work/artifacts/ntrust-kernel.deb"
# Install the matching sanitized userspace API, not full kernel build headers.
# libc6-dev/CUDA JIT need this; it contains declarations, not driver code.
headers=$(mktemp -d "$work/build/headers.XXXXXX")
trap 'rm -rf "$pkg" "$headers"' EXIT
"${kmake[@]}" INSTALL_HDR_PATH="$headers/usr" headers_install
install -d "$headers/usr/include/x86_64-linux-gnu" "$headers/DEBIAN"
mv "$headers/usr/include/asm" "$headers/usr/include/x86_64-linux-gnu/asm"
cat > "$headers/DEBIAN/control" <<EOF
Package: linux-libc-dev
Version: $version-1+ntrust1
Architecture: amd64
Multi-Arch: same
Maintainer: Zmax Ntrust <noreply@github.com>
Description: Linux $version sanitized userspace API headers for Ntrust
 Generated by upstream headers_install from the same source as ntrust-kernel.
EOF
install -d "$headers/usr/share/doc/linux-libc-dev"
install -m 0644 "$src/COPYING" "$headers/usr/share/doc/linux-libc-dev/"
install -m 0644 "$src/LICENSES/preferred/GPL-2.0" \
    "$src/LICENSES/exceptions/Linux-syscall-note" "$headers/usr/share/doc/linux-libc-dev/"
dpkg-deb --root-owner-group --build "$headers" "$work/artifacts/ntrust-linux-headers.deb"
cp "$obj/.config" "$work/evidence/kernel.config"
sha256sum "$work/artifacts/ntrust-kernel.deb" "$work/artifacts/ntrust-linux-headers.deb" \
    > "$work/evidence/kernel-package.sha256"
install -m 0644 "$work/artifacts/ntrust-kernel.deb" "$repo/build/ntrust-kernel.deb"
install -m 0644 "$work/artifacts/ntrust-linux-headers.deb" "$repo/build/ntrust-linux-headers.deb"
printf 'Built %s. Secure Boot enrollment and confidential GPU/cloud boot are not established.\n' "$release"
