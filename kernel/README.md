# Minimal confidential GPU guest kernel

This kernel starts with upstream `allnoconfig` and the explicit requirements in
[`required.config`](required.config). It does not inherit Ubuntu's distribution
driver configuration. Kconfig supplies the dependency closure; [`check-config.py`](check-config.py)
rejects dropped requirements and forbidden features after resolution.

| Required function | Included implementation | Selection reason and remaining risk |
| --- | --- | --- |
| CPU and guest boot | x86-64, SMP (64 CPU limit), Intel/AMD CPUs, ACPI, EFI, NUMA, Hyper-V and KVM guest support | One guest for the targeted Azure/GCP platforms; actual confidential cloud boots remain required |
| Confidential CPU memory | AMD memory encryption/SNP and Intel TDX guest support | Required guest mechanisms; does not establish provider firmware patch status or customer attestation |
| Provider identification | DMI identification, PCI and Hyper-V PCI frontend | Cloud-init datasource selection and assigned cloud hardware |
| Root and provisioning media | ext4, GPT, FAT EFI partition, ISO9660/Joliet cidata | Matches the existing Ubuntu Minimal/Packer disk layout; other filesystems are excluded |
| Storage | NVMe, Hyper-V SCSI, Virtio block/SCSI; mounted-device writes for privileged maintenance | Built in for root-by-PARTUUID boot without initramfs. Ubuntu's resize2fs requires mounted-device writes for first-boot disk growth; inference has no block-device access |
| Networking | IPv4 TCP/UDP, Unix sockets, packet/netlink APIs, GVE, Hyper-V/netvsc, Virtio, Mellanox Ethernet VF | HTTPS, DNS, DHCP, SSH and cloud network devices; no RDMA, IPv6, network filesystems, tunnel or firewall stacks |
| GPU compute | NVIDIA `nvidia` and `nvidia-uvm` only, firmware loading, MMU notifiers, native PAT/MTRR and dynamic SWIOTLB | Headless CUDA inference and GPU memory/DMA mapping; no NVIDIA modeset, DRM, peermem or vGPU host module |
| NVIDIA encryption | Linux AES-GCM/AES-NI, SHA-256/384/512, HMAC, RSA, ECDH, ECDSA and X.509 support | Required by NVIDIA's LKCA/libspdm implementation; build checks reject silently compiled crypto error stubs |
| Runtime | ELF/scripts, threads/futexes, shared memory/memfd, epoll, timers, proc/sysfs/tmpfs, PTY/serial | Existing Python/CUDA engines, systemd, network services and operator SSH; Safetensors uses mmap/read, so AIO/io_uring are excluded |
| Service isolation | Namespaces, seccomp, cgroup memory/PID/CPU limits and cgroup BPF | Required by the shipped systemd units, especially the tested loopback-only inference policy |
| Hardening | CPU mitigations, KASLR, stack protections, allocator hardening, AppArmor/Yama and integrity lockdown | Security controls remain enabled even when removing them would make the binary smaller |
| Module integrity | Forced signatures; build key's public certificate embedded in the kernel | Only modules signed by that build key load. The private key stays on the builder; this does not make the kernel trusted by cloud Secure Boot |

Excluded families include display, input/HID/USB, sound, media, Bluetooth/Wi-Fi,
host KVM/Xen, RDMA, storage targets, device mapper/RAID, network filesystems,
extra local filesystems, swap, core dumps, suspend/hibernate, pstore, kexec,
KSM, HMM, tracing and debugfs. NVIDIA explicitly disables HMM when confidential
computing is enabled (`kernel-open/nvidia-uvm/uvm_hmm.c`); UVM's MMU notifier
dependency is selected separately through the small appended Kconfig declaration.
Runtime algorithms and concurrency remain upstream implementations.

One [small backport](patches/0001-account-file-lock-caches.patch) restores
upstream file-lock cache memory accounting (CVE-2022-0480), including the lease
cache split out since the original patch. Upstream reverted the original change
for a locking microbenchmark regression. This appliance accepts that cost to
keep file-lock objects within the service memory budget. The ordinary boot test
checks actual cgroup slab charges for a bounded set of synthetic file locks;
inference throughput impact still requires GPU measurement. The change only
adds `SLAB_ACCOUNT` flags; it introduces no new synchronization code.

Linux 7.2 x86 unconditionally selects `PERF_EVENTS`; it remains part of the
architecture dependency closure. PMU extensions, tracing and BPF event attachment
are excluded. The inference service denies the debug syscall group and the OS
restricts unprivileged perf access. The upstream perf group-leader fix for
CVE-2026-74753 is present in the selected source.

## Build

Run on `axp.computer`, with GCC/G++, make, bc, bison, flex, libssl-dev,
libelf-dev, OpenSSL, GnuPG, curl, xz, kmod and dpkg tools:

```sh
make kernel
make image
```

The recipe pins Linux **7.2.10** and NVIDIA **580.178.04**, verifies both source
archive hashes, and verifies the Linux release signature against Greg
Kroah-Hartman's fingerprint published by [kernel.org](https://www.kernel.org/signature.html).
It uses upstream Kbuild and `dpkg-deb`; Packer remains the image builder.
`NTRUST_KERNEL_WORK` can point to a shared Linux build cache for the two engine
repositories; `NTRUST_BUILD_JOBS` defaults to 3.

The outputs are `build/ntrust-kernel.deb` and `build/ntrust-linux-headers.deb`.
The latter upgrades `linux-libc-dev` to `7.2.10-1+ntrust1` using upstream
`headers_install`. These sanitized userspace declarations support libc/CUDA JIT;
they are not additional compiled kernel drivers or full kernel development headers.
The build cache retains the resolved
configuration, module list, signature verification, package checksum and NVIDIA
symbol check. Its signing private key must never be copied into a guest, release
archive or Git. The packaged certificate is public. This recipe does not claim
reproducibility: generated module-signing keys and build metadata vary.

## Verification boundary

The image recipe checks the installed configuration, driver metadata and module
signatures. The ordinary UEFI/KVM smoke test must boot this kernel, load signed
ECC modules, exercise the real cgroup network restriction and reject inference
on an ordinary VM. Those are prerequisites to cloud testing, not substitutes for
an H100 confidential GPU test.

This custom kernel is not Canonical-signed. Existing provider launch recipes
keep Secure Boot enabled; their trust/enrollment path must be established before
this kernel can be used there. Do not silently disable Secure Boot to make a test
pass. Azure/GCP import, cloud boot, GPU initialization, encryption and inference
remain hardware validation steps.

The kernel is inventoried as a separate upstream Linux component, with image and
configuration hashes; it is not mislabeled as an Ubuntu HWE package. Historical
scanner output remains retained. Removing a package name from a distro scan is
not evidence that its vulnerabilities are fixed: kernel advisory review must use
the actual upstream version, source fixes and resolved configuration.
