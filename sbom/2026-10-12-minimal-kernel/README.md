# vLLM minimal-kernel image evidence — 2026-10-12

Built and tested on Linux x86-64 KVM at `axp.computer`, from source `c7e89cc78556d75731ae43b84156a4aac1f1b6f9`. This packet describes this engine's finished image. The [build record](build-record.json) ties the exported disk hashes to the kernel, configuration, packages and collected source files. The [earlier HWE packet](../2026-10-12/README.md) remains unchanged for comparison.

Inventory tool revision: `529cb4b46970dc739c0d0cd5937ef151e7fa17d8`. A reporting fix reads kernel identity from the installed package and NVIDIA module because Ubuntu Minimal excludes most package documentation during unpack. That tool update did not modify the built disk.

## Measured reduction

| Material | Previous HWE image | Custom Linux 7.2.10 image |
| --- | ---: | ---: |
| Kernel image bytes | 17,029,512 | 6,664,704 |
| Enabled Kconfig symbols (`y` or `m`) | 10,049 | 838 |
| Loadable module files | 6,908 | 6 |
| Stored loadable-module bytes | 178,099,324 | 22,540,830 |
| Installed Debian packages | 322 | 303 |

The kernel image is 60.9% smaller. The build starts from `allnoconfig` and resolves 282 explicit settings; these counts include architecture and dependency symbols, not only drivers. Cloud storage/network drivers are built in. The [built-in unit list](evidence/kernel-builtins.txt) contains 82 Kbuild module units; it is not a complete list of compiled kernel code. Stored module sizes reflect the packaging and compression of each build. There is no initramfs or guest DKMS. The [selection table](../../kernel/README.md) explains each retained function.

The [exact package delta](package-delta.json) removes 20 packages and adds `ntrust-kernel`, for a net reduction of 19. Removed packages are the HWE kernel/module bundles, initramfs toolchain, unused wireless regulatory data and guest microcode delivery tools. Host firmware/microcode remains the cloud provider's responsibility. `linux-libc-dev` is upgraded to sanitized upstream headers; all other Debian package versions and every Python distribution version are unchanged.

| Loadable module | Bytes |
| --- | ---: |
| `/usr/lib/modules/7.2.10-ntrust/updates/nvidia/nvidia-uvm.ko` | 3,748,025 |
| `/usr/lib/modules/7.2.10-ntrust/updates/nvidia/nvidia.ko` | 18,667,041 |
| `/usr/lib/modules/7.2.10-ntrust/kernel/crypto/ecdsa_generic.ko` | 33,417 |
| `/usr/lib/modules/7.2.10-ntrust/kernel/crypto/ecdh_generic.ko` | 16,153 |
| `/usr/lib/modules/7.2.10-ntrust/kernel/crypto/kpp.ko` | 10,601 |
| `/usr/lib/modules/7.2.10-ntrust/kernel/crypto/ecc.ko` | 65,593 |

## Installed materials

| Category | Count |
| --- | ---: |
| Debian packages | 303 |
| Python distributions | 200 |
| GPU `.cubin` ELF files | 42,704 |
| Other userspace ELF files in scope | 503 |
| Loadable kernel module ELF files | 6 |

ELF files overlap package contents and must not be counted as additional packages. This packet expands the earlier native hash scope to include all six kernel modules. Other distribution libraries are identified by Debian package version. The upstream inference and CUDA dependencies are retained; reducing the FlashInfer bundle further requires actual H100 execution to establish the needed subset.

| File | Contents |
| --- | --- |
| [inventory.json.gz](inventory.json.gz) | Installed package versions and every scoped ELF hash |
| [sbom.cdx.json.gz](sbom.cdx.json.gz) | Project CycloneDX 1.6 inventory, including explicit upstream Linux and NVIDIA components |
| [sbom.syft.cdx.json.gz](sbom.syft.cdx.json.gz) | Independent full-image Syft inventory |
| [vulnerabilities.trivy.json.gz](vulnerabilities.trivy.json.gz) | Unsuppressed full-image Trivy results |
| [scan-summary.json](scan-summary.json) | Raw counts by severity and package |
| [kernel-advisory-review.json.gz](kernel-advisory-review.json.gz) | All 4,294 historical kernel advisory IDs, with source/configuration/version dispositions |
| [config-7.2.10-ntrust](config-7.2.10-ntrust) | Exact resolved configuration, SHA-256 `bc5f5fbe3a4abbf9b932ec6315d9b7d5616572ccaf5b06823b0d06f7ac81d04f` |
| [unit-files.txt](unit-files.txt) | Installed service definitions and activation states |
| [evidence/](evidence/) | Build, boot, reboot, export, isolation, cleanup and schema-validation results |
| [image-SHA256SUMS](image-SHA256SUMS) | Finished disk/export identities |

Large JSON files are gzip-compressed. Schema-validation hashes refer to the decompressed JSON; the packet checksum manifest verifies the published files. From the repository root:

```sh
gzip -dc sbom/2026-10-12-minimal-kernel/inventory.json.gz > /tmp/ntrust-inventory.json
sha256sum --check sbom/2026-10-12-minimal-kernel/SHA256SUMS
```

## What ran

- Linux and the NVIDIA compute/UVM interfaces compiled successfully. Linux source hashes and its release signature were verified; NVIDIA source hashes were verified. The build checks real LKCA crypto references to reject NVIDIA crypto error stubs.
- Fresh Packer image builds passed installed package checks, NGINX/ACME configuration parsing, CPU Safetensors save/load, CUDA SM90a compilation, Python-extension header compilation and the installed upstream parser checks. vLLM's parser test mocks its device type; no GPU kernel or model was executed.
- Each finalized image booted through its shipped GRUB and custom kernel in an ordinary UEFI/KVM VM. A disposable 65 GiB overlay exercised real cloud-init partition and ext4 filesystem expansion from the 64 GiB image.
- Forced signatures rejected an unsigned copy of a valid module, including when root requested the load. The signed ECC modules loaded. Unwanted modules and removed packages were absent.
- The ordinary VM failed confidential-GPU admission, created no inference credential and opened neither inference listener. The shipped systemd IP policy allowed loopback and denied an otherwise reachable non-loopback destination.
- The file-lock patch charged 65,536 synthetic POSIX locks to a bounded 96 MiB service cgroup. The exact measured slab charge is in [the test log](evidence/boot-check-file-lock-accounting.log).
- The same VM rebooted, regained networking and continued to reject ordinary-VM inference without a credential or listener.
- QCOW2/raw, fixed Azure VHD and extracted GCP archive comparisons passed. Read-only inspection found no retained build SSH authorization, SSH host identity, cloud seed, saved random seed, runtime configuration, model or private-key header within the documented inspection scope.
- Both CycloneDX documents passed their official schemas; every inventoried package version and native hash reconciled with the project SBOM.
- All unchanged userspace ELF paths, sizes and hashes matched the independently collected earlier inventory. The only additional native entries are the six kernel modules. This also checks the bounded parallel inventory reads against the previous serial collection.

**Not exercised:** Azure/GCP import or boot, provider Secure Boot trust enrollment, SNP/TDX plus H100 operation, GPU model requests, live ACME issuance, customer remote verification or image sealing. Ordinary VM tests do not establish confidential hardware compatibility. The custom kernel is not Canonical-signed; provider recipes retain Secure Boot and require a compatible trust path.

## Vulnerability evidence

Trivy database update: `2026-10-12T13:18:23.1639207Z`. Current raw package matches: **CRITICAL: 0**, **HIGH: 0**, **MEDIUM: 87**, **LOW: 32**, **UNKNOWN: 0**. There are 36 distinct advisory IDs. These are scanner matches, not a count of reachable exploits.

**Do not interpret the reduced distro-scanner total as all kernel findings being fixed.** The custom kernel and sanitized UAPI-header package no longer use Ubuntu HWE identities. The SBOM explicitly records upstream Linux 7.2.10, and the separate kernel review carries every historical kernel advisory forward. Linux CNA metadata is pinned to `b3dd75ace018d7588a9d02db03acd15bb68c3826`. Maintainer version ranges are not an independent audit of every fixing commit or a search for new defects.

| Kernel advisory disposition | Distinct IDs |
| --- | ---: |
| Affected feature is compiled out of this exact configuration | 43 |
| Affected implementation is absent from this upstream source | 3 |
| Unresolved; no patch claim | 7 |
| Fix independently checked in the selected source | 2 |
| File-lock accounting restored by the included upstream-derived patch | 1 |
| Linux maintainer metadata places 7.2.10 outside the affected range | 4,234 |
| Maintainer default is unaffected; listed older branch regressions do not include 7.2.10 | 2 |
| Requires provider host firmware evidence | 1 |
| Affected Qualcomm hardware is outside the x86 cloud target | 1 |

The file-lock change restores [upstream memory accounting](https://github.com/torvalds/linux/commit/0f12156dff2862ac54235fc72703f18770769042), including the subsequently separated lease cache. Upstream reverted it for a locking microbenchmark regression. This appliance accepts that tradeoff for cgroup memory containment; GPU throughput impact remains unmeasured. No new locking algorithm was introduced.

The following entries remain unresolved or provider-dependent. Exposure observations do not claim patches:

| Advisory | Remaining status |
| --- | --- |
| [CVE-2017-13165](https://ubuntu.com/security/CVE-2017-13165) | Android IP-address disclosure policy via /proc/net/fib_trie. IP addresses are not guest secrets here; upstream access semantics remain. Not claimed patched. |
| [CVE-2017-13693](https://ubuntu.com/security/CVE-2017-13693) | ACPI information disclosure: debug/debugger options are disabled, but the advisory is not fully closed. |
| [CVE-2018-1121](https://ubuntu.com/security/CVE-2018-1121) | PID enumeration race. Process listings are not an enforcement boundary. Not claimed fixed. |
| [CVE-2019-14899](https://ubuntu.com/security/CVE-2019-14899) | VPN traffic inference/hijack scenario: no VPN is shipped; upstream behavior is not claimed patched. |
| [CVE-2020-14304](https://ubuntu.com/security/CVE-2020-14304) | Privileged ethtool EEPROM disclosure: relevance to the retained Mellanox VF path still needs adjudication. |
| [CVE-2020-35501](https://ubuntu.com/security/CVE-2020-35501) | Audit coverage limitation; the appliance does not use audit syscall records as an enforcement boundary. Not claimed fixed. |
| [CVE-2022-4543](https://ubuntu.com/security/CVE-2022-4543) | EntryBleed: no complete upstream fix established. CPU mitigations and the restricted service are not claimed as a patch. |
| [CVE-2023-20585](https://ubuntu.com/security/CVE-2023-20585) | Host AMD IOMMU/RMP firmware issue. Removing guest microcode packages does not fix host firmware; provider patch status must be established. |

Non-kernel findings remain in the unsuppressed scanner report. This kernel change does not claim to fix the retained engine/Python/OS dependency findings. Feature removal applies only to this exact configuration; adding a feature requires revisiting its disposition.

## Selected installed versions

| Package | Version |
| --- | --- |
| `ntrust-kernel` | `7.2.10-1` |
| `linux-libc-dev` | `7.2.10-1+ntrust1` |
| `cloud-init` | `26.1-0ubuntu1~24.04.1` |
| `systemd` | `255.4-1ubuntu8.17` |
| `openssh-server` | `1:9.6p1-3ubuntu13.19` |
| `python3.12` | `3.12.3-1ubuntu0.17` |
| `python3-dev` | `3.12.3-0ubuntu2.1` |
| `gcc` | `4:13.2.0-7ubuntu1` |
| `g++` | `4:13.2.0-7ubuntu1` |
| `libc6` | `2.39-0ubuntu8.9` |
| `ninja-build` | `1.11.1-2` |
| `nginx` | `1.30.5-1~noble` |
| `nginx-module-acme` | `1.30.5+0.4.1-1~noble` |
| `nvattest` | `2.0.0.1790976895-1` |
| `libnvat` | `2.0.0.1790976895-1` |
| `nvidia-utils-580-server` | `580.178.04-0ubuntu0.24.04.1` |

All other versions are in the machine-readable inventory. The [component selection and risk table](../../docs/SECURITY-BOM.md) explains why they remain. Sanitized `linux-libc-dev` declarations support userspace compilation; they are not extra kernel drivers.

## Artifact identity

The original virtual disk is 64 GiB. The 65 GiB test overlay is disposable and is not an exported artifact. Binaries remain on the Linux builder; they are not attached to a GitHub release. Logical VHD size, QCOW2 size and local allocated space are different measurements.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `dist/qemu/ntrust.qcow2` | 16,385,048,576 | `6bf42d43c568bd65f11fc5abad411c3557d4baa797ab4827da1ce5c34078a5b6` |
| `dist/ntrust-gcp.tar.gz` | 5,844,399,713 | `a0e215b9f4fda68446c4ccb47e89aad9609e8691ddf09ecdbee96a528b68f4e8` |
| `dist/ntrust-azure.vhd` | 68,719,477,248 | `b8469efe51fdfbc009f7dcd16dd79804aae6f390f6b1496a786d78558b3ac797` |

On the builder, verify the finished exports from the corresponding repository root:

```sh
sha256sum --check sbom/2026-10-12-minimal-kernel/image-SHA256SUMS
```

Build logs have ANSI styling and trailing whitespace normalized for readability. Scanners run outside the guest on read-only mounts. Reproducible releases and image sealing remain separate work.
