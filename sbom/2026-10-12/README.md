# vLLM image inventory and validation — 2026-10-12

This inventory was generated from this project's completed Linux image on `axp.computer`. It is not a reused inventory of another inference engine. Build source: `7ec986438b986d8831ebc0a8fc596dd4a5873c91`. [Build record](build-record.json) includes input hashes, artifact sizes and validation limits.

## Installed materials

| Category | Count | Meaning |
| --- | ---: | --- |
| Debian packages | 322 | Installed package name, version and architecture |
| Python distributions | 200 | Installed isolated-venv metadata, versions, license text and declared requirements |
| GPU `.cubin` ELF files | 42704 | Specialized precompiled GPU kernel files within installed packages |
| Other native ELF files | 503 | Other native file sizes and SHA-256 hashes within the stated scope |

The native file inventory totals 43207 ELF files, including the bundled GPU kernels. ELF files overlap package contents; these counts must not be added as independent software packages. The native scope is the inference venv, NGINX, its ACME module and nvattest. Other distribution libraries are identified by Debian package version. The supported upstream GPU engine and its JIT/compiler dependencies add substantially to the minimal OS footprint. Many kernel variants belong to one FlashInfer package; they are not independent libraries. This build retains the upstream bundle until H100 execution can verify a smaller architecture-specific subset.

| File | Contents |
| --- | --- |
| [inventory.json.gz](inventory.json.gz) | Exact installed materials and scoped native hashes |
| [sbom.cdx.json.gz](sbom.cdx.json.gz) | Project CycloneDX 1.6 package/file inventory |
| [sbom.syft.cdx.json.gz](sbom.syft.cdx.json.gz) | Independent maintained-tool inventory from Syft |
| [vulnerabilities.trivy.json.gz](vulnerabilities.trivy.json.gz) | Unsuppressed dated vulnerability matches |
| [vulnerability-triage.json](vulnerability-triage.json) | HIGH/CRITICAL findings and evidence-based kernel dispositions |
| [trivy-db-metadata.json](trivy-db-metadata.json) | Vulnerability database timestamps |
| [unit-files.txt](unit-files.txt) | Installed unit definitions and activation states, including static/masked units |
| [evidence/](evidence/) | Build, export, boot, isolation, cleanup and schema-validation results |
| [image-SHA256SUMS](image-SHA256SUMS) | Finished image and provider-export SHA-256 values |

Large JSON reports are gzip-compressed. Schema-validation and triage source hashes refer to the decompressed JSON; `SHA256SUMS` verifies the published files. For example:

```sh
gzip -dc sbom/2026-10-12/inventory.json.gz > /tmp/ntrust-inventory.json
sha256sum --check sbom/2026-10-12/SHA256SUMS
```

Build evidence logs have ANSI styling and trailing whitespace normalized for readability.

## What ran

- The Linux Packer/QEMU image build, installed package checks, real NGINX/ACME configuration parsing, CUDA SM90a compilation and Python-extension header compilation passed.
- The installed upstream launcher parser accepted the selected privacy and serving options. vLLM's parser check mocks its device type on this CPU-only builder. No GPU kernel or model was executed.
- Raw disk, sparse GCP archive and fixed Azure VHD comparisons passed before the artifact checksum manifest was published.
- The completed image booted in an ordinary UEFI KVM VM. It rejected confidential-GPU admission, created no inference API key and opened neither inference listener.
- The shipped inference IP policy allowed a loopback request and blocked an otherwise reachable non-loopback address. This tests that IP policy, not all possible local IPC paths.
- Removed packages were absent, unwanted services were masked, and blocked modules were absent and rejected loading. Root filesystem features and kernel configuration were recorded for advisory triage.
- Read-only inspection found no builder authorization, SSH host identity, cloud seed, saved random seed, runtime configuration or model. The private-key header inspection is scoped and size-bounded as described in its log; this is not forensic disk sealing.
- Both CycloneDX files passed their official JSON schemas; the project SBOM was reconciled with installed package versions and scoped native hashes.

**Not exercised:** Azure/GCP import or boot, confidential CPU/GPU execution, model requests on H100, live ACME issuance, customer remote verification or image sealing. See [cloud bring-up](../../image/clouds.md) for the hardware acceptance procedure.

## Vulnerability snapshot

Trivy database update: `2026-10-12T09:47:21.509023105Z`. Matches by severity: **CRITICAL: 5**, **HIGH: 166**, **MEDIUM: 6050**, **LOW: 301**, **UNKNOWN: 0**. There are 4345 distinct advisory IDs across package matches. These are scanner matches, not a count of reachable exploits.

The kernel findings are individually retained in [the triage](vulnerability-triage.json), linked to the matching installed version and this image's boot/configuration/filesystem evidence. Module and service restrictions are mitigations, not vendor patches; root can bypass them. Raw findings remain unsuppressed. Any other HIGH/CRITICAL findings are listed separately there and must not be hidden by the kernel dispositions.

The HIGH/CRITICAL review separates **23 HWE kernel matches** from **148 matches against `linux-libc-dev`**. The latter binary package contains UAPI headers and documentation, not the affected kernel implementations; [its actual file inventory](evidence/linux-libc-dev-files.json) records the review. All five critical matches are in that header group. Ubuntu's linked advisories list fixes for those five in HWE versions at or before the installed `7.0.0-38.38~24.04.4`. This does not dismiss the separate HWE findings or claim all kernel flaws are patched.

No additional HIGH/CRITICAL package groups were found. Lower-severity matches remain visible in the raw report and are not individually cleared by this triage.

The sole match with a scanner-listed fixed version is the MEDIUM setuptools `CVE-2026-59890` finding. Its affected workflow is source-distribution creation/publication, which this binary-wheel-only Linux image does not perform. vLLM requires setuptools below 81 on Python 3.12, so upgrading to the scanner's fixed version 83 would violate the upstream dependency contract. The package is retained for compatibility and the finding remains unsuppressed; this is an exposure assessment, not a patch. [Upstream advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c).

## Selected installed OS versions

| Package | Installed version |
| --- | --- |
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
| `linux-modules-7.0.0-38-generic` | `7.0.0-38.38~24.04.4` |

The [selection and risk table](../../docs/SECURITY-BOM.md) explains why components remain. All remaining exact Debian and Python versions are in the machine-readable inventory.

## Artifact identity

The virtual disk is 64 GiB. QCOW2 and archive sizes differ from logical VHD size and filesystem allocation. Binaries remain on the Linux builder; they are not attached to a GitHub release.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `dist/qemu/ntrust.qcow2` | 16,720,461,824 | `ea6afaf24e69bfc88e0a186895c51f8abc8111c092060fb9a6ea5ccd868f316d` |
| `dist/ntrust-gcp.tar.gz` | 6,101,726,616 | `1d1df0c7fbda353d23a72523c32ca50b87f28b0b64e1f67c286b1aa42c497f5d` |
| `dist/ntrust-azure.vhd` | 68,719,477,248 | `3874007a293454578e1e981cfeeb548118c70f231f70f405be0038fa1454e48e` |

From the repository root on the builder, verify the exported files with:

```sh
sha256sum --check sbom/2026-10-12/image-SHA256SUMS
```

Scanners and inventory tools run outside the guest on read-only mounts. Scan results depend on database coverage and timestamp; this is not a claim that the image has no vulnerabilities.
