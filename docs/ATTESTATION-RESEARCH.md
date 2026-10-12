# Remote Attestation & Marketplace Publication Architecture

This document evaluates the remote attestation architectures, protocol profiles, and cloud marketplace publication requirements for the `ntrust` confidential GPU inference images across **AMD SEV-SNP + Intel TDX CPU TEEs** and **NVIDIA Hopper/Blackwell (H100, H200, B100, B200) Confidential Compute GPUs** on **Azure** and **Google Cloud**.

> **Current implementation boundary:** In the shipped guest (`guest/gpu-ready`), `nvattest` runs locally at boot to verify GPU SPDM session integrity, RIM measurements, and CC-On readiness before generating the per-boot RAM API key, while NGINX obtains a publicly trusted WebPKI certificate inside the TEE via Let's Encrypt **TLS-ALPN-01** (`ngx_http_acme_module` with `state_path off`). Local admission prevents an ordinary VM from starting the inference engine, but it **does not** prove to a remote client that a specific domain's TLS private key resides inside a genuine, unmodified CPU+GPU TEE. Closing that gap requires remote attestation bound to the TLS session.

---

## 1. Threat Model & What Must Be Bound

A remote client sending sensitive prompts over HTTPS needs cryptographic proof of five properties **before** transmitting bearer credentials or prompt payloads:

1. **CPU TEE Authenticity & TCB Status:** The guest runs inside a hardware-enforced AMD SEV-SNP (`/dev/sev-guest`) or Intel TDX (`/dev/tdx_guest`) confidential VM with production attributes (`DEBUG=0`, `SMT` policy, valid SVN/TCB) signed by a hardware root of trust (AMD VCEK/VLEK or Intel PCK/QE).
2. **Measured Boot & Immutable Image Identity:** The firmware (OVMF/UEFI), bootloader (GRUB), kernel (`vmlinuz-7.2.10-ntrust`), command line, and root filesystem/runtime configuration match an approved release digest published via GitHub SLSA Build Provenance (`dist/SHA256SUMS`).
3. **GPU TEE Authenticity & Co-location:** The attached NVIDIA GPU is in production `CC-On` mode, its firmware/driver measurements match NVIDIA Reference Integrity Manifests (RIMs), and its SPDM attestation report is freshly bound to the CPU TEE session.
4. **TLS Channel / Key Binding (Relay-Attack Prevention):** The attestation evidence is cryptographically bound to the **exact TLS 1.3 connection** (or the ephemeral leaf SubjectPublicKeyInfo generated in guest RAM at `/run/ntrust-web`), preventing a malicious operator who controls DNS from obtaining a valid Let's Encrypt certificate on a non-TEE host and forwarding stolen attestation quotes.
5. **Freshness:** Evidence incorporates a high-entropy client challenge or bounded TLS exporter context to prevent replay of historical boot quotes.

---

## 2. Protocol Alternatives: RA-TLS vs. IETF RATS vs. TLS Exporter Binding

| Dimension | Option A: Classic RA-TLS (X.509 Extension) | Option B: IETF RATS Background-Check / Passport over HTTPS | Option C: WebPKI + RFC 9266 TLS Exporter Binding (Recommended Primary) |
| :--- | :--- | :--- | :--- |
| **Core Mechanism** | Embeds raw TEE quote + GPU evidence inside a custom X.509v3 OID extension on a self-signed ephemeral TLS certificate during the TLS handshake. | Standard WebPKI TLS 1.3 handshake (`acme-tls/1` Let's Encrypt cert), followed by an HTTP attestation endpoint (`/v1/attest` or `Attestation-Evidence` header) returning an IETF RATS bundle / EAT token. | Standard WebPKI TLS 1.3 handshake + HTTP attestation endpoint whose hardware `REPORT_DATA` binds `SHA-512(version \|\| client_nonce \|\| leaf_SPKI_sha256 \|\| tls_exporter_rfc9266 \|\| gpu_evidence_sha256 \|\| manifest_sha256)`. |
| **Standards Alignment** | Intel SGX/TDX RA-TLS, Confidential Containers (CoCo), Gramine/Occlum conventions; `draft-fossati-tls-attestation` (Attested TLS). | [IETF RFC 9334 (RATS Architecture)](https://www.rfc-editor.org/rfc/rfc9334.html), [IETF RFC 9711 (EAT — Entity Attestation Token)](https://www.rfc-editor.org/rfc/rfc9711.html). | Combines [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334.html), [RFC 9266 (`tls-exporter` Channel Binding)](https://www.rfc-editor.org/rfc/rfc9266.html), and standard Let's Encrypt WebPKI + Certificate Transparency. |
| **Browser & Standard SDK Compatibility** | **Breaks standard HTTPS clients.** Self-signed certificates require custom `SSLContext` verification callbacks and fail in standard browsers, `curl`, and unmodified OpenAI SDKs. | **100% compatible** with standard HTTPS clients, corporate proxies, and Certificate Transparency monitors. | **100% compatible** with standard HTTPS clients; verification-aware clients additionally pin the `tls-exporter` or leaf `SPKI` digest before sending prompts. |
| **Handshake Size & Latency** | Bloats the TLS `Certificate` message by 8–20 KiB (SEV-SNP/TDX quote + VCEK/PCK cert chain + NVIDIA SPDM evidence + RIMs) on every new connection. | Zero impact on TLS handshake size; evidence is fetched once per session or cached per leaf SPKI + fresh nonce. | Zero impact on TLS handshake size; supports both per-connection `tls-exporter` binding and per-boot SPKI + client-nonce binding. |
| **Multi-Device (CPU + GPU) Support** | Awkward: requires custom composite ASN.1 DER schema for CPU quote + NVIDIA `nvattest` JSON/COSE payload. | Native: RATS composite evidence / EAT `submods` claim ([RFC 9711 Section 4.2.18](https://www.rfc-editor.org/rfc/rfc9711.html)) cleanly nests CPU TEE and GPU TEE evidence. | Native: RATS composite evidence bundle binds the GPU attestation digest directly into the 64-byte CPU `REPORT_DATA` field. |

### Why We Recommend Supporting Both IETF RATS (WebPKI + SPKI/Exporter Binding) and Optional RA-TLS

1. **Primary Profile — IETF RATS Composite Evidence with WebPKI SPKI + Nonce Binding (`/v1/attest`):**
   - Preserves `ntrust`'s core design: in-guest Let's Encrypt TLS-ALPN-01 issuance, Certificate Transparency observability, and unmodified OpenAI `/v1/chat/completions` compatibility.
   - Binds the serving Let's Encrypt certificate's DER `SubjectPublicKeyInfo` (`leaf_spki_sha256`), the client's unpredictable 32-byte nonce, and the NVIDIA GPU evidence digest into the 64-byte `REPORT_DATA` of the AMD SEV-SNP (`SNP_GET_REPORT`) or Intel TDX (`TDG.VP.VMCALL<GetQuote>`) hardware quote.
   - Supports both **RATS Background-Check Model** (client verifies raw CPU quote + VCEK/PCK chain + NVIDIA `nvattest` evidence locally using an open-source verifier library) and **RATS Passport Model** (guest or client exchanges raw evidence with an external verifier—NVIDIA NRAS, Intel Trust Authority, Azure MAA, or GCP Confidential Space/Attestation—for a signed RFC 9711 EAT JWT/CWT).
2. **Secondary Profile — RA-TLS / Attested TLS (`draft-fossati-tls-attestation` / X.509 Extension Mode):**
   - Useful for closed mTLS/gRPC mesh deployments where public DNS / Let's Encrypt ACME is unavailable (e.g., private VPC endpoints without public TCP 443 ingress).
   - Can be offered as an optional listener or transport adapter where an ephemeral X.509 certificate embeds the RATS composite evidence under a documented OID (`1.3.6.1.4.1.56569.1.1` / Intel RA-TLS OID) with `REPORT_DATA = SHA-512(ephemeral_spki_der)`.

---

## 3. Hardware & Cloud Verifier Ecosystem Matrix

To avoid locking users into a single vendor's cloud attestation service, `ntrust` should emit a **canonical raw evidence bundle** alongside optional Passport tokens:

### 3.1 CPU TEE Evidence & Endorsement Sources

| Platform | Guest Device | Hardware Quote Format | Endorsement / Collateral Source | Cloud-Native Verifier Option |
| :--- | :--- | :--- | :--- | :---
| **AMD SEV-SNP** (Azure `NCCads_H100_v5`, GCP `a3-highgpu-1g` / C3D) | `/dev/sev-guest` (`SNP_GET_EXT_REPORT` ioctl) | 1184-byte `attestation_report` (`version >= 2`, `vmpl == 0`, `report_data[64]`, `measurement[48]`, `host_data[32]`, `reported_tcb`) | [AMD Key Distribution Service (KDS)](https://kdsintf.amd.com/vcek/v1/) (`VCEK` / `VLEK` X.509 chain + CRLs) or cached Azure THIM / GCP endorsement | **Self-verified** (`sev` / `go-sev-guest`), **Microsoft Azure Attestation (MAA)**, or **GCP Attestation Service** |
| **Intel TDX** (Azure `DCesv5` / `ECesv5` + CC GPU, GCP C3 TDX) | `/dev/tdx_guest` (`TDX_CMD_GET_QUOTE` ioctl via ConfigFS-TSM) | Intel DCAP TD Quote v4/v5 (`MRTD[48]`, `RTMR[0..3][48]`, `REPORTDATA[64]`, `TDATTRIBUTES`) | Intel PCS / PCCS (`PCK` cert chain, TCB Info, QE Identity) or Azure THIM | **Self-verified** (`go-tdx-guest` / Intel DCAP QVL), **Intel Trust Authority (ITA)**, **Azure MAA**, or **GCP Attestation** |

> **Linux 7.2 ConfigFS-TSM unify path:** Modern Linux kernels (6.7+ and our Linux `7.2.10-ntrust`) provide `/sys/kernel/config/tsm/report/` (`CONFIG_TSM_REPORTS=y`), a vendor-neutral kernel interface that generates both AMD SEV-SNP and Intel TDX attestation reports without vendor-specific ioctl wrappers. Enabling `CONFIG_CONFIGFS_FS=y` and `CONFIG_TSM_REPORTS=y` in Phase 2 allows a single 50-line userspace helper to request quotes across both CPU architectures.

### 3.2 NVIDIA Confidential GPU Evidence (`nvattest` & SPDM)

1. **In-Guest Collection (`nvml` + SPDM):**
   - The guest collects signed GPU attestation reports (`OPAQUE` SPDM `GET_MEASUREMENT` response signed by the GPU's device-unique Alias Key Certificate chained to the NVIDIA Device Identity Root CA) using `nvattest` / `libnvat` (`2.0.0`).
2. **Two Verification Modes (RATS Background-Check vs. Passport):**
   - **Local / Self-Contained Background-Check (`--verifier local`):** The guest verifies GPU evidence locally at boot against NVIDIA's RIM (Reference Integrity Manifest) service and OCSP revocation responders, and returns the raw signed GPU evidence + certificate chain + RIM bundle to the client so the client can independently re-verify offline without trusting the guest CPU alone.
   - **NVIDIA Remote Attestation Service (`--verifier nras` Passport):** The guest (or client) submits the GPU evidence + nonce to [NVIDIA NRAS](https://attestation.nvidia.com), which returns an **EAT-compliant JSON Web Token (JWT)** signed by NVIDIA's attestation signing key asserting `x-nvidia-gpu-arch-check`, `x-nvidia-gpu-driver-version`, `x-nvidia-gpu-vbios-version`, and `secboot`/`dbgstat` status.

### 3.3 Composite CPU + GPU Binding Construction

To cryptographically bind the GPU, the CPU TEE, the TLS certificate, and the client's challenge into a single verifiable root:

1. Client opens TLS 1.3 connection to `https://<NTRUST_DOMAIN>/v1/attest?nonce=<32B-hex>` (or passes `X-Ntrust-Nonce`).
2. Guest derives `gpu_nonce = SHA-256("ntrust-gpu-v1" || client_nonce || leaf_spki_sha256)`.
3. Guest invokes `libnvat` / `nvattest` with `gpu_nonce` to obtain fresh hardware-signed `gpu_evidence`.
4. Guest computes the 64-byte CPU `REPORT_DATA`:
   $$\text{REPORT\_DATA} = \text{SHA-512}\big(\text{"ntrust-rats-v1"} \parallel \text{client\_nonce} \parallel \text{SHA-256}(\text{leaf\_SPKI\_DER}) \parallel \text{SHA-256}(\text{gpu\_evidence}) \parallel \text{SHA-256}(\text{runtime\_manifest})\big)$$
5. Guest requests a hardware CPU quote from `/sys/kernel/config/tsm/report` (or `/dev/sev-guest` / `/dev/tdx_guest`) with `REPORT_DATA`.
6. Guest returns the JSON/CBOR RATS composite evidence bundle containing:
   - `cpu_quote` (base64) + `cpu_endorsement_chain` (`VCEK`/`PCK`)
   - `gpu_evidence` + `gpu_cert_chain` (+ optional NRAS EAT JWT)
   - `leaf_spki_sha256` and `sct_list` (Certificate Transparency SCTs)
   - `runtime_manifest` (pinned `model.json` digest, kernel `image_sha256`, and GitHub SLSA provenance link)

---

## 4. Phased Implementation Plan (Keeping Custom Code Small)

In accordance with `AGENTS.md` (*"Keep custom code small... Remote attestation, customer verification, reproducible releases and image sealing are deferred. Do not let that work delay the core VM"*), attestation should be rolled out in three strictly bounded increments:

1. **Phase 1 — Build Provenance & Measured Kernel/OS Baseline (Implemented in CI):**
   - Build the sculpted Linux `7.2.10-ntrust` kernel and guest image on GitHub-hosted `ubuntu-24.04` runners using hardware `/dev/kvm` (`.github/workflows/image.yml`).
   - Emit cryptographic **SLSA Build Provenance (`actions/attest-build-provenance`)** over `dist/SHA256SUMS`, `build/ntrust-kernel.deb`, and `build/ntrust-linux-headers.deb`.
   - Maintain dated CycloneDX SBOMs and full-image Trivy/Syft scans (`sbom/2026-10-12-minimal-kernel/README.md`).
2. **Phase 2 — Read-Only `/v1/attest` RATS Endpoint + ConfigFS-TSM:**
   - Enable `CONFIG_CONFIGFS_FS=y` and `CONFIG_TSM_REPORTS=y` in `kernel/required.config`.
   - Add a minimal, memory-only attestation responder on loopback (`127.0.0.1:8082`) exposed via a third exact NGINX route (`GET /v1/attest`), binding `leaf_spki_sha256` + `client_nonce` + `nvattest` GPU evidence into the CPU hardware quote.
   - Ship a lightweight client verifier script (`client/verify-ntrust.py`) that validates the TLS peer's `SubjectPublicKeyInfo`, the CPU quote signature/measurements, and the NVIDIA GPU evidence before forwarding OpenAI SDK traffic.
3. **Phase 3 — Unified Kernel Image (UKI), dm-verity Rootfs Sealing & Custom UEFI Secure Boot:**
   - Seal the read-only root filesystem with `dm-verity` and bundle `vmlinuz-7.2.10-ntrust` + kernel cmdline (`root_hash=...`) into a PE-signed Unified Kernel Image (UKI) so `RTMR` / `LaunchMeasurement` covers the entire userspace and Python/CUDA closure.

---

## 5. Cloud Marketplace & Image Publication Prerequisites

Publishing the CI-built `dist/ntrust-azure.vhd` and `dist/ntrust-gcp.tar.gz` images to the **Microsoft Azure Marketplace** and **Google Cloud Marketplace** requires both technical image preparation (already handled by `make export`) and external account/certification steps:

### 5.1 Microsoft Azure Marketplace & Azure Compute Gallery

1. **Technical Image Requirements (Satisfied in Repo):**
   - Fixed-size VHD (`dist/ntrust-azure.vhd`, 1 MiB aligned via `image/export.sh`), Generation 2 UEFI boot, `hv_vmbus`/`hv_storvsc`/`hv_netvsc`/`mlx5_core` built into `7.2.10-ntrust`, `walinuxagent` removed in favor of `cloud-init` `Azure` datasource (`image/install.sh`).
2. **External Prerequisites (Requires Operator Credentials & Partner Center):**
   - **Azure Compute Gallery (SIG) Definition:** Create an image definition with `--hyper-v-generation V2`, `--security-type TrustedLaunchAndConfidentialVmSupported`, and `--os-state Generalized` (see [`image/clouds.md`](../image/clouds.md)).
   - **Custom UEFI Secure Boot Key Enrollment:** Because `vmlinuz-7.2.10-ntrust` is compiled from upstream `kernel.org` source rather than Canonical's Microsoft-signed shim/kernel binary, launching with `secureBootEnabled=true` requires signing `vmlinuz-7.2.10-ntrust` with `sbsign` using a project UEFI `db` key and enrolling that public X.509 certificate in the Azure Compute Gallery image version's `securityProfile.uefiSettings` ([Azure Custom UEFI Secure Boot documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-secure-boot-custom-uefi)).
   - **Microsoft Partner Center Commercial Marketplace:** Requires an enrolled Microsoft Partner Center publisher account, a Virtual Machine offer submission referencing the Azure Compute Gallery image version, and passing the **Azure Marketplace VM Certification test suite** (`azure-marketplace-validation`).

### 5.2 Google Cloud (GCP) Compute Engine & Cloud Marketplace

1. **Technical Image Requirements (Satisfied in Repo):**
   - GNU-format sparse `disk.raw` archive (`dist/ntrust-gcp.tar.gz`), UEFI boot, `gve` (Google Virtual NIC) and `nvme` built into `7.2.10-ntrust`, `cloud-init` `GCE` datasource enabled.
2. **External Prerequisites (Requires GCP Project & Producer Portal):**
   - **Custom Shielded/Confidential Image Creation:** Import `dist/ntrust-gcp.tar.gz` with `gcloud compute images create --guest-os-features=UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE,GVNIC,SEV_SNP_CAPABLE,TDX_CAPABLE` and enroll the custom UEFI `db` signing certificate via `--signature-database-file` ([GCP Shielded Images documentation](https://cloud.google.com/compute/shielded-vm/docs/creating-shielded-images)).
   - **Google Cloud Marketplace Producer Portal:** Requires a verified Google Cloud Partner / Producer Portal account, public image IAM sharing, and Marketplace VM readiness review.

---

## 6. Authoritative References

- **IETF RFC 9334 — Remote ATtestation procedureS (RATS) Architecture:** <https://www.rfc-editor.org/rfc/rfc9334.html>
- **IETF RFC 9711 — The Entity Attestation Token (EAT):** <https://www.rfc-editor.org/rfc/rfc9711.html>
- **IETF RFC 9266 — Channel Bindings for TLS 1.3 (`tls-exporter`):** <https://www.rfc-editor.org/rfc/rfc9266.html>
- **AMD SEV-SNP Firmware ABI & Key Distribution Service (KDS):** <https://www.amd.com/en/developer/sev.html> / <https://kdsintf.amd.com/vcek/v1/>
- **Intel Trust Domain Extensions (TDX) & Intel Trust Authority (ITA) / RA-TLS:** <https://docs.trustauthority.intel.com/>
- **NVIDIA Confidential Computing & Attestation SDK (`nvtrust` / `nvattest` / NRAS):** <https://docs.nvidia.com/attestation/> / <https://github.com/NVIDIA/nvtrust>
- **Azure Confidential VMs & Custom UEFI Secure Boot:** <https://learn.microsoft.com/en-us/azure/confidential-computing/> / <https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-secure-boot-custom-uefi>
- **Google Cloud Confidential VM & Shielded Images:** <https://cloud.google.com/confidential-computing/confidential-vm/docs/about-cvm> / <https://cloud.google.com/compute/shielded-vm/docs/creating-shielded-images>
