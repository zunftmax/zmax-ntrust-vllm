# Unified Multi-Cloud Attestation (`maceip/unified-quote`) & Marketplace Architecture

This document specifies how the `ntrust` confidential GPU inference images align with [`maceip/unified-quote`](https://github.com/maceip/unified-quote) (`https://uq.secure.build/eat/v2`), [`maceip/attestation-service`](https://github.com/maceip/attestation-service), and [`maceip/tamayo`](https://github.com/maceip/tamayo) across **AMD SEV-SNP**, **Intel TDX**, and **NVIDIA Hopper/Blackwell (H100, H200, B100, B200) Confidential Compute GPUs** on **Azure**, **Google Cloud**, and **AWS**.

---

## 1. Why Align on `maceip/unified-quote` Instead of Cloud Vendor Silos

Cloud providers and silicon vendors each ship incompatible quote wrappers and centralized SaaS verifiers (Microsoft Azure Attestation `MAA`, Google Cloud Attestation, Intel Trust Authority `ITA`, NVIDIA `NRAS`). Relying on cloud-vendor SaaS tokens fragments the ecosystem and forces relying parties to trust the cloud operator's API rather than silicon roots.

By standardizing `ntrust` on [`maceip/unified-quote`](https://github.com/maceip/unified-quote) (`eat_profile: "https://uq.secure.build/eat/v2"`, `version: 2`):

1. **One Receipt Format Across All Three Clouds (GCP, Azure, AWS):**
   - **Intel TDX (GCP C3/A3, Azure DCesv5/ECesv5):** Collected via Linux `ConfigFS-TSM` (`/sys/kernel/config/tsm/report`) with `MRTD` (`0xB8..0xE8`) and `RTMR0..3` (`0x148..0x208`), verified directly against the pinned Intel SGX/TDX Root CA.
   - **AMD SEV-SNP on GCP & AWS (`ConfigFS-TSM` / `/dev/sev-guest` + vTPM/NitroTPM):** The 1184-byte `attestation_report` chains to the pinned AMD Milan/Genoa ARK/ASK (`VCEK`/`VLEK`), while vTPM/NitroTPM PCRs (`PCR 0..9` via `/sys/class/tpm/tpm0/pcr-sha256`) measure the guest kernel and command line.
   - **AMD SEV-SNP on Azure (`NCCads_H100_v5` / `DCas_v5` under vTOM paravisor):** Because Azure's paravisor runs at VMPL 0 and hides `/dev/sev-guest`, the guest reads the hardware-signed AMD `SNP_REPORT` from the **vTPM HCL report** (`NV index 0x01400001`, 32-byte `HCLA` header + 1184-byte `SNP_REPORT` + runtime JSON endorsing the vTPM AK `0x81000003`), chaining directly to AMD silicon without Microsoft Azure Attestation (`MAA`).
2. **One Signature, Silicon-Rooted (`report_data_64`):**
   - Lower 32 bytes (`report_data[0..32]`): `EatToken::binding_bytes_v2()` binding `version`, `eat_profile`, 48-byte `value_x`, `platform`, 32-byte `tls_spki_hash`, 48-byte `source_hash`, 48-byte `artifact_hash`, `iat`, and 32-byte `eat_nonce`.
   - Upper 32 bytes (`report_data[32..64]`): `EatToken::second_commitment()` with domain separator `"uq/eat/report-data-2\0"` binding `SHA-256(gpu_evidence_sha256 || tpm_pcr_composite_sha256)` and `value_x[0..32]`.
3. **Standard WebPKI HTTPS + Attested Channel Binding:**
   - NGINX terminates TLS 1.3 using an in-RAM Let's Encrypt certificate (`TLS-ALPN-01`) so standard OpenAI SDKs work unmodified, while `tls_spki_hash = SHA-256(leaf_SPKI_DER)` is bound directly into `report_data[0..32]` so `client/verify-attestation.py` (or `uq check`) cryptographically pins the TLS session to the hardware quote.

---

## 2. Getting the Disk Image into the Boot Measurement Across TDX & SEV-SNP

A raw CPU launch measurement (`SNP MEASUREMENT` or `TDX MRTD`) only hashes the initial OVMF firmware volume—not the kernel or the root disk. Furthermore, cloud VMs mutate `/etc/machine-id` and `/etc/ntrust/runtime.env` via `cloud-init` on first boot.

To ensure that **anyone who forks this repo, builds the image, and boots it on TDX or SEV-SNP gets the exact same measurement posted on GitHub**:

1. **Clamped Reproducible Kernel Build ([`kernel/build.sh`](../kernel/build.sh)):**
   - `KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00 UTC"`, `KBUILD_BUILD_USER=ntrust`, `KBUILD_BUILD_HOST=ntrust`, `KBUILD_BUILD_VERSION=1`, and `SOURCE_DATE_EPOCH=1760000000` are pinned so `vmlinuz-7.2.10-ntrust` does not embed builder hostnames or timestamps.
2. **Hardware Kernel & Bootloader Registers (`RTMR0..3` & `vTPM PCR 0..9`):**
   - `CONFIG_VIRT_DRIVERS=y`, `CONFIG_SEV_GUEST=y`, `CONFIG_TDX_GUEST_DRIVER=y`, `CONFIG_TCG_TPM=y`, `CONFIG_TCG_TIS=y`, and `CONFIG_TCG_CRB=y` are compiled into `7.2.10-ntrust`.
   - On **Intel TDX**, OVMF and GRUB measure `vmlinuz-7.2.10-ntrust` and the kernel command line into hardware `RTMR[1]` and `RTMR[2]`, which [`client/verify-attestation.py`](../client/verify-attestation.py) extracts directly from `TD Quote v4` (`0x148..0x208`).
   - On **AMD SEV-SNP**, OVMF and GRUB measure the boot chain into vTPM `PCR 0..9` (`/sys/class/tpm/tpm0/pcr-sha256/{0..9}`), whose composite digest is bound into `report_data[32..64]`.
3. **Deterministic 48-Byte SHA-384 Disk Image Tree Hash (`Value X`):**
   - During `make image` ([`image/install.sh`](../image/install.sh)), the guest computes `Value X` (`compute_value_x()` in [`guest/attest-server`](../guest/attest-server), matching `v2/src/value_x.rs` in `maceip/unified-quote`) over the sorted immutable system closure (`/boot/vmlinuz-7.2.10-ntrust`, `/boot/config-7.2.10-ntrust`, `/usr/local/lib/ntrust/*`, `/usr/local/bin/ntrust-status`, `/etc/systemd/system/ntrust-*.service`, `/etc/ntrust/nginx.conf.template`, `/etc/ntrust/model.json`, and `/usr/share/doc/ntrust/requirements.lock`) and exports it to `dist/value_x.sha384`.
   - At runtime, `guest/attest-server` recomputes `Value X` from the live disk and commits it into `report_data[0..32]` and `report_data[32..64]`. Any modification to the guest binaries, units, kernel, or Python lockfile changes `value_x_hex` and fails verification against `--expected-value-x`.

---

## 3. Privacy-Preserving Blind Tokens with `maceip/tamayo`

Once a client has verified the `ntrust` TEE via `GET /v1/attest` (`unified-quote` v2 receipt), [`maceip/tamayo`](https://github.com/maceip/tamayo) (post-quantum **One-More-MAYO / Pomfrit** blind signatures + FAEST / ML-DSA) provides the natural privacy layer on top of `ntrust`:

- The attested `ntrust` guest (or an attested `tamayo serve` instance bound by `unified-quote` `value_x`) acts as a **hardware-attested blind token issuer** (`/v1/blind-sign`).
- A user authenticates/pays once to obtain a blinded MAYO preimage (`Sign1 -> BlindSign -> Sign3`), and later redeems the unblinded burn token (`verify-burn`) on `/v1/chat/completions` over a fresh connection, proving authorization without linking the prompt session to the user's identity.

---

## 4. Cloud Marketplace & Image Publication Prerequisites

### 4.1 Microsoft Azure Marketplace & Azure Compute Gallery
1. **Image Format:** Fixed-size VHD (`dist/ntrust-azure.vhd`, 1 MiB aligned via `image/export.sh`), Generation 2 UEFI boot, `hv_vmbus`/`hv_storvsc`/`hv_netvsc`/`mlx5_core` + `CONFIG_TCG_TPM=y` built into `7.2.10-ntrust`.
2. **Gallery & Custom UEFI Secure Boot:** Create an Azure Compute Gallery image definition with `--hyper-v-generation V2` and `--security-type TrustedLaunchAndConfidentialVmSupported`, sign `vmlinuz-7.2.10-ntrust` with a project UEFI `db` key (`sbsign`), and enroll the public certificate in `securityProfile.uefiSettings`.

### 4.2 Google Cloud (GCP) Compute Engine & Cloud Marketplace
1. **Image Format:** GNU-format sparse `disk.raw` archive (`dist/ntrust-gcp.tar.gz`), UEFI boot, `gve` and `nvme` + `CONFIG_TDX_GUEST_DRIVER=y` / `CONFIG_SEV_GUEST=y` built into `7.2.10-ntrust`.
2. **Shielded/Confidential Image Import:** Import `dist/ntrust-gcp.tar.gz` with `--guest-os-features=UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE,GVNIC,SEV_SNP_CAPABLE,TDX_CAPABLE` and enroll the custom UEFI `db` key via `--signature-database-file`.
