# Remote Attestation (`GET /v1/attest` — `unified-quote` `https://uq.secure.build/eat/v2`)

The guest serves a [`maceip/unified-quote`](https://github.com/maceip/unified-quote)-compatible EAT (`eat_profile: "https://uq.secure.build/eat/v2"`, `version: 2`) attestation endpoint at `GET /v1/attest?nonce=<64-hex>` while keeping Let's Encrypt **TLS-ALPN-01** certificates in guest RAM so unmodified OpenAI SDKs, browsers, and `curl` work out of the box.

## How the Disk Image, Kernel, GPU, and TLS Key Are Bound

1. **Deterministic Disk Image Tree Measurement (`Value X` — 48-byte SHA-384):**
   - Both at image build time (`/usr/share/doc/ntrust/value_x.sha384` exported to `dist/value_x.sha384`) and at runtime in [`guest/attest-server`](../guest/attest-server), `compute_value_x()` computes the deterministic 48-byte `SHA-384` tree hash (`relative_path:` + raw 48B `SHA-384` + `\n`, matching `v2/src/value_x.rs` in `maceip/unified-quote`) over the guest's kernel (`vmlinuz-7.2.10-ntrust`, `config-7.2.10-ntrust`), admission scripts, systemd units, NGINX template, `model.json`, and Python wheel hash lockfile (`requirements.lock`).
   - Because [`kernel/build.sh`](../kernel/build.sh) clamps `SOURCE_DATE_EPOCH`, `KBUILD_BUILD_TIMESTAMP`, `KBUILD_BUILD_USER`, `KBUILD_BUILD_HOST`, and `KBUILD_BUILD_VERSION`, any user who forks the repo and builds the image gets the exact same `value_x_hex` (`artifact_hash_hex`) regardless of per-instance `cloud-init` settings (`/etc/machine-id` or `/etc/ntrust/runtime.env`).

2. **Boot-Time Kernel & Disk Measurement on Intel TDX and AMD SEV-SNP:**
   - **Intel TDX:** The hardware quote (`TD Quote v4` via `/sys/kernel/config/tsm/report`) carries `MRTD` (`0xB8..0xE8`, OVMF firmware) and all four Runtime Measurement Registers `RTMR0..3` (`0x148..0x208`, covering UEFI state, GRUB, `vmlinuz-7.2.10-ntrust`, and kernel cmdline).
   - **AMD SEV-SNP (GCP, Azure HCL vTPM, AWS NitroTPM):** With `CONFIG_TCG_TPM=y`, `CONFIG_TCG_TIS=y`, and `CONFIG_TCG_CRB=y` built into `7.2.10-ntrust`, the guest reads `/sys/class/tpm/tpm0/pcr-sha256/{0..9}` (covering UEFI, GRUB, `vmlinuz-7.2.10-ntrust`, and kernel cmdline) and supports Azure's HCL vTPM report (`0x01400001`).

3. **Canonical `unified-quote` 64-Byte Hardware `REPORT_DATA` Layout:**
   - **`report_data[0..32]` (`EatToken::binding_bytes_v2`):**
     $$\text{SHA-256}\big(\text{version} \parallel \text{len(profile)} \parallel \text{profile} \parallel \text{value\_x}_{48} \parallel \text{platform}_{1} \parallel \text{tls\_spki\_sha256}_{32} \parallel \text{source\_hash}_{48} \parallel \text{artifact\_hash}_{48} \parallel \text{iat}_{8} \parallel \text{eat\_nonce}_{32} \parallel 0^{32}\big)$$
   - **`report_data[32..64]` (`EatToken::second_commitment`):**
     $$\text{SHA-256}\big(\text{"uq/eat/report-data-2\textbackslash 0"} \parallel \text{SHA-256}(\text{gpu\_evidence\_sha256} \parallel \text{tpm\_pcr\_composite\_sha256}) \parallel \text{value\_x}[0..32]\big)$$

4. **Customer Verifier CLI ([`client/verify-attestation.py`](../client/verify-attestation.py)):**
   ```bash
   python3 client/verify-attestation.py https://inference.example.com \
     --expected-value-x "$(cat dist/value_x.sha384)"
   ```

See [ATTESTATION-RESEARCH.md](ATTESTATION-RESEARCH.md) for the full multi-cloud (`unified-quote` + `tamayo`) architecture and **Azure / GCP Marketplace** publication steps.
