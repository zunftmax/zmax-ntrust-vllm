# Remote Attestation (`GET /v1/attest` — IETF RATS over WebPKI TLS 1.3)

The guest serves an **IETF RATS (RFC 9334 / RFC 9711 EAT)** composite evidence endpoint at `GET /v1/attest?nonce=<64-hex>` while keeping standard Let's Encrypt **TLS-ALPN-01** certificates in guest RAM so unmodified OpenAI SDKs, browsers, and `curl` work without custom TLS libraries.

## How It Works

1. **In-Guest RATS Responder ([`guest/attest-server`](../guest/attest-server) & [`guest/systemd/ntrust-attest.service`](../guest/systemd/ntrust-attest.service)):**
   - Listens on `127.0.0.1:8082` behind the exact NGINX route `location = /v1/attest` in [`guest/nginx.conf.template`](../guest/nginx.conf.template).
   - Reads the active Let's Encrypt TLS 1.3 certificate served by NGINX and extracts its DER-encoded `SubjectPublicKeyInfo` (`leaf_spki_sha256`).
   - Reads the verified in-RAM NVIDIA GPU SPDM attestation report (`/run/ntrust-gpu/attestation.json` or `/run/ntrust-tee/attestation.json`) and computes `gpu_evidence_sha256`.
   - Computes the 64-byte hardware `REPORT_DATA`:
     $$\text{REPORT\_DATA} = \text{SHA-512}\big(\text{"ntrust-rats-v1:"} \parallel \text{nonce} \parallel \text{":"} \parallel \text{leaf\_spki\_sha256} \parallel \text{":"} \parallel \text{gpu\_evidence\_sha256} \parallel \text{":"} \parallel \text{manifest\_sha256}\big)$$
   - Requests a hardware-signed CPU TEE quote via Linux `ConfigFS-TSM` (`/sys/kernel/config/tsm/report`, enabled by `CONFIG_SEV_GUEST=y` and `CONFIG_TDX_GUEST_DRIVER=y` in [`kernel/required.config`](../kernel/required.config)).
   - Never labels an ordinary KVM VM (`CVM=none`) as confidential (`cpu_tee.confidential = false`, `quote_b64 = null`).

2. **Customer Verifier CLI ([`client/verify-attestation.py`](../client/verify-attestation.py)):**
   ```bash
   python3 client/verify-attestation.py https://inference.example.com
   ```
   - Opens a TLS 1.3 connection, extracts the peer certificate's `SubjectPublicKeyInfo` (`SPKI`) directly from the active socket, sends a fresh 32-byte random `nonce` to `GET /v1/attest?nonce=<nonce>`, and verifies:
     - `leaf_spki_sha256` matches the live TLS socket's certificate public key (defeating DNS/ACME relay and MITM attacks).
     - `nonce` matches the client's fresh challenge.
     - The binary AMD SEV-SNP (`attestation_report` offset `0x50..0x90`, `VMPL == 0`, `DEBUG == 0`) or Intel TDX (`TD Quote v4` offset `0x238..0x278`, `DEBUG == 0`) hardware quote contains the exact recomputed 64-byte `REPORT_DATA`.
     - `gpu_tee.verified` is `true` (unless `--no-gpu` is explicitly passed on CPU-only `dev` or `relay` paths).

See [ATTESTATION-RESEARCH.md](ATTESTATION-RESEARCH.md) for the protocol comparison of **IETF RATS vs. RA-TLS**, hardware quote layouts, and **Azure / GCP Marketplace** publication prerequisites.
