# Zmax ntrust · vLLM

A focused VM image for serving vLLM through HTTPS inside a confidential NVIDIA GPU VM. One guest, two disk formats: Azure fixed VHD and GCP raw-disk archive. This repository packages **vLLM 0.31.0**, without another inference engine or remote inference fallback.

**Status:** experimental core image. Linux builds, Azure/GCP export comparisons, ordinary-VM rejection and network-policy checks, and installed parser/compiler checks passed. Per-image inventories and vulnerability scans are in progress. Cloud import, confidential H100 execution and public ACME issuance have not been validated. Customer verification of the image and TLS identity is deferred. Do not interpret a successful local build as a confidential-computing proof.

The sibling project is [zmax-ntrust-sglang](https://github.com/ZUNFTMAX/zmax-ntrust-sglang).

## What runs

```text
Client ── TLS 1.3 / JSON or SSE ── cloud TCP forwarding ── guest NGINX :443
                                                           │ loopback
                                                      vLLM :8080
                                                           │
                                                    NVIDIA driver / H100
```

NGINX obtains its certificate directly from Let's Encrypt with TLS-ALPN-01. Only `GET /v1/models` and `POST /v1/chat/completions` are public. Responses return over the client's existing HTTPS connection; streaming uses SSE. Keep any load balancer at layer 4 so TLS terminates in the guest.

The guest requires SEV-SNP or TDX, exactly one NVIDIA GPU in production CC-On mode, successful local NVIDIA verification, no swap, and a ready inference backend before serving. NVIDIA supplies GPU attestation, SPDM and link encryption. The project adds no thread pool, spinlock or GPU encryption implementation.

## Privacy and key lifecycle

- TLS/ACME state, the API credential, request working files and JIT caches stay in RAM. Swap, core dumps, suspend, hibernation and pstore are disabled.
- A full HTTPS restart deliberately creates a new TLS key and certificate. Reload retains the running ACME state. Reboot creates a new API credential. Use ACME staging while testing repeated restarts.
- The inference process can connect only to loopback. No prompt/response logging, remote inference fallback or telemetry service is configured. Upstream logging outputs are discarded; usage tracking and OpenTelemetry are disabled.
- The root disk contains software and a separately provisioned public model. It is not an encrypted secret store. Cloud metadata contains only public bootstrap configuration.

These controls do not yet let a customer authenticate the running image. Certificate Transparency records issuance, not image approval. The cloud still observes traffic metadata, allocation and availability. See [security boundaries](docs/SECURITY-REVIEW.md) and the [remote verification next phase](docs/REMOTE-ATTESTATION.md).

## Build on Linux

Use an x86-64 Linux host with KVM, Packer 1.16.1, QEMU 8.2.2 or compatible tools, OVMF 4M, xorriso, Python 3, gettext and ShellCheck. Image builds for this project run on `axp.computer` over SSH. Do not emulate the image on macOS.

Allow a 64 GiB virtual root disk, ample build cache/export space and 4 GiB builder RAM. Fixed VHD export is 64 GiB plus its footer; sparse files still require an upload plan.

```sh
make check
make image
make export
bash tests/smoke-guest.sh
bash tests/inspect-image.sh
make sbom
sha256sum --check dist/SHA256SUMS
```

Outputs are `dist/qemu/ntrust.qcow2`, `dist/ntrust-azure.vhd`, `dist/ntrust-gcp.tar.gz` and `dist/SHA256SUMS`. Build/SSH keys and disk files are ignored by Git. Each repository builds only its own engine. The ordinary KVM smoke test must reject inference; it cannot exercise H100 inference.

The [hashed Python dependency lock](image/requirements.lock) contains 200 distributions. Base package versions are recorded from each build. Ubuntu packages are not snapshot-pinned, so reproducible releases are not claimed. [Component selection and risks](docs/SECURITY-BOM.md) explain what stays and why.

## Deploy

Follow the separate [Azure and GCP launch recipes](image/clouds.md). Obtain a supported confidential H100 quota/capacity allocation, a DNS hostname, an operator SSH public key and TCP 443 pass-through. Copy `guest/cloud-init.example.yaml`, replace the public placeholders and use the staging CA first.

The example provisions Qwen2.5-0.5B-Instruct from an exact revision, verifies every file against [the model manifest](guest/model.json), and installs it as `/var/lib/ntrust/model`. It is a small bring-up model. For another model, provision a local Safetensors model directory with trusted tokenizer/configuration files; remote model code is not enabled. Keep private model provisioning out of public cloud metadata.

The shipped profile uses one GPU, four concurrent engine requests, an 8,192-token context ceiling and an 85% GPU memory budget. NGINX limits global concurrency to four and per-client-IP concurrency to two. Model-specific tuning requires an actual GPU test; this is not a throughput benchmark.

## Run

After hardware verification, staged ACME issuance and synthetic inference pass, switch to production ACME as described in the deployment guide. Retrieve `/run/ntrust-gpu/api-key` using your trusted operator SSH channel and place it in your client's secret storage. Do not send it through cloud metadata or application logs.

```sh
# NTRUST_API_KEY is the per-boot credential; DOMAIN is your provisioned hostname.
curl --fail --no-buffer "https://$DOMAIN/v1/chat/completions" \
  -H "Authorization: Bearer $NTRUST_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"model","messages":[{"role":"user","content":"Reply with hello."}],"max_tokens":16,"stream":true}'
```

Use `sudo ntrust-status` for payload-free local diagnostics. Full HTTPS restarts reissue certificates; use staging during diagnosis to avoid production issuance limits.

## Project contents

| Path | Purpose |
| --- | --- |
| `guest/` | Small startup helpers, upstream server configuration and service isolation |
| `image/` | Packer recipe, hashed dependencies, disk export and provider launch instructions |
| `tests/` | Admission/credential tests, ordinary UEFI boot rejection and artifact inspection |
| `docs/SECURITY-BOM.md` | Versions, selection rationale, expected risk and reduction decisions |
| `docs/REMOTE-ATTESTATION.md` | Reserved follow-on scope for customer verification and sealing |

Project code uses the MIT license. Upstream Python wheels, NVIDIA components, NGINX and Ubuntu retain their own licenses. Installed license files and package metadata are retained in the image; the public demonstration model includes its own license.
