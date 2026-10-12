# Security boundaries and current evidence

The project is a core guest implementation awaiting a supported confidential H100 test. Treat source checks, ordinary boot tests, cloud import, real GPU inference and customer verification as separate evidence levels.

Implemented controls: strict local GPU admission; no swap/core/suspend/pstore; signed distribution NVIDIA kernel modules; local-only inference networking; RAM-backed credentials and working caches; TLS termination in the guest; exact public HTTP routes; bounded ingress; payload logging disabled; volatile journal; no cloud extension or telemetry daemon; fresh ACME/TLS state after full HTTPS restart.

Administrative SSH is retained for initial operator setup and per-boot credential retrieval. The operator and that channel remain trusted. Removing the Azure provisioning daemon does not eliminate cloud-init: cloud-init is needed for networking and public first-boot configuration. Its optional telemetry reporter is disabled.

The inference engines and PyTorch bring a large native/Python dependency closure. Some packages support telemetry, model downloading, distributed execution or additional API features. Installed dependency presence is not proof that those features run. We disable usage reporting, set offline model mode, keep workers on loopback and expose only two NGINX routes. Do not enable remote model code or arbitrary engine flags through untrusted input.

CUDA JIT needs compiler components and executable RAM-backed cache files. Therefore a general C/C++ compiler and Python headers remain in the guest. No project-owned concurrency implementation is added; engine scheduling, multiprocessing, queues, locks and GPU kernels are maintained upstream. This does not prove the absence of upstream concurrency defects. Native driver/JIT dependencies remain a significant trust boundary.

The ordinary KVM test must fail GPU admission with no API key or inference listener. It cannot establish confidential hardware compatibility, ACME issuance, model correctness, prompt isolation, cancellation or throughput. Complete those tests on the exact cloud SKU and image before use with sensitive data. Azure/GCP custom import, kernel/driver behavior and external traffic tests are still pending.

CT observes new certificate issuance; it neither seals this disk nor prevents a provider from presenting a modified guest. Customer attestation of the image and TLS identity is explicitly deferred in REMOTE-ATTESTATION.md. The provider can observe connection metadata and deny service.

No vulnerability scan or package count from the earlier engine is evidence for these new images. Every built image needs its own inventory and scan. Build outputs include the installed Debian/Python versions and native-file hashes; vulnerability results must be dated and tied to the corresponding disk hash.

## Script and service decisions

| File or service | Review and retained purpose |
| --- | --- |
| `guest/gpu-ready` | SNP/TDX, no swap, one CC-On GPU, bounded native verification, ready-state check, then a RAM-only API credential; no custom cryptography |
| `ntrust-gpu.service` | Privileged setup only; depends on NVIDIA persistence and a bounded clock wait; evidence stays in its private RAM directory |
| `guest/inference-start` | Fixed upstream command, local Safetensors model and strict per-boot credential format; credential stays out of process arguments |
| `ntrust-inference.service` | Dedicated user, credential delivery, read-only system, RAM working/cache directories, no capabilities, bounded resources and loopback-only network access |
| `guest/inference-ready` | Bounded local `/health` check without recording response bodies; upstream exempts this probe from API-key authentication, and HTTPS waits for readiness |
| `guest/https-start` | Validates public hostname/email, permits only the two Let's Encrypt directories and substitutes only named NGINX variables |
| `ntrust-https.service` | Separate user, bind-port capability only, private devices and RAM ACME state; full restart intentionally re-keys |
| `guest/nginx.conf.template` | Two exact method/path pairs, TLS 1.3, bounded admission, streaming, no response cache or payload logging |
| `guest/fetch-model` / `model.json` | Bootstrap only: pinned public revision, size/hash checks on every file and atomic directory promotion; no runtime model downloading |
| `guest/cloud-init.example.yaml` / `runtime.env.example` | Public deployment inputs only; no private credentials or model tokens |
| `guest/status` | Fixed service states and a discarded health response; no generic command or log-reader endpoint |
| `guest/blocked-modules.conf` | Unneeded subsystems blocked while cloud storage/network, NVIDIA and required crypto drivers remain; root can bypass policy |
| `image/install.sh` | Signed distribution modules, hashed binary wheel closure, background-package pruning and installed configuration checks; compiler retained for upstream JIT |
| `image/check-installed.sh` | Package/module checks, dynamic linkage, native NGINX/ACME configuration, CUDA toolkit and installed engine metadata |
| `image/check-engine.py` | Build/test only: compile small CUDA/Python-header probes and validate upstream argument parsing; vLLM's device type is mocked for this CPU-only syntax test |
| `image/finalize.sh` | Removes builder authorizations, host identities, cloud seed/state, saved random seed and logs; scoped cleanup, not forensic disk sealing |
| `image/ntrust.pkr.hcl` / `build-cloud-init.yaml` | Existing Packer/QEMU/UEFI workflow and temporary builder key; build on Linux |
| `image/export.sh` | Stage exports, compare logical QCOW/raw/VHD/archive bytes, then publish a checksum manifest |
| `image/inventory.py` / `inventory.sh` | Read-only artifact inventory of package versions, licenses/dependencies and scoped ELF hashes; no runtime scanner |
| `image/scan.sh` | Maintained Syft/Trivy scan on read-only root/boot/EFI; retain dated results without suppression |
| `Makefile` | Standard source-check, image, export, inventory and scan entry points |
| `tests/test_guest.py` | Synthetic device/admission fixtures, bounded failure/retry, API-key lifecycle and NGINX configuration-injection rejection |
| `tests/test_launcher.py` | Credential privacy at the exec boundary and rejection of malformed credentials |
| `tests/test_lock.py` | Reject missing hashes and a direct wheel URL whose pinned checksum disagrees with the lock |
| `tests/smoke-guest.sh` | Disposable ordinary UEFI VM: verify bootstrap, package/module policy, failed GPU admission, no listener/key, actual loopback-only IP policy, running-service inventory and installed parser/compiler checks |
| `tests/inspect-image.sh` | Read-only, size-bounded scan for residual identities/private-key headers plus installed-package extraction |
| `.github/workflows/check.yml` | Source checks with a pinned checkout action and read-only token; no image build or cloud deployment |

Retained OS services cover systemd/udev, volatile journal, networking/DNS/time, cloud-init bootstrap, AppArmor, restricted operator SSH and filesystem/boot maintenance. NVIDIA persistence remains part of the documented GPU setup. Unit entries include static and masked definitions; they are not all running background daemons. Exact unit states belong to each built-image inventory.
