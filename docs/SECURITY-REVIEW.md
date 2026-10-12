# Security boundaries and current evidence

The project is a core guest implementation awaiting a supported confidential H100 test. Treat source checks, ordinary boot tests, cloud import, real GPU inference and customer verification as separate evidence levels.

Implemented controls: strict local GPU admission; no swap/core/suspend/pstore; signed distribution NVIDIA kernel modules; local-only inference networking; RAM-backed credentials and working caches; TLS termination in the guest; exact public HTTP routes; bounded ingress; payload logging disabled; volatile journal; no cloud extension or telemetry daemon; fresh ACME/TLS state after full HTTPS restart.

Administrative SSH is retained for initial operator setup and per-boot credential retrieval. The operator and that channel remain trusted. Removing the Azure provisioning daemon does not eliminate cloud-init: cloud-init is needed for networking and public first-boot configuration. Its optional telemetry reporter is disabled.

The inference engines and PyTorch bring a large native/Python dependency closure. Some packages support telemetry, model downloading, distributed execution or additional API features. Installed dependency presence is not proof that those features run. We disable usage reporting, set offline model mode, keep workers on loopback and expose only two NGINX routes. Do not enable remote model code or arbitrary engine flags through untrusted input.

CUDA JIT needs compiler components and executable RAM-backed cache files. Therefore a general C/C++ compiler and Python headers remain in the guest. No project-owned concurrency implementation is added; engine scheduling, multiprocessing, queues, locks and GPU kernels are maintained upstream. This does not prove the absence of upstream concurrency defects. Native driver/JIT dependencies remain a significant trust boundary.

The ordinary KVM test must fail GPU admission with no API key or inference listener. It cannot establish confidential hardware compatibility, ACME issuance, model correctness, prompt isolation, cancellation or throughput. Complete those tests on the exact cloud SKU and image before use with sensitive data. Azure/GCP custom import, kernel/driver behavior and external traffic tests are still pending.

CT observes new certificate issuance; it neither seals this disk nor prevents a provider from presenting a modified guest. Customer attestation of the image and TLS identity is explicitly deferred in REMOTE-ATTESTATION.md. The provider can observe connection metadata and deny service.

No vulnerability scan or package count from the earlier engine is evidence for these new images. Every built image needs its own inventory and scan. Build outputs include the installed Debian/Python versions and native-file hashes; vulnerability results must be dated and tied to the corresponding disk hash.
