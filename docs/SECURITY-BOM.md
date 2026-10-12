# Component selection and security bill of materials

This records the selected vLLM build inputs and their purpose. Expected risk below describes exposure and trust, not a computed probability or a promise of safety. [requirements.lock](../image/requirements.lock) pins 199 Python distributions and accepted SHA-256 hashes for Linux Python 3.12. The image inventory records exact installed OS versions and native-file hashes; source requirements alone are not an installed-image SBOM.

| Item | Selected version / source | Why retained | Expected risk and control |
| --- | --- | --- | --- |
| Ubuntu minimal | 24.04, base 20261008, SHA in Packer | One maintained guest for Azure/GCP; cloud-init handles both | Kernel/OS privileged TCB; apply updates during build, inventory exact result |
| Kernel / NVIDIA modules | Ubuntu HWE + signed 580-server-open family | Avoid DKMS and a custom kernel build; Hyper-V/GVE/NVMe support | Privileged native code; actual cloud CC compatibility still requires hardware proof |
| NVIDIA nvattest / libnvat | 2.0.0.1790976895-1, pinned `.deb` hashes | Upstream local GPU evidence verification before enabling use | Verification and vendor collateral are trusted; failure blocks startup |
| NGINX | 1.30.5-1~noble, SHA verified | Maintained HTTPS, exact routing, rate limits and streaming | Internet-facing parser; only TLS 1.3 and two API routes exposed |
| NGINX ACME | 1.30.5+0.4.1-1~noble, SHA verified | Native TLS-ALPN-01 and memory-only certificate state | CA/module/parser trust; full restart intentionally reissues |
| vLLM | 0.31.0, hash-locked wheel | User-selected upstream GPU serving ecosystem | Native/Python parsing, scheduler and kernels; no remote code, local model only |
| PyTorch / Triton | 2.13.0 / 3.7.1 | Required upstream tensor runtime/JIT | Large native closure; RAM JIT/cache paths and process confinement |
| CUDA toolkit | 13.0.3 runtime/compiler selection; exact component versions in lock | CUDA GPU execution and offline JIT compilation | Individual dependency minimums resolve some newer CUDA 13 components; H100/driver execution must be tested |
| FlashInfer | 0.7.0.post1 | Required upstream attention/kernel dependency | Native/JIT code; no runtime network, RAM cache |
| Python | Ubuntu 3.12 | Upstream engine runtime and cloud-init | Package attack surface; isolated venv and hashed binary wheels |
| C/C++ compiler, Python headers, Ninja | Ubuntu packages recorded per build | Required for upstream runtime JIT; removing them can break model execution | Expands tooling surface; inference has no general execution endpoint, strict filesystem and network policy |
| systemd/resolved/timesyncd | Ubuntu packages recorded per build | Service ordering, cgroups, DNS and verification clock | Privileged OS components; bounded startup and resource policies |
| cloud-init / OpenSSH | Ubuntu packages recorded per build | Cloud bootstrap and trusted operator access | Public metadata is not secret; restricted SSH ingress, no root/password login |
| Public Qwen model | Qwen2.5-0.5B-Instruct, revision 7ae557604adf67be50417f59c2c2f167def9a775 | Small standard Safetensors bring-up model | Provisioned separately; per-file hashes, no remote Python model code |
| uv | 0.13.0, wheel SHA verified | Install the complete hashed dependency closure | Build-only; removed from finished image |
| Packer / QEMU | 1.16.1 / 8.2.2; QEMU plugin 1.1.7 | Existing maintained image builder | Build-host supply chain; no new VM builder framework |

## Reduction decisions

No container runtime, Kubernetes, cloud extension agent, telemetry daemon, general execution API, model router, remote backend, custom GPU crypto, custom scheduler or second inference engine is added. Ubuntu Pro, unattended background update timers, crash reporting, pollinate, LXD, snapd, old GA kernels and unrelated suspend/pstore services are removed or disabled. Optional kernel subsystems are blocked while required cloud/GPU modules remain.

Upstream dependency removal is constrained by engine imports and native ABI requirements. We do not use `--no-deps` to make an impressive package count while shipping an incomplete engine. In particular, OpenTelemetry libraries may remain as declared upstream dependencies even though collection/export is disabled. CUDA/compiler and PyTorch libraries dominate size. CUDA 12/13 support libraries pulled by upstream packaging are retained until the actual GPU execution path establishes which can safely be removed.

All engine installs use `--only-binary=:all:` and `--require-hashes`. The complete wheel closure is resolved from PyPI; accepted distribution hashes are checked during installation.

## Material provenance

The built image retains upstream `.dist-info` metadata and license files. `make sbom` mounts the exported image read-only and writes `inventory.json` and CycloneDX `sbom.cdx.json` under `sbom/YYYY-MM-DD/`, separating Debian packages, Python distributions and overlapping native files. `dist/SHA256SUMS` identifies exported disks. Ubuntu apt repositories are updated during each build; reproducible OS snapshots and signed release provenance are deferred.

Official references: [vLLM source](https://github.com/vllm-project/vllm/tree/v0.31.0), [NVIDIA CUDA compatibility](https://docs.nvidia.com/deploy/cuda-compatibility/), [NGINX ACME module](https://nginx.org/en/docs/http/ngx_http_acme_module.html), [provider deployment sources](../image/clouds.md#sources).
