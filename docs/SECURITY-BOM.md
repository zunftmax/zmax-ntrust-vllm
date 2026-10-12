# Component selection and security bill of materials

This records the selected vLLM build inputs and their purpose. Expected risk below describes exposure and trust, not a computed probability or a promise of safety. [requirements.lock](../image/requirements.lock) pins 200 Python distributions and accepted SHA-256 hashes for Linux Python 3.12. The image inventory records exact installed OS versions and native-file hashes; source requirements alone are not an installed-image SBOM.

The [2026-10-12 installed-image SBOM and evidence](../sbom/2026-10-12/README.md) records 322 Debian packages and 200 Python distributions. Its native-file inventory separately counts 42,704 bundled GPU kernels and 503 other ELF files; these files overlap package contents. Both project and Syft CycloneDX documents passed schema validation. Raw vulnerability results and the initial triage remain published as the historical HWE baseline.

| Item | Selected version / source | Why retained | Expected risk and control |
| --- | --- | --- | --- |
| Ubuntu minimal | 24.04, base 20261008, SHA in Packer | One maintained guest for Azure/GCP; cloud-init handles both | Kernel/OS privileged TCB; apply updates during build, inventory exact result |
| Kernel / NVIDIA modules | Linux 7.2.10 + NVIDIA open 580.178.04 | [Feature allowlist](../kernel/README.md), built-in cloud drivers, compute/UVM only; no guest DKMS | Privileged native code; custom Secure Boot trust and confidential GPU/cloud compatibility still require validation |
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

No container runtime, Kubernetes, cloud extension agent, telemetry daemon, general execution API, model router, remote backend, custom GPU crypto, custom scheduler or second inference engine is added. Ubuntu Pro, unattended background update timers, crash reporting, pollinate, LXD, snapd, old GA kernels and unrelated suspend/pstore services are removed or disabled. The new kernel compiles out unrelated subsystem families and boots directly from built-in storage drivers, removing the initramfs helper stack. Required cloud drivers are built in; only required crypto and NVIDIA compute modules remain. The historical SBOM above describes the previous HWE artifact, not this replacement.

Upstream dependency removal is constrained by engine imports and native ABI requirements. The declared dependency closure stays intact; dropping required packages with `--no-deps` can break upstream imports or native ABI dependencies. In particular, OpenTelemetry libraries may remain as declared upstream dependencies even though collection/export is disabled. CUDA/compiler and PyTorch libraries dominate size. CUDA 12/13 support libraries pulled by upstream packaging are retained until the actual GPU execution path establishes which can safely be removed.

All engine installs use `--only-binary=:all:` and `--require-hashes`. The wheel closure is resolved from PyPI plus the matching official FlashInfer release wheel; accepted distribution hashes are checked during installation.

## Material provenance

The built image retains upstream `.dist-info` metadata and license files. `make sbom` mounts the exported image read-only and writes `inventory.json` and CycloneDX `sbom.cdx.json` under `sbom/YYYY-MM-DD/`, separating Debian packages, Python distributions and overlapping native ELF files. The file hash inventory covers the inference venv, NGINX, its ACME module and nvattest; other distribution libraries remain identified by their Debian packages. `dist/SHA256SUMS` identifies exported disks. Ubuntu apt repositories are updated during each build; reproducible OS snapshots and signed release provenance are deferred.

Official references: [vLLM source](https://github.com/vllm-project/vllm/tree/v0.31.0), [NVIDIA CUDA compatibility](https://docs.nvidia.com/deploy/cuda-compatibility/), [NGINX ACME module](https://nginx.org/en/docs/http/ngx_http_acme_module.html), [provider deployment sources](../image/clouds.md#sources).

For a dated vulnerability scan, set `NTRUST_SCAN_TOOLS` to a directory containing verified Syft and Trivy binaries, set `NTRUST_TRIVY_CACHE` to a cache outside the guest, then run `make scan`. This records a maintained-tool SBOM, vulnerability JSON and vulnerability database timestamp alongside the image hashes. Scanners are not installed in the runtime guest.

FlashInfer's matching `flashinfer-cubin` wheel is pinned from its official release to provide kernel files before the inference network is restricted. Each archive is about 1.57 GB compressed and contains multiple GPU architectures. This adds size, but avoids relying on first-request kernel downloads. Architecture-specific pruning is deferred until H100 execution identifies the required subset. JIT source compilation still uses the installed toolkit and RAM cache; the prebuilt JIT-cache bundles are not added. See [FlashInfer installation options](https://docs.flashinfer.ai/installation.html).
