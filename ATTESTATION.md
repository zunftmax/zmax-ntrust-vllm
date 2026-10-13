# Rust attestation integration

The source adapters require the real `uq` composite collector and verifier. Image
builds now stop until an independently reviewed exact release record is supplied.
No compatible GPU release or hardware acceptance is asserted by these edits.
The responder is **not enabled automatically** in the image.

After hardware acceptance and approval of the exact upstream release, provide a
private build-host JSON file with exactly these four string fields:

- `release_tag`: the reviewed version tag.
- `source_sha`: its approved 40-character source commit.
- `binary_sha256`: the independently approved 64-character binary digest.
- `target`: `x86_64-unknown-linux-gnu`.

There are deliberately no default/example pin values. On the configured Linux
host (`axp.computer`), set `NTRUST_UQ_RELEASE_CONFIG` to that absolute file path
before `make image`. `image/fetch-uq.sh` verifies the digest and GitHub SLSA
provenance against the exact source commit, repository and release workflow.
It stages the binary and its record in `build/uq`; the image installer checks
both again and measures/inventories the installed binary and record. The copied
`image/fetch-verified-uq.sh` originates in
`zmax-universal-attestations/v2/deploy/fetch-verified-uq.sh`.

Value X measures an explicit required application-file manifest; absent, linked,
nonregular or concurrently changed files fail measurement. It does not claim a
full disk measurement or substitute for signed measured boot.

The guest adapter observes the live loopback TLS leaf key, invokes `uq collect`
with each customer's fresh nonce, and returns the Rust receipt unchanged in
meaning. It never interprets stored `nvattest` JSON as remote attestation proof.
Inference variants explicitly collect GPUs; the relay variant explicitly
collects CPU-only evidence and makes no claim about its remote origin hardware.
The unit permits only the named attestation device classes and configfs report
path, retains filesystem/syscall hardening, and permits network access for Rust's
fixed collateral endpoints. Linux service/device permissions and quote access
still need to be exercised on the intended hardware before enabling the service.

The customer runs `client/verify-attestation.py` with an installed, independently
trusted `uq`, mandatory `--expected-value-x` and `--expected-measurement`, and
exactly one of `--gpu-policy` or `--cpu-only`. GPU policy is the Rust verifier's
enrolled inventory JSON. A CPU-only verdict authenticates the relay itself.
Use `--platform tdx` or `--platform sev-snp` with independently supplied
`--cpu-collateral` JSON for certificate, TCB, QE and revocation appraisal, plus
`--cpu-tcb-policy` JSON for independently approved rollback floors. If the
platform is left unspecified, the Rust verifier still rejects missing required
collateral; no transport option bypasses that check.
Explicit CPU/TPM formats use `--platform azure-snp-vtpm --azure-policy <local.json>`
or `--platform aws-snp-nitrotpm --nitrotpm-policy <local.json>`, both with the
independent AMD `--cpu-collateral` and `--cpu-tcb-policy` files. Azure policy pins
the approved AK, VM identity, paravisor and guest PCRs; NitroTPM policy pins the
PCR bank/values and freshness bounds. A profile policy on a different platform,
a missing policy, or a generic CPU verdict without the selected profile's
appraisal is rejected. Files stay local to the verifier and are never learned
from the received evidence. The standalone CLI, installed SDK CLI and Python
verifier expose these same `azure_policy`/`nitrotpm_policy` options.

Guest collection defaults to `NTRUST_CPU_PROFILE=direct`. Explicit Azure collection
requires `NTRUST_CPU_PROFILE=azure-snp-vtpm` and `NTRUST_TPM_PCRS` containing a
sorted, unique CSV selection within PCR0..15. The selected indices must match the
independently enrolled verifier policy. `NTRUST_CPU_PROFILE=aws-snp-nitrotpm`
selects that exact compound collector. These profile settings do not auto-detect
or fall back to another provider, authorize admission, or expand deployment
targets. AWS remains outside the confidential GPU deployment target list.
For either compound profile, optional `NTRUST_TPM_BOOT_LOG` selects a local TCG2
log for Rust collection. `NTRUST_TDX_BOOT_LOG`/`NTRUST_TDX_RUNTIME_LOG` apply only
to the direct TDX profile; incompatible log/profile settings are rejected.
Source support does not enable the responder or change release/hardware gates.

Optional `--boot-policy` appraises the collected TDX event log configured through
`NTRUST_TDX_BOOT_LOG`; no unsigned PCR or disk hash is presented as measured boot.
For an independently approved UKI policy, also supply `--uki /local/image.efi`.
The local image must be nonempty and at most 512 MiB; `--uki` requires
`--boot-policy`. Its path is passed only to the local Rust verifier for section
measurement appraisal against that policy and the authenticated boot registers.
The client never uploads the image or accepts an image supplied by the server.
For explicit Google measured-boot replay, supply
`--google-boot-verifier /absolute/path/uq-google-attestation` together with
`--boot-policy`. The helper must already be independently trusted, nonempty,
regular and executable. This option does not enable a Google CPU verifier.
`--prior-stage-policy /local/prior-stage.json` forwards an independent, nonempty
JSON policy of at most 1 MiB to Rust's prior-stage verifier. Helper, policy and
UKI paths are passed only to the local verifier, never in HTTP requests.

The guest may additionally configure `NTRUST_TDX_RUNTIME_LOG` to an absolute
local CoCo AAEL file, alongside `NTRUST_TDX_BOOT_LOG`. The adapter forwards them
as `--runtime-log` and `--boot-log`; Rust bounds/parses the logs and combines the
runtime extensions before requesting the CPU-signed commitment. A runtime log
without a boot log is rejected. Collection itself is not an acceptance verdict.

The standalone script and installed SDK now share
`client/ntrust/_attestation_transport.py`. Ship/install the `ntrust` package
alongside the script; copying only the script is insufficient. Every SDK
verification requires the real Rust executable and independent image/inventory
policy. The former structural-receipt path that could return `valid: true`
without Rust verification has been removed; receipt fields cannot authorize
inference. The SDK exposes the same optional boot, UKI, helper, prior-stage and
CPU collateral/policy parameters.
TLS validation, the observed SPKI, nonce and receipt all use the same connection.
Any missing binary, collection failure, stale/missing collateral, invalid Rust
verdict or policy failure is an error; no Python appraisal path exists.

Prepared source is not deployment or hardware validation. Activation, image
builds, release-pin approval and end-to-end acceptance remain deliberately pending.


## Optional companion packaging proposal

The Google boot helper remains an explicitly selected local verifier dependency.
The current image installer still accepts only the reviewed four-field `uq`
release record above; it does not download, install or select a companion.

When the canonical release workflow publishes a reviewed companion artifact,
extend the packaging contract with a separate, optional companion record that
pins its exact release tag, canonical source commit, platform/architecture and
SHA-256. Verify the artifact's own SLSA provenance and digest before staging it;
install the binary and record together and inventory both. The parent release
workflow must supply real pins and attestations. No placeholder pin or implicit
"latest" selection is acceptable. For client-side boot verification this is a
verifier-host installation, not a reason to add the helper to a guest image.
Guest installation would require a separately selected guest use case and must
also add both files to Value X's required inventory.

Existing image acceptance and service-activation gates remain unchanged. No
companion backend becomes active merely because a binary is installed; the
caller must explicitly supply its absolute path with the applicable policy.
