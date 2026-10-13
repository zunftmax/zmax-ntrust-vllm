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
Optional `--boot-policy` appraises the collected TDX event log configured through
`NTRUST_TDX_BOOT_LOG`; no unsigned PCR or disk hash is presented as measured boot.
For an independently approved UKI policy, also supply `--uki /local/image.efi`.
The local image must be nonempty and at most 512 MiB; `--uki` requires
`--boot-policy`. Its path is passed only to the local Rust verifier for section
measurement appraisal against that policy and the authenticated boot registers.
The client never uploads the image or accepts an image supplied by the server.
TLS validation, the observed SPKI, nonce and receipt all use the same connection.
Any missing binary, collection failure, stale/missing collateral, invalid Rust
verdict or policy failure is an error; no Python appraisal path exists.

Prepared source is not deployment or hardware validation. Activation, image
builds, release-pin approval and end-to-end acceptance remain deliberately pending.
