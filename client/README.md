# Ntrust Python SDK

The official Python client SDK for Ntrust Confidential AI Inference Virtual Machines.

Supports OpenAI-compatible API endpoints with hardware attestation verification, zero-leakage session binding, and no third-party Python runtime dependencies. Attestation requires a separately installed, independently trusted Rust `uq` executable and explicit policy.

## Installation

```bash
cd client
pip install .
```

Or install in editable mode for local development:
```bash
pip install -e client/
```

## Quickstart

### 1. Simple Chat Completion

```python
from ntrust import ConfidentialClient

client = ConfidentialClient(
    base_url="https://inference.example.com",
    api_key="your-ram-only-api-key"
)

response = client.chat.completions.create(
    model="default",
    messages=[
        {"role": "system", "content": "You are a confidential AI assistant."},
        {"role": "user", "content": "Explain homomorphic encryption in one sentence."}
    ],
    temperature=0.7,
    max_tokens=150
)

print(response.text)
# Dot-notation or dict access:
print(response.choices[0].message.content)
```

### 2. Streaming Chat Completion (SSE)

```python
from ntrust import ConfidentialClient

client = ConfidentialClient(
    base_url="https://inference.example.com",
    api_key="your-ram-only-api-key"
)

stream = client.chat.completions.stream(
    model="default",
    messages=[{"role": "user", "content": "Write a short poem about secure enclaves."}]
)

for chunk in stream:
    print(chunk.delta_text, end="", flush=True)
print()
```

### 3. Hardware-Attested Pre-Flight Verification

In confidential environments, you can enforce that the remote machine proves its hardware identity (AMD SEV-SNP or Intel TDX + NVIDIA H100 CC-On) and binds its active TLS session key before any prompt data is transmitted:

```python
from ntrust import ConfidentialClient, AttestationError

try:
    client = ConfidentialClient(
        base_url="https://inference.example.com",
        api_key="your-ram-only-api-key",
        verify_attestation=True,  # Validates hardware attestation & TLS SPKI binding
        expected_value_x="<approved-96-hex>",  # Required application-file commitment
        expected_measurement="<approved-96-hex>",  # Required CPU launch measurement
        gpu_policy="/local/enrolled-gpus.json",  # Or cpu_only=True for a relay
        platform="tdx", cpu_collateral="/local/intel-collateral.json",
        cpu_tcb_policy="/local/cpu-policy.json", uq_binary="/trusted/bin/uq",
    )
    print("Remote enclave verified successfully!")
except AttestationError as e:
    print(f"Enclave rejected: {e}")
```

### 4. CLI Usage

The package installs the `ntrust` CLI command:

```bash
# Chat with the endpoint
ntrust chat --endpoint https://inference.example.com --key <api-key> --stream "Hello confidential GPU!"

# Verify remote hardware attestation
ntrust attest --endpoint https://inference.example.com \
  --value-x <approved-96-hex> --measurement <approved-96-hex> \
  --gpu-policy /local/enrolled-gpus.json --platform tdx \
  --cpu-collateral /local/intel-collateral.json --cpu-tcb-policy /local/cpu-policy.json \
  --uq-bin /trusted/bin/uq

# List available models
ntrust models --endpoint https://inference.example.com --key <api-key>
```


Attestation checks fail before connecting if the trusted binary or independent
policy is missing. The SDK no longer returns an accepting structural-only
receipt verdict. `verify_attestation=True` and `ntrust chat --attest` require
these same inputs; the CLI chat command accepts the attestation policy options.
Hardware and end-to-end acceptance remain pending; mocked adapter tests do not
establish confidential hardware compatibility.

Optional local parameters are `boot_policy`, `uki`, `google_boot_verifier` and
`prior_stage_policy` (matching CLI flags use hyphens). The Google helper must be
an absolute path to a nonempty regular executable and requires `boot_policy`.
It selects measured-boot replay, not CPU verification. Prior-stage policy is a
nonempty local JSON file bounded to 1 MiB. None of these paths or file contents
is uploaded. See [../ATTESTATION.md](../ATTESTATION.md) for runtime-log collection
and the optional companion release-pin proposal.


Attested SDK requests now perform a fresh challenge and Rust appraisal before
**every** model query, inference request, and streaming request. The SDK then
checks the actual request connection's certificate SPKI against the key observed
by the attestation transport, before sending any HTTP headers, API key, or body.
Every reconnection repeats the key check. A verified result must be used within
30 seconds; expired results and failed refreshes reject the request. A completed
response stream stays on its checked TLS connection and does not require a new
appraisal for each received chunk.

Calling `verify_attestation()` enables this requirement for subsequent requests,
even when that first check fails. `attestation_verdict` reports the latest
successful check and is never a cached authorization for later traffic. The
default mode with no attestation requested remains explicitly unverified.
Certificate-authority and hostname checks still apply. This establishes request
TLS-key continuity with the fresh attestation; it does not establish physical
CPU/GPU attachment or attest a relay's remote inference origin.
