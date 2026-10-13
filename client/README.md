# Ntrust Python SDK

The official Python client SDK for Ntrust Confidential AI Inference Virtual Machines.

Supports OpenAI-compatible API endpoints with hardware attestation verification, zero-leakage session binding, and zero external runtime dependencies.

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
        expected_value_x="<sha384-hex>",  # Optional: expected Value X disk hash
        expected_measurement="<sha384-hex>" # Optional: expected CPU measurement
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
ntrust attest --endpoint https://inference.example.com

# List available models
ntrust models --endpoint https://inference.example.com --key <api-key>
```
