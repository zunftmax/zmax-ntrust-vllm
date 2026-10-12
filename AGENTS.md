# Project constraints

- Build the core confidential GPU VM first. Try one shared guest image for Azure
  and GCP, with provider-specific import formats. AWS is off the target list
  because no documented SEV-SNP/TDX plus confidential NVIDIA GPU instance was found.
- Do Linux builds on axp.computer over SSH. Use an existing image tool, not a new
  VM builder framework. Do not set up emulation on the Mac.
- Keep custom code small: maintained HTTPS/ACME server, upstream inference engine,
  NVIDIA driver. NVIDIA owns SPDM and GPU encryption; do not implement them.
- The guest generates its TLS key and obtains a Let's Encrypt certificate using
  TLS-ALPN-01. Keep keys and inference working data in guest memory.
- Keep the inference backend local. No prompt/response logging, remote inference
  fallback, telemetry agents, or general execution API.
- Remote attestation, customer verification, reproducible releases and image
  sealing are deferred. Do not let that work delay the core VM.
- A local build or boot does not establish cloud or confidential GPU compatibility.
  Report what actually exists and ran. Never label a normal VM confidential.
- Keep provider launch configuration separate from shared guest contents.
