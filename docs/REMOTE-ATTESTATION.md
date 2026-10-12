# Remote verification — next phase

Reserved for customer verification after the core confidential GPU VM works.

The local NVIDIA verifier gates startup. It does not bind the CPU, image, runtime configuration or guest TLS public key to a customer-verified measurement. Neither a cloud launch flag nor a CT certificate entry supplies that missing binding.

Next work: define the approved image/configuration identity, fresh CPU and GPU evidence, TLS-key binding, customer verifier policy and rejection tests; then define image sealing, reproducible releases, rollback policy and publication evidence. No code in this phase should delay core GPU bring-up.

See [ATTESTATION-RESEARCH.md](ATTESTATION-RESEARCH.md) for the complete comparison of **IETF RATS (RFC 9334 / RFC 9711 EAT)**, **RA-TLS**, **RFC 9266 TLS Exporter channel binding**, **AMD SEV-SNP KDS + Intel TDX + NVIDIA NRAS/local SPDM composite binding**, and **Azure/GCP Marketplace publication prerequisites**.
