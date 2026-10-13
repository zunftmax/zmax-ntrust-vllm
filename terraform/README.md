# OpenTofu & Terraform Modules for Ntrust

Turnkey Infrastructure as Code (IaC) modules to launch Ntrust Confidential GPU Virtual Machines on Azure and GCP with strict hardware security controls.

Fully compatible with **OpenTofu (>= 1.6)** and **HashiCorp Terraform (>= 1.5)**.

## Directory Structure

- [`azure/`](azure/): Provisions Azure `Standard_NCC40ads_H100_v5` with AMD SEV-SNP confidential VM security profile, vTPM, Secure Boot, and restricted NSG rules.
- [`gcp/`](gcp/): Provisions GCP `a3-highgpu-1g` with Intel TDX confidential compute, shielded VM, GVNIC, and restricted firewall policies.

## Security Architecture Enforced by Modules

1. **Hardware Security Type:**
   - Azure: `security_type = "ConfidentialVM"`, `vtpm_enabled = true`, `secure_boot_enabled = true`.
   - GCP: `confidential_instance_config { confidential_compute_type = "TDX" }`, `shielded_instance_config`.
2. **Attack Surface Reduction:**
   - Azure: `allow_extension_operations = false` (enforces agentless deployment without `walinuxagent`).
   - GCP: Stripped telemetry, no default service account scopes.
3. **Network Confinement:**
   - Public port 443 is open for ACME TLS-ALPN-01 issuance and HTTPS inference.
   - Public port 22 (SSH) is strictly confined to `operator_cidr` and never opened to `0.0.0.0/0`.

## Quickstart (OpenTofu / Terraform)

### Azure

```bash
cd terraform/azure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your operator IP CIDR and gallery image ID
tofu init   # or terraform init
tofu plan   # or terraform plan
tofu apply  # or terraform apply
```

### GCP

```bash
cd terraform/gcp
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your project ID and image name
tofu init   # or terraform init
tofu plan   # or terraform plan
tofu apply  # or terraform apply
```
