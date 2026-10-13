"""Verify OpenTofu/Terraform IaC modules enforce confidential compute security controls."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TERRAFORM_DIR = ROOT / "terraform"


class TerraformModuleTests(unittest.TestCase):
    def test_azure_module_enforces_confidential_gpu_contract(self):
        main_tf = (TERRAFORM_DIR / "azure" / "main.tf").read_text()
        var_tf = (TERRAFORM_DIR / "azure" / "variables.tf").read_text()

        # Enforce NCC40ads H100 v5 default
        self.assertIn("Standard_NCC40ads_H100_v5", var_tf)

        # Enforce agentless VM (no walinuxagent)
        self.assertIn("allow_extension_operations = false", main_tf)

        # Enforce confidential security profile
        self.assertIn("vtpm_enabled        = true", main_tf)
        self.assertIn("secure_boot_enabled = true", main_tf)
        self.assertIn('security_encryption_type = "VMGuestStateOnly"', main_tf)

        # Enforce port isolation
        self.assertIn('destination_port_range     = "443"', main_tf)
        self.assertIn('destination_port_range     = "22"', main_tf)
        self.assertIn("source_address_prefix      = var.operator_cidr", main_tf)

    def test_gcp_module_enforces_confidential_gpu_contract(self):
        main_tf = (TERRAFORM_DIR / "gcp" / "main.tf").read_text()
        var_tf = (TERRAFORM_DIR / "gcp" / "variables.tf").read_text()

        # Enforce a3-highgpu-1g
        self.assertIn('machine_type = "a3-highgpu-1g"', main_tf)

        # Enforce TDX confidential computing
        self.assertIn('confidential_compute_type = "TDX"', main_tf)

        # Enforce shielded VM with Secure Boot and vTPM
        self.assertIn("enable_secure_boot          = true", main_tf)
        self.assertIn("enable_vtpm                 = true", main_tf)
        self.assertIn("enable_integrity_monitoring = true", main_tf)

        # Enforce GVNIC for high throughput
        self.assertIn('nic_type   = "GVNIC"', main_tf)

        # Enforce firewall rules
        self.assertIn('ports    = ["443"]', main_tf)
        self.assertIn('ports    = ["22"]', main_tf)
        self.assertIn("source_ranges = [var.operator_cidr]", main_tf)


if __name__ == "__main__":
    unittest.main()
