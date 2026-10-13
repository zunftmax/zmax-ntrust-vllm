variable "location" {
  description = "Azure region with confidential H100 capacity (e.g. eastus2, westeurope)."
  type        = string
  default     = "eastus2"
}

variable "resource_group_name" {
  description = "Name of the resource group to create."
  type        = string
  default     = "rg-ntrust"
}

variable "vm_name" {
  description = "Name of the confidential VM instance."
  type        = string
  default     = "ntrust-vllm"
}

variable "vm_size" {
  description = "Confidential VM size with NVIDIA H100 GPU."
  type        = string
  default     = "Standard_NCC40ads_H100_v5"
}

variable "admin_username" {
  description = "Operator administration username."
  type        = string
  default     = "operator"
}

variable "ssh_public_key_path" {
  description = "Path to the operator's public SSH key file."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "operator_cidr" {
  description = "CIDR block permitted for SSH administration (never use 0.0.0.0/0 in production)."
  type        = string
  default     = "127.0.0.1/32"
}

variable "cloud_init_path" {
  description = "Path to cloud-init user-data file."
  type        = string
  default     = "../../guest/cloud-init.example.yaml"
}

variable "image_id" {
  description = "Resource ID of the Ntrust image in an Azure Compute Gallery or Community Gallery."
  type        = string
}

variable "dns_label" {
  description = "Optional DNS label for the public IP address (maps to <label>.<location>.cloudapp.azure.com)."
  type        = string
  default     = null
}
