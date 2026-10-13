variable "project_id" {
  description = "GCP Project ID."
  type        = string
}

variable "region" {
  description = "GCP region with confidential A3 GPU capacity."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone with confidential A3 GPU capacity (e.g. us-central1-a)."
  type        = string
  default     = "us-central1-a"
}

variable "instance_name" {
  description = "Name of the confidential GCE instance."
  type        = string
  default     = "ntrust-vllm"
}

variable "image" {
  description = "Image name or image family (e.g. projects/zmax-ntrust/global/images/ntrust-vllm-0-1-0)."
  type        = string
}

variable "operator_cidr" {
  description = "Operator CIDR allowed for SSH ingress (never use 0.0.0.0/0 in production)."
  type        = string
  default     = "127.0.0.1/32"
}

variable "cloud_init_path" {
  description = "Path to cloud-init user-data file."
  type        = string
  default     = "../../guest/cloud-init.example.yaml"
}

variable "spot_instance" {
  description = "Whether to launch as a Spot instance (recommended for A3 development & batch inference)."
  type        = bool
  default     = true
}
