output "public_ip" {
  description = "Public static IPv4 address of the instance."
  value       = google_compute_address.static_ip.address
}

output "instance_id" {
  description = "GCE instance ID."
  value       = google_compute_instance.ntrust.instance_id
}

output "ssh_command" {
  description = "SSH administration command."
  value       = "ssh operator@${google_compute_address.static_ip.address}"
}

output "https_endpoint" {
  description = "Inference endpoint URL."
  value       = "https://${google_compute_address.static_ip.address}"
}
