output "public_ip" {
  description = "Public IPv4 address assigned to the confidential VM."
  value       = azurerm_public_ip.ntrust.ip_address
}

output "fqdn" {
  description = "Fully Qualified Domain Name of the instance if dns_label was provided."
  value       = azurerm_public_ip.ntrust.fqdn
}

output "ssh_command" {
  description = "Command to connect as operator."
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.ntrust.ip_address}"
}

output "https_endpoint" {
  description = "Inference endpoint URL."
  value       = "https://${coalesce(azurerm_public_ip.ntrust.fqdn, azurerm_public_ip.ntrust.ip_address)}"
}
