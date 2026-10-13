terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.80.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "ntrust" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_virtual_network" "ntrust" {
  name                = "vnet-${var.vm_name}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.ntrust.location
  resource_group_name = azurerm_resource_group.ntrust.name
}

resource "azurerm_subnet" "ntrust" {
  name                 = "snet-${var.vm_name}"
  resource_group_name  = azurerm_resource_group.ntrust.name
  virtual_network_name = azurerm_virtual_network.ntrust.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "ntrust" {
  name                = "nsg-${var.vm_name}"
  location            = azurerm_resource_group.ntrust.location
  resource_group_name = azurerm_resource_group.ntrust.name

  # Public HTTPS inference endpoint (ACME TLS-ALPN-01 + API)
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Restricted operator administration
  security_rule {
    name                       = "AllowOperatorSSH"
    priority                   = 1010
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.operator_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "ntrust" {
  name                = "pip-${var.vm_name}"
  location            = azurerm_resource_group.ntrust.location
  resource_group_name = azurerm_resource_group.ntrust.name
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = var.dns_label
}

resource "azurerm_network_interface" "ntrust" {
  name                = "nic-${var.vm_name}"
  location            = azurerm_resource_group.ntrust.location
  resource_group_name = azurerm_resource_group.ntrust.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.ntrust.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.ntrust.id
  }
}

resource "azurerm_network_interface_security_group_association" "ntrust" {
  network_interface_id      = azurerm_network_interface.ntrust.id
  network_security_group_id = azurerm_network_security_group.ntrust.id
}

resource "azurerm_linux_virtual_machine" "ntrust" {
  name                = var.vm_name
  resource_group_name = azurerm_resource_group.ntrust.name
  location            = azurerm_resource_group.ntrust.location
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [
    azurerm_network_interface.ntrust.id,
  ]

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(pathexpand(var.ssh_public_key_path))
  }

  # Agentless deployment (walinuxagent is stripped to eliminate remote telemetry / command injection)
  allow_extension_operations = false

  # Confidential VM Security Profile (AMD SEV-SNP)
  vtpm_enabled        = true
  secure_boot_enabled = true

  os_disk {
    caching                  = "ReadWrite"
    storage_account_type     = "Premium_LRS"
    security_encryption_type = "VMGuestStateOnly"
  }

  source_image_id = var.image_id

  custom_data = fileexists(pathexpand(var.cloud_init_path)) ? base64encode(file(pathexpand(var.cloud_init_path))) : null
}
