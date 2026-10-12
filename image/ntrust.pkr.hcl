packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "= 1.1.7"
    }
  }
}

variable "ssh_private_key_file" {
  type    = string
  default = "build/image-key"
}

locals {
  ssh_key = abspath(var.ssh_private_key_file)
}

source "qemu" "ntrust" {
  iso_url          = "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20261008/ubuntu-24.04-minimal-cloudimg-amd64.img"
  iso_checksum     = "sha256:2f119f50bf29fe40e73b69ae2a736e8210d8146796f036e0324315b6b3a777df"
  disk_image       = true
  format           = "qcow2"
  disk_size        = "64G"
  disk_interface   = "virtio-scsi"
  disk_discard     = "unmap"
  output_directory = "${path.cwd}/dist/qemu"
  vm_name          = "ntrust.qcow2"
  accelerator      = "kvm"
  qemu_binary      = "qemu-system-x86_64"
  machine_type     = "q35"
  cpus             = 4
  memory           = 4096
  headless         = true
  efi_boot         = true
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.fd"
  net_device       = "virtio-net"
  ssh_username     = "root"
  ssh_private_key_file = local.ssh_key
  ssh_timeout      = "20m"
  shutdown_command = "sh /tmp/ntrust/image/finalize.sh"
  shutdown_timeout = "5m"
  cd_label         = "cidata"
  cdrom_interface  = "virtio"
  cd_content = {
    "meta-data" = "instance-id: ntrust-image-build\nlocal-hostname: ntrust\n"
    "user-data" = templatefile("${path.cwd}/image/build-cloud-init.yaml", {
      public_key = trimspace(file("${local.ssh_key}.pub"))
    })
  }
  qemuargs = [
    ["-cpu", "host"],
    ["-serial", "file:${path.cwd}/build/serial.log"],
    ["-netdev", "user,id=user.0,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"]
  ]
}

build {
  sources = ["source.qemu.ntrust"]
  provisioner "shell" {
    inline = ["cloud-init status --wait", "mkdir -p /tmp/ntrust"]
  }
  provisioner "file" {
    sources     = ["${path.cwd}/guest", "${path.cwd}/image"]
    destination = "/tmp/ntrust/"
  }
  provisioner "shell" {
    inline = ["bash /tmp/ntrust/image/install.sh"]
  }
}
