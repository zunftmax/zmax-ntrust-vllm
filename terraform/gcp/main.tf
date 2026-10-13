terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_compute_network" "ntrust" {
  name                    = "vpc-${var.instance_name}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "ntrust" {
  name          = "snet-${var.instance_name}"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
  network       = google_compute_network.ntrust.id
}

resource "google_compute_firewall" "allow_https" {
  name    = "allow-https-${var.instance_name}"
  network = google_compute_network.ntrust.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ntrust-https"]
}

resource "google_compute_firewall" "allow_operator_ssh" {
  name    = "allow-ssh-${var.instance_name}"
  network = google_compute_network.ntrust.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [var.operator_cidr]
  target_tags   = ["ntrust-ssh"]
}

resource "google_compute_address" "static_ip" {
  name   = "ip-${var.instance_name}"
  region = var.region
}

resource "google_compute_instance" "ntrust" {
  name         = var.instance_name
  machine_type = "a3-highgpu-1g"
  zone         = var.zone

  tags = ["ntrust-https", "ntrust-ssh"]

  # Confidential VM Security Profile (Intel TDX)
  confidential_instance_config {
    confidential_compute_type = "TDX"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    provisioning_model  = var.spot_instance ? "SPOT" : "STANDARD"
    on_host_maintenance = "TERMINATE"
    automatic_restart   = false
  }

  boot_disk {
    auto_delete = true
    initialize_params {
      image = var.image
      size  = 64
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.ntrust.id
    nic_type   = "GVNIC"
    access_config {
      nat_ip = google_compute_address.static_ip.address
    }
  }

  metadata = fileexists(pathexpand(var.cloud_init_path)) ? {
    user-data = file(pathexpand(var.cloud_init_path))
  } : {}
}
