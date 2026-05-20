packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1"
    }
  }
}

# ── Variables ──────────────────────────────────────────────────────────────────

variable "bas_version" {
  description = "BAS Platform version string embedded in the image"
  default     = "latest"
}

variable "ubuntu_iso_url" {
  description = "Ubuntu 24.04 LTS server ISO download URL"
  default     = "https://releases.ubuntu.com/24.04.2/ubuntu-24.04.2-live-server-amd64.iso"
}

variable "ubuntu_iso_checksum" {
  description = "ISO checksum — 'file:URL' fetches the SHA256SUMS file automatically"
  default     = "file:https://releases.ubuntu.com/24.04.2/SHA256SUMS"
}

variable "airgap_bundle" {
  description = "Absolute path to dist/bas-airgap-<version>.tar.gz (build with packaging/airgap/pack.sh)"
}

variable "build_cpus" {
  default = 2
}

variable "build_memory_mb" {
  default = 4096
}

variable "disk_size_mb" {
  default = 20480
}

variable "output_dir" {
  description = "Directory for the output QCOW2 (convert.sh adds VHDX and OVA)"
  default     = "../../dist/packer-output"
}

variable "packer_ssh_pass" {
  description = "Temporary build-time SSH password — set by build-packer.sh, removed during sysprep"
  default     = "packer-build-only"
  sensitive   = true
}

# ── Source ─────────────────────────────────────────────────────────────────────

source "qemu" "bas_ubuntu" {
  # ISO
  iso_url      = var.ubuntu_iso_url
  iso_checksum = var.ubuntu_iso_checksum

  # VM sizing
  cpus        = var.build_cpus
  memory      = var.build_memory_mb
  disk_size   = var.disk_size_mb
  accelerator = "kvm"

  # Networking
  net_device = "virtio-net"

  # Disk
  disk_interface = "virtio"
  format         = "qcow2"

  # Output
  output_directory = var.output_dir
  vm_name          = "bas-platform-${var.bas_version}.qcow2"

  # Boot — GRUB command line mode (reliable across Ubuntu 24.04 ISO builds)
  headless     = true
  http_directory = "http"
  http_port_min  = 8100
  http_port_max  = 8199

  boot_wait = "5s"
  boot_command = [
    "c<wait3>",
    "linux /casper/vmlinuz autoinstall ds=nocloud-net\\;s=http://{{.HTTPIP}}:{{.HTTPPort}}/ quiet ---<enter><wait3>",
    "initrd /casper/initrd<enter><wait3>",
    "boot<enter>"
  ]

  # SSH (used by all provisioners)
  communicator = "ssh"
  ssh_username = "bas"
  ssh_password = var.packer_ssh_pass
  ssh_timeout  = "90m"

  shutdown_command = "echo '${var.packer_ssh_pass}' | sudo -S shutdown -P now"
}

# ── Build ──────────────────────────────────────────────────────────────────────

build {
  name    = "bas-platform"
  sources = ["source.qemu.bas_ubuntu"]

  # Upload the pre-built air-gap bundle (images + compose files)
  provisioner "file" {
    source      = var.airgap_bundle
    destination = "/var/tmp/bas-airgap.tar.gz"
  }

  # Step 1 — Install Docker + system dependencies
  provisioner "shell" {
    execute_command = "echo '${var.packer_ssh_pass}' | sudo -S env {{.Vars}} bash {{.Path}}"
    script          = "scripts/provision.sh"
  }

  # Step 2 — Install BAS files and first-boot service
  provisioner "shell" {
    execute_command  = "echo '${var.packer_ssh_pass}' | sudo -S env {{.Vars}} bash {{.Path}}"
    environment_vars = ["BAS_VERSION=${var.bas_version}"]
    script           = "scripts/install-bas.sh"
  }

  # Step 3 — Sysprep (zero host keys, logs, machine-id — must be last)
  provisioner "shell" {
    execute_command = "echo '${var.packer_ssh_pass}' | sudo -S env {{.Vars}} bash {{.Path}}"
    script          = "scripts/sysprep.sh"
  }
}
