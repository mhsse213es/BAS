# Default variable values for bas-platform Packer build.
# Override on the command line:
#   packer build -var-file=variables.pkrvars.hcl -var "bas_version=1.2.0" ubuntu.pkr.hcl
#
# Note: packer_ssh_pass and airgap_bundle are set by build-packer.sh at runtime.

bas_version   = "latest"
build_cpus    = 2
build_memory_mb = 4096
disk_size_mb  = 20480
output_dir    = "../../dist/packer-output"

# ISO — Ubuntu 24.04.2 LTS server (amd64)
ubuntu_iso_url      = "https://releases.ubuntu.com/24.04.2/ubuntu-24.04.2-live-server-amd64.iso"
ubuntu_iso_checksum = "file:https://releases.ubuntu.com/24.04.2/SHA256SUMS"
