#!/usr/bin/env bash
# BAS Platform — VM Image Format Converter
#
# Converts the Packer-built QCOW2 to VHDX (Hyper-V) and OVA (VMware/VirtualBox).
# Run after a successful packer build.
#
# Usage:
#   bash packaging/packer/convert.sh [version]
#
# Prerequisites:
#   qemu-img   (apt install qemu-utils)
#   tar        (standard)
#   ovftool    (optional — higher-quality OVA; falls back to manual OVA packaging)
#
# Output in dist/:
#   bas-platform-<version>.qcow2   (KVM/QEMU, already produced by Packer)
#   bas-platform-<version>.vhdx    (Hyper-V)
#   bas-platform-<version>.ova     (VMware ESXi / VirtualBox)
#   bas-platform-<version>.sha256  (checksums of all three)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

VERSION="${1:-$(cat "${REPO_ROOT}/dist/packer-output/"*.qcow2 2>/dev/null | head -1 | grep -oP '\d+\.\d+\.\d+' || echo "latest")}"
DIST_DIR="${REPO_ROOT}/dist"
PACKER_OUT="${DIST_DIR}/packer-output"
QCOW2="${PACKER_OUT}/bas-platform-${VERSION}.qcow2"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Prerequisites ──────────────────────────────────────────────────────────────
if ! command -v qemu-img &>/dev/null; then
  err "qemu-img not found. Install: apt-get install -y qemu-utils"
  exit 1
fi
if [[ ! -f "$QCOW2" ]]; then
  err "QCOW2 not found: ${QCOW2}"
  echo "  Run: bash packaging/packer/build-packer.sh ${VERSION}"
  exit 1
fi
log "Source: ${QCOW2} ($(du -sh "${QCOW2}" | cut -f1))"

# ── Compact QCOW2 first ────────────────────────────────────────────────────────
QCOW2_COMPACT="${DIST_DIR}/bas-platform-${VERSION}.qcow2"
if [[ "$QCOW2" != "$QCOW2_COMPACT" ]]; then
  log "Compacting QCOW2..."
  qemu-img convert -f qcow2 -O qcow2 -c "${QCOW2}" "${QCOW2_COMPACT}"
  log "  $(du -sh "${QCOW2_COMPACT}" | cut -f1)  →  ${QCOW2_COMPACT}"
fi

# ── VHDX (Hyper-V) ────────────────────────────────────────────────────────────
VHDX="${DIST_DIR}/bas-platform-${VERSION}.vhdx"
log "Converting to VHDX (Hyper-V)..."
qemu-img convert \
  -f qcow2 \
  -O vhdx \
  -o subformat=dynamic \
  "${QCOW2_COMPACT}" "${VHDX}"
log "  $(du -sh "${VHDX}" | cut -f1)  →  ${VHDX}"

# ── OVA (VMware ESXi / VirtualBox) ────────────────────────────────────────────
VMDK="${DIST_DIR}/bas-platform-${VERSION}.vmdk"
OVA="${DIST_DIR}/bas-platform-${VERSION}.ova"
OVF="${DIST_DIR}/bas-platform-${VERSION}.ovf"

if command -v ovftool &>/dev/null; then
  # ovftool produces a higher-quality OVA with correct hardware descriptors
  log "Converting to OVA with ovftool..."
  ovftool \
    --diskMode=thin \
    --name="BAS Platform ${VERSION}" \
    "${QCOW2_COMPACT}" "${OVA}"
  log "  $(du -sh "${OVA}" | cut -f1)  →  ${OVA}"
  rm -f "${VMDK}" "${OVF}"
else
  warn "ovftool not found — building OVA manually (compatible with VirtualBox and most ESXi versions)."

  # Convert to VMDK (streamOptimized subformat for OVA compatibility)
  log "Converting QCOW2 → VMDK..."
  qemu-img convert \
    -f qcow2 \
    -O vmdk \
    -o adapter_type=lsilogic,subformat=streamOptimized,compat6 \
    "${QCOW2_COMPACT}" "${VMDK}"

  VMDK_SIZE=$(qemu-img info --output=json "${VMDK}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['virtual-size'])")
  VMDK_CAPACITY_GB=$(( (VMDK_SIZE + 1073741823) / 1073741824 ))
  VMDK_FILE_SIZE=$(stat -c%s "${VMDK}")

  log "Generating OVF descriptor..."
  cat > "${OVF}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vmw="http://www.vmware.com/schema/ovf"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <References>
    <File ovf:href="bas-platform-${VERSION}.vmdk"
          ovf:id="file1"
          ovf:size="${VMDK_FILE_SIZE}"/>
  </References>

  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="${VMDK_CAPACITY_GB}"
          ovf:capacityAllocationUnits="byte * 2^30"
          ovf:diskId="vmdisk1"
          ovf:fileRef="file1"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>

  <NetworkSection>
    <Info>Network adapters</Info>
    <Network ovf:name="VM Network">
      <Description>VM Network</Description>
    </Network>
  </NetworkSection>

  <VirtualSystem ovf:id="bas-platform">
    <Info>BAS Platform ${VERSION} — Breach and Attack Simulation</Info>
    <Name>BAS Platform ${VERSION}</Name>

    <OperatingSystemSection ovf:id="101">
      <Info>Ubuntu 24.04 LTS (x86_64)</Info>
      <Description>Ubuntu Linux (64-bit)</Description>
    </OperatingSystemSection>

    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>vmx-19</vssd:VirtualSystemType>
      </System>

      <!-- CPUs -->
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>2 virtual CPUs</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
      </Item>

      <!-- Memory (4 GB) -->
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>4096 MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>4096</rasd:VirtualQuantity>
      </Item>

      <!-- SCSI controller -->
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>

      <!-- Disk -->
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>

      <!-- Network adapter -->
      <Item>
        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>VirtIO Ethernet adapter</rasd:Description>
        <rasd:ElementName>Network Adapter 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
EOF

  log "Packaging OVA..."
  # OVA is a TAR (not gzip) — order matters: OVF first, then VMDK
  tar -cf "${OVA}" -C "${DIST_DIR}" \
    "$(basename "${OVF}")" \
    "$(basename "${VMDK}")"
  rm -f "${VMDK}" "${OVF}"
  log "  $(du -sh "${OVA}" | cut -f1)  →  ${OVA}"
fi

# ── Checksums ──────────────────────────────────────────────────────────────────
CHECKSUM_FILE="${DIST_DIR}/bas-platform-${VERSION}-vm.sha256"
log "Generating checksums..."
(
  cd "${DIST_DIR}"
  sha256sum \
    "bas-platform-${VERSION}.qcow2" \
    "bas-platform-${VERSION}.vhdx"  \
    "bas-platform-${VERSION}.ova"   \
    2>/dev/null || true
) > "${CHECKSUM_FILE}"
log "Checksums: ${CHECKSUM_FILE}"

echo ""
log "Conversion complete."
echo ""
printf "  %-12s  %s\n" "Format" "File"
printf "  %-12s  %s\n" "------" "----"
printf "  %-12s  %s  (%s)\n" "QCOW2 (KVM)" "bas-platform-${VERSION}.qcow2" "$(du -sh "${DIST_DIR}/bas-platform-${VERSION}.qcow2" | cut -f1)"
printf "  %-12s  %s  (%s)\n" "VHDX (HyperV)" "bas-platform-${VERSION}.vhdx"  "$(du -sh "${VHDX}" | cut -f1)"
printf "  %-12s  %s  (%s)\n" "OVA (VMware)" "bas-platform-${VERSION}.ova"   "$(du -sh "${OVA}"  | cut -f1)"
echo ""
echo "  Sign with: bash packaging/signing/sign.sh ${DIST_DIR}/bas-platform-${VERSION}.ova"
