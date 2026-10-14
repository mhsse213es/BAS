#!/usr/bin/env bash
# BAS Platform — Hardware Appliance ISO Builder
#
# Remasters the Ubuntu 24.04 LTS server ISO into a BAS Platform appliance ISO:
#   • Auto-installs Ubuntu with LUKS full-disk encryption + LVM
#   • Embeds BAS airgap bundle (optional, for fully offline installs)
#   • First-boot wizard configures BAS after OS install
#   • Hybrid BIOS+UEFI bootable
#
# Usage:
#   bash packaging/iso/build-iso.sh [version] [options]
#
# Options:
#   --ubuntu-iso <path>    Local Ubuntu ISO (downloads if not provided)
#   --bundle    <path>     Embed a pre-built bas-airgap bundle into the ISO
#   --no-luks              Build without LUKS encryption (test/dev only)
#   --output    <path>     Output ISO path (default: dist/bas-platform-<version>.iso)
#
# Prerequisites (Ubuntu/Debian build host):
#   apt-get install -y xorriso squashfs-tools genisoimage isolinux
#
# Run from the repository root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

VERSION="${1:-$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "dev")}"
shift || true

UBUNTU_ISO_URL="https://releases.ubuntu.com/24.04.2/ubuntu-24.04.2-live-server-amd64.iso"
UBUNTU_ISO_CHECKSUM="file:https://releases.ubuntu.com/24.04.2/SHA256SUMS"
UBUNTU_ISO_LOCAL=""
AIRGAP_BUNDLE=""
USE_LUKS=true
OUTPUT_ISO="${REPO_ROOT}/dist/bas-platform-${VERSION}.iso"
DIST_DIR="${REPO_ROOT}/dist"

# ── Parse options ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ubuntu-iso) shift; UBUNTU_ISO_LOCAL="$1" ;;
    --bundle)     shift; AIRGAP_BUNDLE="$1" ;;
    --no-luks)    USE_LUKS=false ;;
    --output)     shift; OUTPUT_ISO="$1" ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Prerequisites ──────────────────────────────────────────────────────────────
log "Checking prerequisites..."
MISSING=()
for tool in xorriso openssl sha256sum curl; do
  command -v "$tool" &>/dev/null || MISSING+=("$tool")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
  err "Missing tools: ${MISSING[*]}"
  echo "  Install: apt-get install -y xorriso openssl coreutils"
  exit 1
fi

mkdir -p "${DIST_DIR}"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
log "Working directory: ${WORK_DIR}"

# ── 1. Ubuntu ISO ──────────────────────────────────────────────────────────────
if [[ -n "$UBUNTU_ISO_LOCAL" ]]; then
  if [[ ! -f "$UBUNTU_ISO_LOCAL" ]]; then
    err "Ubuntu ISO not found: ${UBUNTU_ISO_LOCAL}"
    exit 1
  fi
  UBUNTU_ISO="$UBUNTU_ISO_LOCAL"
  log "Using local ISO: ${UBUNTU_ISO} ($(du -sh "${UBUNTU_ISO}" | cut -f1))"
else
  UBUNTU_ISO="${DIST_DIR}/ubuntu-24.04-server-amd64.iso"
  if [[ -f "$UBUNTU_ISO" ]]; then
    log "Using cached ISO: ${UBUNTU_ISO}"
  else
    log "Downloading Ubuntu 24.04 LTS server ISO..."
    curl -L --progress-bar "${UBUNTU_ISO_URL}" -o "${UBUNTU_ISO}"
  fi
fi

# ── 2. Extract ISO ─────────────────────────────────────────────────────────────
ISO_EXTRACT="${WORK_DIR}/iso"
log "Extracting ISO..."
xorriso -osirrox on -indev "${UBUNTU_ISO}" -extract / "${ISO_EXTRACT}" 2>/dev/null
chmod -R u+w "${ISO_EXTRACT}"
log "  Extracted $(find "${ISO_EXTRACT}" -type f | wc -l) files."

# ── 3. Generate LUKS passphrase ────────────────────────────────────────────────
if $USE_LUKS; then
  LUKS_PASS=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 20)
  log "Generated LUKS passphrase (printed once — save it):"
  echo ""
  echo "  ╔════════════════════════════════════════════════╗"
  printf "  ║  LUKS key: %-34s  ║\n" "${LUKS_PASS}"
  echo "  ╚════════════════════════════════════════════════╝"
  echo ""
  warn "This passphrase is embedded in the ISO. Change it on first boot."
  echo "  Command: sudo cryptsetup luksChangeKey /dev/<encrypted-partition>"
  echo ""
else
  LUKS_PASS="NOENCRYPTION"
  warn "Building WITHOUT LUKS encryption (--no-luks). Not for production."
fi

# ── 4. Generate admin password hash ───────────────────────────────────────────
log "Generating build admin credentials..."
ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | head -c 16)
ADMIN_SALT=$(openssl rand -base64 8 | tr -dc 'a-zA-Z0-9' | head -c 12)
ADMIN_HASH=$(openssl passwd -6 -salt "${ADMIN_SALT}" "${ADMIN_PASS}")

# ── 5. Build autoinstall directory ────────────────────────────────────────────
log "Building autoinstall configuration..."
AUTOINSTALL_DIR="${ISO_EXTRACT}/autoinstall"
mkdir -p "${AUTOINSTALL_DIR}/scripts"

AUTOINSTALL_SRC="${REPO_ROOT}/packaging/iso/autoinstall"

# Patch user-data template
sed \
  -e "s|%%LUKS_PASSPHRASE%%|${LUKS_PASS}|g" \
  -e "s|%%ADMIN_PASS_HASH%%|${ADMIN_HASH}|g" \
  -e "s|%%BAS_VERSION%%|${VERSION}|g" \
  -e "s|%%USE_LUKS%%|${USE_LUKS}|g" \
  "${AUTOINSTALL_SRC}/user-data.tmpl" > "${AUTOINSTALL_DIR}/user-data"

# Use the correct storage section based on --no-luks
if ! $USE_LUKS; then
  # Replace the LUKS storage config with simple LVM layout
  python3 - <<PYEOF
import re, sys

with open('${AUTOINSTALL_DIR}/user-data', 'r') as f:
    content = f.read()

# Remove dm_crypt block and replace luks-part volume reference with direct lvm
content = re.sub(r'\n\s*# LUKS encryption layer.*?preserve: false\n', '\n', content, flags=re.DOTALL)
content = content.replace('      volume: dm-crypt0', '      volume: luks-part')

with open('${AUTOINSTALL_DIR}/user-data', 'w') as f:
    f.write(content)
PYEOF
fi

cp "${AUTOINSTALL_SRC}/meta-data" "${AUTOINSTALL_DIR}/meta-data"
cp "${AUTOINSTALL_SRC}/scripts/post-install.sh" "${AUTOINSTALL_DIR}/scripts/"
chmod +x "${AUTOINSTALL_DIR}/scripts/post-install.sh"

# ── 5b. Stage pinned cosign (appliance build dependency) ──────────────────────
# The installed appliance needs cosign >= v3.1.0 to verify the orchestrator
# image, and an air-gapped target cannot download it, so it is fetched HERE
# (checksum-pinned; the build fails if download or checksum fails).
mkdir -p "${AUTOINSTALL_DIR}/appliance"
bash "${REPO_ROOT}/packaging/appliance/fetch-cosign.sh" "${AUTOINSTALL_DIR}/appliance/cosign-linux-amd64"
cp "${REPO_ROOT}/packaging/appliance/cosign.pin" "${AUTOINSTALL_DIR}/appliance/cosign.pin"
cp "${REPO_ROOT}/packaging/appliance/fetch-cosign.sh" "${AUTOINSTALL_DIR}/appliance/fetch-cosign.sh"

# ── 6. Optionally embed airgap bundle ─────────────────────────────────────────
if [[ -n "$AIRGAP_BUNDLE" ]]; then
  if [[ ! -f "$AIRGAP_BUNDLE" ]]; then
    err "Airgap bundle not found: ${AIRGAP_BUNDLE}"
    exit 1
  fi
  BUNDLE_SIZE=$(du -sh "${AIRGAP_BUNDLE}" | cut -f1)
  log "Embedding airgap bundle (${BUNDLE_SIZE}) into ISO..."
  cp "${AIRGAP_BUNDLE}" "${ISO_EXTRACT}/bas-airgap.tar.gz"
  # Record the bundle filename in the autoinstall config for late-commands
  echo "BUNDLE_INCLUDED=true" >> "${AUTOINSTALL_DIR}/meta-data"
else
  warn "No airgap bundle provided — ISO will need internet access or manual bundle import."
  echo "  BUNDLE_INCLUDED=false" >> "${AUTOINSTALL_DIR}/meta-data"
fi

# ── 7. Patch GRUB config (add autoinstall boot entry) ─────────────────────────
log "Patching GRUB configuration..."
GRUB_CFG="${ISO_EXTRACT}/boot/grub/grub.cfg"

if [[ ! -f "$GRUB_CFG" ]]; then
  err "grub.cfg not found at ${GRUB_CFG}. ISO structure may differ."
  exit 1
fi

# Backup original
cp "${GRUB_CFG}" "${GRUB_CFG}.orig"

# Prepend a BAS autoinstall entry at the top, reduce timeout
cat > "${ISO_EXTRACT}/boot/grub/grub.cfg" <<'GRUBEOF'
set default="0"
set timeout=10
set timeout_style=menu

if loadfont /boot/grub/font.pf2 ; then
  set gfxmode=auto
  insmod efi_gop
  insmod efi_uga
  insmod gfxterm
  terminal_output gfxterm
fi

menuentry "Install BAS Platform (LUKS Encrypted)" --id=bas-install {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet autoinstall ds=nocloud\;s=/cdrom/autoinstall/ ---
    initrd  /casper/initrd
}

menuentry "Install BAS Platform (No Encryption)" --id=bas-install-noenc {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet autoinstall ds=nocloud\;s=/cdrom/autoinstall/ bas_noenc=1 ---
    initrd  /casper/initrd
}

menuentry "Ubuntu Server Install (Manual)" --id=ubuntu-standard {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet ---
    initrd  /casper/initrd
}

menuentry "Boot from next device" --id=boot-next {
    exit
}
GRUBEOF

# ── 8. Repackage ISO ───────────────────────────────────────────────────────────
log "Repackaging ISO as ${OUTPUT_ISO}..."
log "  (This may take several minutes for large bundles)"

# Capture the original ISO's El Torito and EFI boot parameters
BOOT_CATALOG=""
EFI_IMG="${ISO_EXTRACT}/boot/grub/efi.img"

# Build the ISO using xorriso with hybrid MBR+UEFI support
xorriso -as mkisofs \
  -r \
  -V "BAS-Platform-${VERSION}" \
  -o "${OUTPUT_ISO}" \
  --grub2-mbr "${ISO_EXTRACT}/boot/grub/i386-pc/boot_hybrid.img" \
  -partition_offset 16 \
  --mbr-force-bootable \
  -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b "${EFI_IMG}" \
  -appended_part_as_gpt \
  -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \
  -c '/boot.catalog' \
  -b '/boot/grub/i386-pc/eltorito.img' \
  -no-emul-boot \
  -boot-load-size 4 \
  -boot-info-table \
  --grub2-boot-info \
  -eltorito-alt-boot \
  -e '--interval:appended_partition_2:::' \
  -no-emul-boot \
  "${ISO_EXTRACT}" 2>/dev/null

# ── 9. Generate checksum and sign ─────────────────────────────────────────────
CHECKSUM="${OUTPUT_ISO}.sha256"
sha256sum "${OUTPUT_ISO}" > "${CHECKSUM}"
log "Checksum: $(cat "${CHECKSUM}" | cut -d' ' -f1)"

SIGN_SCRIPT="${REPO_ROOT}/packaging/signing/sign.sh"
SIGNING_KEY_EMAIL="releases@audspect.com"
if command -v gpg &>/dev/null && gpg --list-secret-keys "${SIGNING_KEY_EMAIL}" &>/dev/null 2>&1; then
  log "Signing ISO..."
  bash "${SIGN_SCRIPT}" "${OUTPUT_ISO}"
else
  warn "GPG signing key not found — ISO is unsigned."
fi

# ── 10. Summary ───────────────────────────────────────────────────────────────
ISO_SIZE=$(du -sh "${OUTPUT_ISO}" | cut -f1)
log "Build complete."
echo ""
echo "  ISO:       ${OUTPUT_ISO}  (${ISO_SIZE})"
echo "  Checksum:  ${CHECKSUM}"
[[ -n "$AIRGAP_BUNDLE" ]] && echo "  Bundle:    embedded (offline install)"
echo ""
echo "  LUKS encryption: $( $USE_LUKS && echo "YES — passphrase shown above" || echo "NO (test build)" )"
echo ""
echo "  Write to USB:  sudo dd if=${OUTPUT_ISO} of=/dev/sdX bs=4M status=progress && sync"
echo "  Verify:        sha256sum --check ${CHECKSUM}"
echo ""
warn "Distribute the LUKS passphrase securely to the customer (separate from the ISO)."
