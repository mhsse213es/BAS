#!/usr/bin/env bash
# BAS Platform — TPM2 PCR Enrollment for LUKS Disk Encryption
#
# Seals the LUKS disk encryption key to TPM2 PCR (Platform Configuration
# Register) measurements.  After enrollment:
#   • The disk unlocks automatically at boot IF the bootchain is unmodified
#   • Any tampering with firmware, bootloader, or Secure Boot causes the TPM
#     to refuse releasing the key — the operator must enter the passphrase manually
#
# PCR reference:
#   PCR 0  — UEFI firmware code (detects firmware/BIOS tampering)
#   PCR 7  — Secure Boot state + authority (detects Secure Boot bypass)
#   PCR 8  — GRUB command line (detects bootloader arg tampering)
#   PCR 9  — GRUB files loaded (kernel/initrd path)
#
# Usage:
#   sudo bash packaging/tpm/enroll-pcr.sh [options]
#
# Options:
#   --device  <dev>       LUKS device (e.g. /dev/sda3) — auto-detected if omitted
#   --pcrs    <list>      Comma-separated PCR IDs to seal against (default: 0,7)
#   --pcr-bank <bank>     sha256 or sha1 (default: sha256)
#   --test                Dry-run — show what would be done without binding
#
# Prerequisites:
#   apt-get install -y clevis clevis-luks clevis-tpm2 clevis-initramfs tpm2-tools tpm2-abrmd
#
# Run AFTER: bas-firstboot setup is complete and the system is in its final state.
# Run BEFORE: kernel or firmware updates (see update-pcr.sh).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Error: must be run as root (sudo bash enroll-pcr.sh)" >&2
  exit 1
fi

# ── Defaults ───────────────────────────────────────────────────────────────────
LUKS_DEVICE=""
PCR_IDS="0,7"
PCR_BANK="sha256"
DRY_RUN=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Parse args ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --device)   shift; LUKS_DEVICE="$1" ;;
    --pcrs)     shift; PCR_IDS="$1" ;;
    --pcr-bank) shift; PCR_BANK="$1" ;;
    --test)     DRY_RUN=true ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BLUE=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
info() { echo -e "${BLUE}[i]${NC} $*"; }

# ── 1. Prerequisite checks ─────────────────────────────────────────────────────
log "Checking prerequisites..."

for tool in clevis tpm2_getrandom tpm2_pcrread; do
  if ! command -v "$tool" &>/dev/null; then
    err "${tool} not found."
    echo "  Install: apt-get install -y clevis clevis-luks clevis-tpm2 clevis-initramfs tpm2-tools tpm2-abrmd"
    exit 1
  fi
done

# TPM functional test
if ! tpm2_getrandom 8 &>/dev/null; then
  err "TPM2 is not accessible. Run check-tpm.sh for diagnostics."
  exit 1
fi
log "  TPM2 accessible."

# Secure Boot warning for PCR 7
if echo "${PCR_IDS}" | grep -q "7"; then
  SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "unknown")
  if ! echo "${SB_STATE}" | grep -qi "enabled"; then
    warn "Secure Boot is not enabled — PCR 7 binding may offer reduced protection."
    warn "PCR 7 will seal to the current (non-Secure-Boot) state."
    read -r -p "  Continue anyway? [y/N] " yn
    [[ "${yn,,}" == "y" ]] || exit 0
  else
    log "  Secure Boot: enabled (PCR 7 protection active)."
  fi
fi

# ── 2. Find LUKS device ────────────────────────────────────────────────────────
if [[ -z "$LUKS_DEVICE" ]]; then
  log "Auto-detecting LUKS device..."
  LUKS_DEVICE=$(lsblk -o NAME,FSTYPE -J 2>/dev/null | \
    python3 -c "
import sys, json
data = json.load(sys.stdin)
def find(devs):
    for d in devs:
        if d.get('fstype') == 'crypto_LUKS':
            print('/dev/' + d['name'])
            return
        find(d.get('children') or [])
find(data.get('blockdevices', []))
" || true)

  if [[ -z "$LUKS_DEVICE" ]]; then
    err "No LUKS device found. Specify with --device /dev/<partition>."
    echo "  List block devices: lsblk -o NAME,TYPE,FSTYPE"
    exit 1
  fi
  log "  Detected LUKS device: ${LUKS_DEVICE}"
fi

if ! cryptsetup isLuks "${LUKS_DEVICE}" 2>/dev/null; then
  err "${LUKS_DEVICE} is not a LUKS volume."
  exit 1
fi

# ── 3. Show current PCR values ────────────────────────────────────────────────
echo ""
log "Current PCR values (${PCR_BANK}) — these will be sealed:"
echo ""
tpm2_pcrread "${PCR_BANK}:${PCR_IDS}" 2>/dev/null | \
  awk '{printf "  %s\n", $0}'
echo ""

if $DRY_RUN; then
  warn "DRY RUN — no changes made."
  echo ""
  echo "  Would bind: ${LUKS_DEVICE}"
  echo "  PCR policy: ${PCR_BANK}:${PCR_IDS}"
  echo "  Tool:       clevis luks bind -d ${LUKS_DEVICE} tpm2 '{\"pcr_bank\":\"${PCR_BANK}\",\"pcr_ids\":\"${PCR_IDS}\"}'"
  exit 0
fi

# ── 4. Confirm ────────────────────────────────────────────────────────────────
echo "  About to seal LUKS key on ${LUKS_DEVICE} to TPM2 PCRs: ${PCR_IDS}"
echo "  After enrollment, the disk auto-unlocks only when the bootchain is unmodified."
echo ""
warn "If you update the kernel or firmware without running update-pcr.sh first,"
warn "you will need the LUKS passphrase to unlock manually on next boot."
echo ""
read -r -p "  Proceed with TPM2 enrollment? [y/N] " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Cancelled."; exit 0; }

# ── 5. Check for existing clevis binding ──────────────────────────────────────
EXISTING_SLOTS=$(clevis luks list -d "${LUKS_DEVICE}" 2>/dev/null | grep "tpm2" | awk '{print $1}' | tr -d ':' || true)
if [[ -n "$EXISTING_SLOTS" ]]; then
  warn "Existing TPM2 clevis binding found in slot(s): ${EXISTING_SLOTS}"
  read -r -p "  Remove existing binding and re-enroll? [y/N] " re_enroll
  if [[ "${re_enroll,,}" == "y" ]]; then
    for slot in $EXISTING_SLOTS; do
      log "  Removing existing binding (slot ${slot})..."
      clevis luks unbind -f -d "${LUKS_DEVICE}" -s "${slot}"
    done
  else
    info "Keeping existing binding and adding a new one."
  fi
fi

# ── 6. Enroll ─────────────────────────────────────────────────────────────────
log "Sealing LUKS key to TPM2 PCRs ${PCR_IDS} (${PCR_BANK})..."
log "  You will be prompted for the current LUKS passphrase."
echo ""

CLEVIS_CONFIG="{\"pcr_bank\":\"${PCR_BANK}\",\"pcr_ids\":\"${PCR_IDS}\"}"
clevis luks bind -d "${LUKS_DEVICE}" tpm2 "${CLEVIS_CONFIG}"

log "Enrollment complete."
NEW_SLOT=$(clevis luks list -d "${LUKS_DEVICE}" 2>/dev/null | grep "tpm2" | tail -1 | awk '{print $1}' | tr -d ':')
log "  Clevis slot: ${NEW_SLOT}"

# ── 7. Record enrollment metadata ────────────────────────────────────────────
RECORD_DIR="/etc/bas-tpm"
mkdir -p "${RECORD_DIR}"
chmod 700 "${RECORD_DIR}"
RECORD_FILE="${RECORD_DIR}/enrollment.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Capture sealed PCR values for future comparison
PCR_VALUES=$(tpm2_pcrread "${PCR_BANK}:${PCR_IDS}" 2>/dev/null | \
  grep -oP '0x[0-9A-Fa-f]+' | paste -sd ',' -)

python3 - <<PYEOF
import json, os

record = {
    "enrolled_at": "${TIMESTAMP}",
    "device": "${LUKS_DEVICE}",
    "pcr_bank": "${PCR_BANK}",
    "pcr_ids": "${PCR_IDS}",
    "pcr_values_at_enrollment": "${PCR_VALUES}",
    "clevis_slot": "${NEW_SLOT}",
    "kernel": "$(uname -r)",
    "hostname": "$(hostname)"
}

with open("${RECORD_FILE}", "w") as f:
    json.dump(record, f, indent=2)
os.chmod("${RECORD_FILE}", 0o600)
print(f"  Enrollment record: ${RECORD_FILE}")
PYEOF

# ── 8. Rebuild initramfs ──────────────────────────────────────────────────────
log "Rebuilding initramfs (enables auto-unlock at boot)..."
update-initramfs -u -k all 2>/dev/null

# ── 9. Verify the binding works ───────────────────────────────────────────────
log "Verifying binding..."
if clevis luks list -d "${LUKS_DEVICE}" 2>/dev/null | grep -q "tpm2"; then
  log "  Clevis TPM2 binding confirmed."
else
  err "Binding verification failed — check clevis luks list -d ${LUKS_DEVICE}"
  exit 1
fi

# ── 10. Summary ───────────────────────────────────────────────────────────────
echo ""
log "TPM2 enrollment complete."
echo ""
echo "  Device:       ${LUKS_DEVICE}"
echo "  PCR policy:   ${PCR_BANK}:${PCR_IDS}"
echo "  Clevis slot:  ${NEW_SLOT}"
echo "  Record:       ${RECORD_FILE}"
echo ""
echo "  On next boot: disk will unlock automatically via TPM2."
echo ""
warn "IMPORTANT — Before any kernel or firmware update:"
echo "  Run: sudo bash $(dirname "$0")/update-pcr.sh"
echo "  This re-seals the key to the new PCR values after the update."
echo ""
info "To manually verify boot integrity at any time:"
echo "  sudo bash $(dirname "$0")/verify-boot.sh"
