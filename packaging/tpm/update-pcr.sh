#!/usr/bin/env bash
# BAS Platform — TPM2 PCR Policy Update
#
# Re-seals the LUKS key to updated PCR values after planned system changes
# (kernel upgrades, firmware updates, GRUB updates, Secure Boot cert rotation).
#
# WHEN to run this:
#   AFTER a kernel/firmware/GRUB update, on the FIRST reboot with the new
#   component.  At that point, the old clevis binding has already failed
#   (TPM refused to release the key) and you unlocked with the passphrase.
#   Run this script while the system is booted into the new kernel to re-seal.
#
# WORKFLOW for kernel upgrades:
#   1. (before upgrade) Note current LUKS passphrase — you will need it once
#   2. Run: apt-get upgrade  (installs new kernel)
#   3. Reboot — TPM binding FAILS (PCRs changed) — enter passphrase manually
#   4. After login, run: sudo bash update-pcr.sh
#   5. Subsequent boots: auto-unlock resumes
#
# Usage:
#   sudo bash packaging/tpm/update-pcr.sh [--device <dev>] [--pcrs <list>]
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Error: must be run as root." >&2
  exit 1
fi

RECORD_DIR="/etc/bas-tpm"
RECORD_FILE="${RECORD_DIR}/enrollment.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BLUE=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
info() { echo -e "${BLUE}[i]${NC} $*"; }

# ── Load enrollment record ────────────────────────────────────────────────────
LUKS_DEVICE=""
PCR_IDS="0,7"
PCR_BANK="sha256"
ENROLLED_KERNEL=""

if [[ -f "$RECORD_FILE" ]]; then
  LUKS_DEVICE=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('device',''))" 2>/dev/null || true)
  PCR_IDS=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('pcr_ids','0,7'))" 2>/dev/null || true)
  PCR_BANK=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('pcr_bank','sha256'))" 2>/dev/null || true)
  ENROLLED_KERNEL=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('kernel','unknown'))" 2>/dev/null || true)
  ENROLLED_AT=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('enrolled_at','unknown'))" 2>/dev/null || true)
  log "Loaded enrollment record from ${RECORD_FILE}"
  info "  Originally enrolled: ${ENROLLED_AT}"
  info "  Original kernel:     ${ENROLLED_KERNEL}"
  info "  Current kernel:      $(uname -r)"
else
  warn "No enrollment record found at ${RECORD_FILE}."
  warn "Using defaults — run enroll-pcr.sh for initial enrollment first."
fi

# Override with any command-line args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --device)   shift; LUKS_DEVICE="$1" ;;
    --pcrs)     shift; PCR_IDS="$1" ;;
    --pcr-bank) shift; PCR_BANK="$1" ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

if [[ -z "$LUKS_DEVICE" ]]; then
  err "No LUKS device found in enrollment record. Use --device /dev/<partition>."
  exit 1
fi

if ! cryptsetup isLuks "${LUKS_DEVICE}" 2>/dev/null; then
  err "${LUKS_DEVICE} is not a LUKS volume."
  exit 1
fi

if ! tpm2_getrandom 8 &>/dev/null; then
  err "TPM2 not accessible."
  exit 1
fi

# ── Show what changed ─────────────────────────────────────────────────────────
echo ""
log "New PCR values (${PCR_BANK}:${PCR_IDS}) that will be sealed:"
echo ""
tpm2_pcrread "${PCR_BANK}:${PCR_IDS}" 2>/dev/null | awk '{printf "  %s\n", $0}'
echo ""

if [[ "${ENROLLED_KERNEL}" != "$(uname -r)" ]]; then
  info "Kernel changed: ${ENROLLED_KERNEL} → $(uname -r)"
fi

read -r -p "  Re-seal LUKS key to current PCR values? [y/N] " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Cancelled."; exit 0; }

# ── Remove old TPM2 clevis bindings ───────────────────────────────────────────
log "Removing old TPM2 clevis binding(s)..."
OLD_SLOTS=$(clevis luks list -d "${LUKS_DEVICE}" 2>/dev/null | grep "tpm2" | awk '{print $1}' | tr -d ':' || true)
if [[ -n "$OLD_SLOTS" ]]; then
  for slot in $OLD_SLOTS; do
    log "  Unbinding slot ${slot}..."
    clevis luks unbind -f -d "${LUKS_DEVICE}" -s "${slot}" 2>/dev/null || true
  done
else
  warn "No existing TPM2 bindings found on ${LUKS_DEVICE} — creating fresh enrollment."
fi

# ── Re-enroll with current PCR values ─────────────────────────────────────────
log "Re-sealing to current PCR values (you will be prompted for the LUKS passphrase)..."
CLEVIS_CONFIG="{\"pcr_bank\":\"${PCR_BANK}\",\"pcr_ids\":\"${PCR_IDS}\"}"
clevis luks bind -d "${LUKS_DEVICE}" tpm2 "${CLEVIS_CONFIG}"

NEW_SLOT=$(clevis luks list -d "${LUKS_DEVICE}" 2>/dev/null | grep "tpm2" | tail -1 | awk '{print $1}' | tr -d ':')
log "  New clevis slot: ${NEW_SLOT}"

# ── Update enrollment record ──────────────────────────────────────────────────
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PCR_VALUES=$(tpm2_pcrread "${PCR_BANK}:${PCR_IDS}" 2>/dev/null | grep -oP '0x[0-9A-Fa-f]+' | paste -sd ',' -)

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
    "hostname": "$(hostname)",
    "updated_from_kernel": "${ENROLLED_KERNEL}"
}

# Keep history of previous enrollments
history_file = "${RECORD_DIR}/enrollment-history.json"
history = []
try:
    history = json.load(open(history_file))
except Exception:
    pass

# Archive the old record before overwriting
try:
    old = json.load(open("${RECORD_FILE}"))
    history.append(old)
except Exception:
    pass

with open(history_file, "w") as f:
    json.dump(history, f, indent=2)
os.chmod(history_file, 0o600)

with open("${RECORD_FILE}", "w") as f:
    json.dump(record, f, indent=2)
os.chmod("${RECORD_FILE}", 0o600)

print(f"  Record updated: ${RECORD_FILE}")
print(f"  History appended: {history_file}")
PYEOF

# ── Rebuild initramfs ─────────────────────────────────────────────────────────
log "Rebuilding initramfs..."
update-initramfs -u -k all 2>/dev/null

echo ""
log "PCR policy updated successfully."
echo ""
echo "  Device:      ${LUKS_DEVICE}"
echo "  PCR policy:  ${PCR_BANK}:${PCR_IDS}"
echo "  Slot:        ${NEW_SLOT}"
echo "  Kernel:      $(uname -r)"
echo ""
echo "  Reboot to confirm auto-unlock works with the new PCR values."
