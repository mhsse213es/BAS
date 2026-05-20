#!/usr/bin/env bash
# BAS Platform — Boot Integrity Verifier
#
# Compares current TPM2 PCR values against the values sealed at enrollment time.
# Detects firmware, bootloader, kernel, or Secure Boot state changes that could
# indicate tampering or an unplanned system modification.
#
# Can be run:
#   • Manually:  sudo bash packaging/tpm/verify-boot.sh
#   • As a systemd service on every boot (installed by enroll-pcr.sh)
#   • From a monitoring agent to feed SIEM/SOC alerts
#
# Exit codes:
#   0  PCR values match enrollment — boot is clean
#   1  PCR values changed — tamper indicator or unplanned update
#   2  TPM/clevis unavailable — cannot verify
#
# Output:
#   /var/log/bas-tpm-verify.log  (machine-readable JSON, one record per run)
set -euo pipefail

RECORD_FILE="/etc/bas-tpm/enrollment.json"
LOG_FILE="/var/log/bas-tpm-verify.log"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BLUE=''; NC=''
fi
pass()  { echo -e "${GREEN}  [PASS]${NC} $*"; }
fail()  { echo -e "${RED}  [FAIL]${NC} $*"; }
warn()  { echo -e "${YELLOW}  [WARN]${NC} $*"; }
info()  { echo -e "${BLUE}  [INFO]${NC} $*"; }

OVERALL=0
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo "  BAS Platform — Boot Integrity Verification"
echo "  Timestamp: ${TIMESTAMP}"
echo ""

# ── Load enrollment record ────────────────────────────────────────────────────
if [[ ! -f "$RECORD_FILE" ]]; then
  echo "  ERROR: No enrollment record at ${RECORD_FILE}." >&2
  echo "  Run enroll-pcr.sh first."
  exit 2
fi

PCR_BANK=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('pcr_bank','sha256'))")
PCR_IDS=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('pcr_ids','0,7'))")
SEALED_KERNEL=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('kernel',''))")
ENROLLED_AT=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('enrolled_at',''))")
SEALED_PCR_CSV=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('pcr_values_at_enrollment',''))")
LUKS_DEVICE=$(python3 -c "import json; d=json.load(open('${RECORD_FILE}')); print(d.get('device',''))")

info "Enrolled:    ${ENROLLED_AT}"
info "Sealed PCRs: ${PCR_BANK}:${PCR_IDS}"
info "Sealed on:   ${SEALED_KERNEL}"

# ── 1. TPM availability ───────────────────────────────────────────────────────
echo ""
if command -v tpm2_getrandom &>/dev/null && tpm2_getrandom 8 &>/dev/null 2>&1; then
  pass "TPM2 accessible"
else
  fail "TPM2 not accessible"
  exit 2
fi

# ── 2. Kernel change detection ────────────────────────────────────────────────
CURRENT_KERNEL=$(uname -r)
if [[ "$CURRENT_KERNEL" == "$SEALED_KERNEL" ]]; then
  pass "Kernel unchanged: ${CURRENT_KERNEL}"
else
  warn "Kernel changed: sealed=${SEALED_KERNEL}  current=${CURRENT_KERNEL}"
  info "  If this was a planned upgrade, run: sudo bash update-pcr.sh"
  OVERALL=1
fi

# ── 3. PCR value comparison ───────────────────────────────────────────────────
echo ""
echo "  PCR Comparison (${PCR_BANK}:${PCR_IDS}):"
echo "  ─────────────────────────────────────────────────────────────────────"

if ! command -v tpm2_pcrread &>/dev/null; then
  warn "tpm2_pcrread not available — skipping PCR comparison"
else
  # Read current PCR values
  declare -A CURRENT_PCRS
  while IFS= read -r line; do
    pcr_num=$(echo "$line" | grep -oP '^\s*\d+' | tr -d ' ' || true)
    pcr_val=$(echo "$line" | grep -oP '0x[0-9A-Fa-f]+' | head -1 || true)
    [[ -n "$pcr_num" && -n "$pcr_val" ]] && CURRENT_PCRS["$pcr_num"]="$pcr_val"
  done < <(tpm2_pcrread "${PCR_BANK}:${PCR_IDS}" 2>/dev/null)

  # Compare with sealed values (stored as comma-separated hex values in order)
  IFS=',' read -ra SEALED_VALS <<< "$SEALED_PCR_CSV"
  IFS=',' read -ra PCR_ID_LIST <<< "$PCR_IDS"

  PCR_CHANGED=()
  for i in "${!PCR_ID_LIST[@]}"; do
    pcr_id="${PCR_ID_LIST[$i]}"
    sealed_val="${SEALED_VALS[$i]:-}"
    current_val="${CURRENT_PCRS[$pcr_id]:-unknown}"

    printf "  PCR %-3s  sealed: %-68s\n" "${pcr_id}" "${sealed_val}"
    printf "          current: %-68s" "${current_val}"

    if [[ -z "$sealed_val" ]]; then
      echo "  (no sealed value)"
    elif [[ "${current_val,,}" == "${sealed_val,,}" ]]; then
      echo -e "  ${GREEN}MATCH${NC}"
    else
      echo -e "  ${RED}CHANGED${NC}"
      PCR_CHANGED+=("$pcr_id")
      OVERALL=1
    fi
    echo ""
  done

  if [[ ${#PCR_CHANGED[@]} -eq 0 ]]; then
    pass "All PCR values match enrollment"
  else
    fail "PCR values changed: ${PCR_CHANGED[*]}"
    echo ""
    echo "  Possible causes:"
    for pcr_id in "${PCR_CHANGED[@]}"; do
      case "$pcr_id" in
        0) echo "    PCR 0: Firmware/BIOS was updated or tampered with" ;;
        4) echo "    PCR 4: Bootloader (GRUB) changed" ;;
        7) echo "    PCR 7: Secure Boot state changed (certs added/removed or SB toggled)" ;;
        8) echo "    PCR 8: GRUB kernel command line changed" ;;
        9) echo "    PCR 9: GRUB loaded different files (new kernel/initrd)" ;;
        *) echo "    PCR ${pcr_id}: Component measured by this PCR changed" ;;
      esac
    done
  fi
fi

# ── 4. Clevis binding health ──────────────────────────────────────────────────
echo ""
if [[ -n "$LUKS_DEVICE" ]] && command -v clevis &>/dev/null; then
  BINDING=$(clevis luks list -d "${LUKS_DEVICE}" 2>/dev/null | grep "tpm2" || true)
  if [[ -n "$BINDING" ]]; then
    pass "Clevis TPM2 binding present on ${LUKS_DEVICE}"
    echo "  ${BINDING}" | awk '{printf "  %s\n", $0}'
  else
    fail "No clevis TPM2 binding found on ${LUKS_DEVICE}"
    info "  Re-enroll with: sudo bash enroll-pcr.sh"
    OVERALL=1
  fi
fi

# ── 5. Check if disk was auto-unlocked this boot ──────────────────────────────
CLEVIS_LOG=$(journalctl -b -u clevis-luks-askpass.service 2>/dev/null || \
             journalctl -b --grep "clevis" 2>/dev/null | tail -5 || true)
if echo "${CLEVIS_LOG}" | grep -qi "success\|unlocked"; then
  pass "Disk auto-unlocked this boot via TPM2"
elif echo "${CLEVIS_LOG}" | grep -qi "fail\|error"; then
  warn "Clevis reported issues during boot unlock (disk may have been opened with passphrase)"
  OVERALL=1
else
  info "Clevis auto-unlock log not available (normal if running mid-session)"
fi

# ── 6. Secure Boot state ──────────────────────────────────────────────────────
echo ""
if command -v mokutil &>/dev/null; then
  SB=$(mokutil --sb-state 2>/dev/null || echo "unknown")
  if echo "$SB" | grep -qi "enabled"; then
    pass "Secure Boot: ${SB}"
  else
    warn "Secure Boot: ${SB} — PCR 7 protection reduced"
  fi
fi

# ── 7. Write machine-readable log ─────────────────────────────────────────────
python3 - <<PYEOF
import json, os

entry = {
    "timestamp": "${TIMESTAMP}",
    "result": "PASS" if ${OVERALL} == 0 else "FAIL",
    "kernel_current": "$(uname -r)",
    "kernel_sealed": "${SEALED_KERNEL}",
    "pcr_bank": "${PCR_BANK}",
    "pcr_ids": "${PCR_IDS}",
    "pcr_match": ${OVERALL} == 0,
    "hostname": "$(hostname)"
}

log_file = "${LOG_FILE}"
entries = []
try:
    entries = json.load(open(log_file))
except Exception:
    pass

entries.append(entry)
# Keep last 90 entries
entries = entries[-90:]

with open(log_file, "w") as f:
    json.dump(entries, f, indent=2)
os.chmod(log_file, 0o640)
PYEOF

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [[ $OVERALL -eq 0 ]]; then
  echo -e "${GREEN}  Boot integrity VERIFIED — system is in expected state.${NC}"
else
  echo -e "${RED}  Boot integrity CHECK FAILED — investigate PCR changes above.${NC}"
  echo ""
  echo "  If this was a planned change:"
  echo "    sudo bash $(dirname "$0")/update-pcr.sh"
  echo ""
  echo "  If this was unexpected:"
  echo "    Investigate immediately. Do not allow production traffic."
fi
echo "  Log: ${LOG_FILE}"
echo ""
exit $OVERALL
