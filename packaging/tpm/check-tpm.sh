#!/usr/bin/env bash
# BAS Platform — TPM2 Health Check
#
# Verifies that a functional TPM 2.0 is present and reports its state.
# Run before enroll-pcr.sh to confirm TPM readiness.
#
# Usage:
#   bash packaging/tpm/check-tpm.sh
#
# Exit codes:
#   0  TPM2 present and functional
#   1  TPM2 missing, inaccessible, or unhealthy
set -euo pipefail

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BLUE=''; NC=''
fi
pass()  { echo -e "${GREEN}  [PASS]${NC} $*"; }
fail()  { echo -e "${RED}  [FAIL]${NC} $*"; FAIL=1; }
warn()  { echo -e "${YELLOW}  [WARN]${NC} $*"; }
info()  { echo -e "${BLUE}  [INFO]${NC} $*"; }

FAIL=0

echo ""
echo "  BAS Platform — TPM 2.0 Hardware Check"
echo ""

# ── 1. Kernel TPM device ──────────────────────────────────────────────────────
if ls /dev/tpm0 /dev/tpmrm0 &>/dev/null 2>&1; then
  pass "TPM character device found: $(ls /dev/tpm* 2>/dev/null | tr '\n' ' ')"
elif [[ -d /sys/class/tpm ]]; then
  pass "TPM present in sysfs: $(ls /sys/class/tpm/ | tr '\n' ' ')"
else
  fail "No TPM device found (/dev/tpm0 or /dev/tpmrm0 missing)"
  info "Check BIOS/UEFI settings — TPM may need to be enabled."
fi

# ── 2. tpm2-tools ─────────────────────────────────────────────────────────────
if command -v tpm2_getrandom &>/dev/null; then
  pass "tpm2-tools installed: $(tpm2_getrandom --version 2>/dev/null | head -1 || echo 'unknown version')"
else
  fail "tpm2-tools not installed"
  echo "       Install: apt-get install -y tpm2-tools tpm2-abrmd"
fi

# ── 3. tpm2-abrmd (resource manager) ──────────────────────────────────────────
if systemctl is-active --quiet tpm2-abrmd 2>/dev/null; then
  pass "tpm2-abrmd (resource manager) is running"
elif tpm2_getrandom 8 &>/dev/null 2>&1; then
  warn "tpm2-abrmd not running but TPM is directly accessible (kernel resource manager in use)"
  info "tpm2-abrmd improves multi-process TPM access — install for production."
else
  fail "tpm2-abrmd not running and TPM not accessible"
  echo "       Start: systemctl enable --now tpm2-abrmd"
fi

# ── 4. TPM random number generation (functional test) ─────────────────────────
RNG_OUTPUT=$(tpm2_getrandom 8 2>/dev/null | xxd | head -1 || echo "")
if [[ -n "$RNG_OUTPUT" ]]; then
  pass "TPM RNG functional"
else
  fail "TPM RNG not responding — TPM may be locked or malfunctioning"
fi

# ── 5. TPM2 properties ────────────────────────────────────────────────────────
echo ""
echo "  TPM2 Properties:"
if command -v tpm2_getcap &>/dev/null; then
  tpm2_getcap properties-fixed 2>/dev/null | grep -E "(TPM2_PT_MANUFACTURER|TPM2_PT_VENDOR_STRING|TPM2_PT_FIRMWARE_VERSION_1|TPM2_PT_PCR_COUNT)" | \
    awk '{printf "    %-40s %s\n", $1, $NF}' || true
fi

# ── 6. PCR banks available ────────────────────────────────────────────────────
echo ""
echo "  PCR Banks:"
if command -v tpm2_pcrread &>/dev/null; then
  BANKS=$(tpm2_pcrread 2>/dev/null | grep -oP '^\w+:' | sort -u | tr '\n' ' ')
  info "Available PCR banks: ${BANKS:-none detected}"
fi

# ── 7. Secure Boot state ──────────────────────────────────────────────────────
echo ""
echo "  Secure Boot:"
if command -v mokutil &>/dev/null; then
  SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "unknown")
  if echo "${SB_STATE}" | grep -qi "enabled"; then
    pass "Secure Boot: ${SB_STATE}"
    info "PCR 7 will reflect Secure Boot state — recommended to include in PCR policy."
  else
    warn "Secure Boot: ${SB_STATE}"
    info "PCR 7 will be zero without Secure Boot — consider enabling Secure Boot for PCR 7 binding."
  fi
elif [[ -d /sys/firmware/efi ]]; then
  info "UEFI firmware detected — Secure Boot status unknown (install mokutil for details)"
else
  info "Legacy BIOS boot detected — Secure Boot not available"
fi

# ── 8. clevis availability ────────────────────────────────────────────────────
echo ""
echo "  Clevis (LUKS binding):"
for pkg in clevis clevis-luks clevis-tpm2 clevis-initramfs; do
  if dpkg -l "$pkg" &>/dev/null 2>&1 | grep -q "^ii"; then
    pass "${pkg} installed"
  else
    warn "${pkg} not installed"
    echo "       Install: apt-get install -y clevis clevis-luks clevis-tpm2 clevis-initramfs"
  fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [[ $FAIL -eq 0 ]]; then
  echo -e "${GREEN}  TPM2 is present and functional — ready for enroll-pcr.sh${NC}"
else
  echo -e "${RED}  TPM2 checks failed — resolve issues above before enrolling.${NC}"
fi
echo ""
exit $FAIL
