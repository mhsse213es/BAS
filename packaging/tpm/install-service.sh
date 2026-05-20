#!/usr/bin/env bash
# BAS Platform — Install TPM2 verify-boot as a systemd service
#
# Installs verify-boot.sh to run on every boot and alert via wall + journal
# if PCR values change (tamper indicator).
#
# Usage:
#   sudo bash packaging/tpm/install-service.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Error: must be run as root." >&2; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

# Install verify script
log "Installing /usr/local/sbin/bas-tpm-verify..."
cp "${SCRIPT_DIR}/verify-boot.sh" /usr/local/sbin/bas-tpm-verify
chmod 0755 /usr/local/sbin/bas-tpm-verify

# Install alert script (broadcasts to all logged-in users on failure)
log "Installing /usr/local/sbin/bas-tpm-alert..."
cat > /usr/local/sbin/bas-tpm-alert <<'ALERT'
#!/usr/bin/env bash
# Called by bas-tpm-verify.service after verify-boot.sh completes
LOG="/var/log/bas-tpm-verify.log"
RESULT=$(python3 -c "
import json, sys
try:
    entries = json.load(open('${LOG}'))
    print(entries[-1].get('result','UNKNOWN'))
except:
    print('UNKNOWN')
" 2>/dev/null || echo "UNKNOWN")

if [[ "$RESULT" != "PASS" ]]; then
  wall <<'MSG'

  ╔═══════════════════════════════════════════════════════════════════╗
  ║  !! BAS PLATFORM — BOOT INTEGRITY ALERT !!                      ║
  ║                                                                   ║
  ║  TPM2 PCR values have changed since last enrollment.             ║
  ║  This may indicate firmware, bootloader, or kernel tampering.    ║
  ║                                                                   ║
  ║  Run: sudo bash /opt/bas-platform/tpm/verify-boot.sh             ║
  ║  If planned: sudo bash /opt/bas-platform/tpm/update-pcr.sh       ║
  ╚═══════════════════════════════════════════════════════════════════╝

MSG
  logger -t bas-tpm -p security.crit "BOOT INTEGRITY FAILURE: PCR values changed — possible tamper"
fi
ALERT
chmod 0755 /usr/local/sbin/bas-tpm-alert

# Install systemd service
log "Installing bas-tpm-verify.service..."
cp "${SCRIPT_DIR}/bas-tpm-verify.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable bas-tpm-verify.service

# Copy TPM scripts to /opt/bas-platform/tpm/ for easy access
mkdir -p /opt/bas-platform/tpm
cp "${SCRIPT_DIR}"/*.sh /opt/bas-platform/tpm/
chmod +x /opt/bas-platform/tpm/*.sh

log "TPM verify service installed and enabled."
echo ""
echo "  Service:    bas-tpm-verify.service (runs on every boot)"
echo "  Verify now: sudo bash ${SCRIPT_DIR}/verify-boot.sh"
echo "  Enroll:     sudo bash ${SCRIPT_DIR}/enroll-pcr.sh"
echo ""
warn "Enroll the LUKS key now if you haven't already:"
echo "  sudo bash ${SCRIPT_DIR}/enroll-pcr.sh"
