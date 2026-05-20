#!/usr/bin/env bash
# BAS Platform — Uninstaller
set -euo pipefail

readonly SERVICE_NAME="bas-compose"
readonly DEFAULT_INSTALL_DIR="/opt/bas-platform"

if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
  err "This uninstaller must be run as root."
  echo "  Run: sudo bash $0"
  exit 1
fi

INSTALL_DIR="${1:-$DEFAULT_INSTALL_DIR}"

echo ""
echo "  BAS Platform Uninstaller"
echo "  Install directory: ${INSTALL_DIR}"
echo ""
read -r -p "  Remove BAS Platform? This stops all services. [y/N] " confirm
[[ "${confirm,,}" != "y" ]] && { echo "Cancelled."; exit 0; }

# Stop and disable systemd service
if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
  log "Stopping ${SERVICE_NAME} service..."
  systemctl stop "${SERVICE_NAME}"
fi
if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
  log "Disabling ${SERVICE_NAME} service..."
  systemctl disable "${SERVICE_NAME}"
fi
if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
  log "Removing systemd unit..."
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  systemctl daemon-reload
fi

# Bring down compose stack if install dir still exists
if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]]; then
  log "Bringing down Docker Compose stack..."
  cd "${INSTALL_DIR}"
  docker compose -f docker-compose.yml down --remove-orphans 2>/dev/null || true
fi

# Optionally remove persistent data volumes
echo ""
read -r -p "  Remove database volumes (ALL DATA WILL BE LOST)? [y/N] " rm_volumes
if [[ "${rm_volumes,,}" == "y" ]]; then
  log "Removing Docker volumes..."
  docker volume rm bas-postgres-data 2>/dev/null || true
fi

# Optionally remove install directory
echo ""
read -r -p "  Remove install directory ${INSTALL_DIR}? [y/N] " rm_dir
if [[ "${rm_dir,,}" == "y" ]]; then
  log "Removing ${INSTALL_DIR}..."
  rm -rf "${INSTALL_DIR}"
fi

log "BAS Platform has been removed."
