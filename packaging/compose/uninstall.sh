#!/usr/bin/env bash
# BAS Platform — Uninstaller
# Removes containers, volumes, images, systemd service, and install directory,
# then verifies every item was actually gone.
#
# Usage: sudo bash uninstall.sh [--purge-images] [--yes]
#   --purge-images   Also remove Docker images
#   --yes / -y       Skip confirmation prompt
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
step() { echo -e "\n${BOLD}──${NC} $*"; }

PURGE_IMAGES=false
YES=false
for arg in "$@"; do
  case "$arg" in
    --purge-images) PURGE_IMAGES=true ;;
    --yes|-y)       YES=true ;;
  esac
done

# ── Must run as root ──────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "Run with sudo: sudo bash $0 $*"
  exit 1
fi

# ── Detect install directory from systemd unit ────────────────────────────────
readonly SERVICE_UNIT="/etc/systemd/system/bas-compose.service"
INSTALL_DIR="/opt/bas-platform"
if [[ -f "$SERVICE_UNIT" ]]; then
  detected=$(grep -Po '(?<=WorkingDirectory=)[^\s]+' "$SERVICE_UNIT" || true)
  [[ -n "$detected" ]] && INSTALL_DIR="$detected"
fi
PROJECT="$(basename "$INSTALL_DIR")"

echo ""
echo -e "${RED}${BOLD}━━━  BAS Platform — Uninstaller  ━━━${NC}"
echo "  Install directory : $INSTALL_DIR"
echo "  Compose project   : $PROJECT"
echo "  Purge images      : $PURGE_IMAGES"
echo ""
echo "  The following will be PERMANENTLY DELETED:"
echo "    • Systemd service    bas-compose"
echo "    • Containers         bas-orchestrator  bas-caldera  bas-postgres"
echo "    • Docker volume      ${PROJECT}_bas-postgres-data  (ALL database data)"
echo "    • Docker network     ${PROJECT}_bas-internal"
if $PURGE_IMAGES; then
echo "    • Docker images      bas-orchestrator:*  postgres:16-alpine  ghcr.io/mitre/caldera:latest"
fi
echo "    • Install directory  $INSTALL_DIR"
echo ""

if ! $YES; then
  read -rp "  Type 'yes' to confirm complete removal: " confirm
  if [[ "$confirm" != "yes" ]]; then
    echo "Aborted."; exit 0
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# REMOVAL
# ═════════════════════════════════════════════════════════════════════════════

step "1/6  Stopping systemd service..."
if systemctl is-active --quiet bas-compose 2>/dev/null; then
  systemctl stop bas-compose && log "Service stopped." || warn "Failed to stop service (continuing)."
else
  warn "Service not active — skipping stop."
fi
if systemctl is-enabled --quiet bas-compose 2>/dev/null; then
  systemctl disable bas-compose && log "Service disabled." || warn "Failed to disable (continuing)."
fi
if [[ -f "$SERVICE_UNIT" ]]; then
  rm -f "$SERVICE_UNIT"
  systemctl daemon-reload
  log "Unit file removed."
fi

step "2/6  Removing containers..."
if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]]; then
  COMPOSE_ARGS="-f docker-compose.yml"
  [[ -f "${INSTALL_DIR}/docker-compose.prod.yml" ]] && COMPOSE_ARGS+=" -f docker-compose.prod.yml"
  (cd "${INSTALL_DIR}" && docker compose $COMPOSE_ARGS down --volumes --remove-orphans 2>&1) \
    && log "Compose stack torn down." || warn "Compose down had errors (continuing)."
else
  for ctr in bas-orchestrator bas-caldera bas-postgres; do
    if docker inspect "$ctr" &>/dev/null 2>&1; then
      docker rm -f "$ctr" && log "Removed: $ctr" || warn "Could not remove $ctr"
    else
      warn "Container $ctr not found — skipping."
    fi
  done
fi

step "3/6  Removing Docker volumes..."
for vol in "${PROJECT}_bas-postgres-data" "bas-postgres-data"; do
  if docker volume inspect "$vol" &>/dev/null 2>&1; then
    docker volume rm -f "$vol" && log "Removed volume: $vol" || warn "Could not remove: $vol"
  fi
done

step "4/6  Removing Docker network..."
for net in "${PROJECT}_bas-internal" "bas-internal"; do
  if docker network inspect "$net" &>/dev/null 2>&1; then
    docker network rm "$net" && log "Removed network: $net" || warn "Could not remove: $net"
  fi
done

step "5/6  Removing Docker images..."
if $PURGE_IMAGES; then
  while IFS= read -r img; do
    [[ -z "$img" ]] && continue
    docker rmi -f "$img" && log "Removed image: $img" || warn "Could not remove: $img"
  done < <(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^bas-orchestrator' || true)
  for img in "postgres:16-alpine" "ghcr.io/mitre/caldera:latest"; do
    if docker image inspect "$img" &>/dev/null 2>&1; then
      docker rmi -f "$img" && log "Removed image: $img" || warn "Could not remove: $img"
    fi
  done
else
  warn "Images retained (re-run with --purge-images to remove them)."
fi

step "6/6  Removing install directory..."
if [[ -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR" && log "Removed $INSTALL_DIR."
else
  warn "Directory not found — already removed."
fi

# ═════════════════════════════════════════════════════════════════════════════
# VERIFICATION
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}━━━  Verification  ━━━${NC}"
echo ""

PASS=true
ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
fail() { echo -e "  ${RED}✘${NC}  $*"; PASS=false; }

# Containers
for ctr in bas-orchestrator bas-caldera bas-postgres; do
  if docker inspect "$ctr" &>/dev/null 2>&1; then
    fail "Container still exists: $ctr"
  else
    ok "Container removed: $ctr"
  fi
done

# Volumes
for vol in "${PROJECT}_bas-postgres-data" "bas-postgres-data"; do
  if docker volume inspect "$vol" &>/dev/null 2>&1; then
    fail "Volume still exists: $vol"
  else
    ok "Volume removed: $vol"
  fi
done

# Network
for net in "${PROJECT}_bas-internal" "bas-internal"; do
  if docker network inspect "$net" &>/dev/null 2>&1; then
    fail "Network still exists: $net"
  else
    ok "Network removed: $net"
  fi
done

# Systemd service unit file
if [[ -f "$SERVICE_UNIT" ]]; then
  fail "Systemd unit still present: $SERVICE_UNIT"
else
  ok "Systemd unit removed"
fi

# Ports
for port in 9000 8888 5432; do
  if ss -tlnp 2>/dev/null | grep -q ":${port}"; then
    fail "Port $port still in use"
  else
    ok "Port $port free"
  fi
done

# Install directory
if [[ -d "$INSTALL_DIR" ]]; then
  fail "Install directory still present: $INSTALL_DIR"
else
  ok "Install directory removed: $INSTALL_DIR"
fi

# Images (only checked when --purge-images was requested)
if $PURGE_IMAGES; then
  for img in "postgres:16-alpine" "ghcr.io/mitre/caldera:latest"; do
    if docker image inspect "$img" &>/dev/null 2>&1; then
      fail "Image still present: $img"
    else
      ok "Image removed: $img"
    fi
  done
  if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q '^bas-orchestrator'; then
    fail "Image still present: bas-orchestrator:*"
  else
    ok "Image removed: bas-orchestrator:*"
  fi
fi

echo ""
if $PASS; then
  echo -e "${GREEN}${BOLD}✔  BAS Platform completely removed. All checks passed.${NC}"
else
  echo -e "${RED}${BOLD}✘  Uninstall incomplete — review the failures above.${NC}"
  exit 1
fi
echo ""
