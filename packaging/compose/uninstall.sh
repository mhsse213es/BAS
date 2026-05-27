#!/usr/bin/env bash
# BAS Platform — Uninstaller
# Removes all containers, volumes, images, the systemd service, and the install directory.
#
# Usage: sudo bash uninstall.sh [--purge-images] [--yes]
#   --purge-images   Also remove Docker images (bas-orchestrator, postgres, caldera)
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

# Docker Compose project name = basename of install dir (Docker Compose default)
PROJECT="$(basename "$INSTALL_DIR")"

echo ""
echo -e "${RED}${BOLD}━━━  BAS Platform — Complete Uninstaller  ━━━${NC}"
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
    echo "Aborted."
    exit 0
  fi
fi

# ── 1. Stop + disable systemd service ─────────────────────────────────────────
step "Stopping systemd service..."
if systemctl is-active --quiet bas-compose 2>/dev/null; then
  systemctl stop bas-compose && log "Service stopped." || warn "Failed to stop service (continuing)."
else
  warn "Service bas-compose is not active — skipping stop."
fi
if systemctl is-enabled --quiet bas-compose 2>/dev/null; then
  systemctl disable bas-compose && log "Service disabled." || warn "Failed to disable service (continuing)."
fi
if [[ -f "$SERVICE_UNIT" ]]; then
  rm -f "$SERVICE_UNIT"
  systemctl daemon-reload
  log "Service unit removed and daemon reloaded."
fi

# ── 2. Docker Compose down (removes containers + project network + named volumes) ─
step "Bringing down Docker Compose stack..."
if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]]; then
  COMPOSE_ARGS="-f docker-compose.yml"
  [[ -f "${INSTALL_DIR}/docker-compose.prod.yml" ]] && COMPOSE_ARGS+=" -f docker-compose.prod.yml"
  (cd "${INSTALL_DIR}" && docker compose $COMPOSE_ARGS down --volumes --remove-orphans 2>&1) \
    && log "Compose stack torn down." \
    || warn "Compose down reported errors (continuing)."
else
  warn "No docker-compose.yml found — removing containers by name..."
  for ctr in bas-orchestrator bas-caldera bas-postgres; do
    if docker inspect "$ctr" &>/dev/null 2>&1; then
      docker rm -f "$ctr" && log "Removed container: $ctr" || warn "Could not remove $ctr"
    else
      warn "Container $ctr not found — skipping."
    fi
  done
fi

# ── 3. Remove named volumes (belt-and-suspenders — compose down covers these,
#       but the project prefix can differ if the user moved the directory) ───────
step "Removing Docker volumes..."
for vol in "${PROJECT}_bas-postgres-data" "bas-postgres-data"; do
  if docker volume inspect "$vol" &>/dev/null 2>&1; then
    docker volume rm -f "$vol" && log "Removed volume: $vol" || warn "Could not remove volume: $vol"
  else
    warn "Volume $vol not found — skipping."
  fi
done

# ── 4. Remove Docker network ──────────────────────────────────────────────────
step "Removing Docker network..."
for net in "${PROJECT}_bas-internal" "bas-internal"; do
  if docker network inspect "$net" &>/dev/null 2>&1; then
    docker network rm "$net" && log "Removed network: $net" \
      || warn "Could not remove network $net (may still have endpoints)."
  fi
done

# ── 5. Remove Docker images ───────────────────────────────────────────────────
if $PURGE_IMAGES; then
  step "Removing Docker images..."
  # Find all local bas-orchestrator image tags
  while IFS= read -r img; do
    [[ -z "$img" ]] && continue
    docker rmi -f "$img" && log "Removed image: $img" || warn "Could not remove image: $img"
  done < <(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^bas-orchestrator' || true)
  for img in "postgres:16-alpine" "ghcr.io/mitre/caldera:latest"; do
    if docker image inspect "$img" &>/dev/null 2>&1; then
      docker rmi -f "$img" && log "Removed image: $img" || warn "Could not remove image: $img"
    else
      warn "Image $img not found — skipping."
    fi
  done
else
  warn "Docker images retained. Re-run with --purge-images to also remove them."
fi

# ── 6. Remove install directory ───────────────────────────────────────────────
step "Removing install directory..."
if [[ -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR" && log "Removed ${INSTALL_DIR}."
else
  warn "Install directory not found — already removed."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}BAS Platform has been completely removed.${NC}"
echo ""
if ! $PURGE_IMAGES; then
  echo "  Docker images are still on disk. To also remove them:"
  echo "    sudo bash $(basename "$0") --purge-images --yes"
  echo ""
fi
