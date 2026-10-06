#!/usr/bin/env bash
# BAS Platform -Uninstaller
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
err()  { echo -e "${RED}[X]${NC} $*" >&2; }
step() { echo -e "\n${BOLD}--${NC} $*"; }

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
readonly SERVICE_UNIT="/etc/systemd/system/audspect.service"
INSTALL_DIR="/opt/audspect"
if [[ -f "$SERVICE_UNIT" ]]; then
  detected=$(grep -Po '(?<=WorkingDirectory=)[^\s]+' "$SERVICE_UNIT" || true)
  [[ -n "$detected" ]] && INSTALL_DIR="$detected"
fi

echo ""
echo -e "${RED}${BOLD}===  Audspect BAS -Uninstaller  ===${NC}"
echo "  Install directory : $INSTALL_DIR"
echo "  Purge images      : $PURGE_IMAGES"
echo ""
echo "  The following will be PERMANENTLY DELETED:"
echo "    • Systemd service    audspect"
echo "    • Containers         audspect-orchestrator  audspect-caldera"
echo "                         audspect-postgres       audspect-chrome"
echo "    • Docker volumes     (ALL database data)"
echo "    • Deployment CA      (every already-enrolled agent certificate becomes"
echo "                         invalid -- this is NOT just data loss, it locks out"
echo "                         the entire fleet until each agent is manually"
echo "                         re-bootstrapped against a new CA)"
echo "    • Docker network     audspect_bas-internal"
if $PURGE_IMAGES; then
echo "    • Docker images      bas-orchestrator:*  bas-caldera:*  postgres:16-alpine  chromedp/headless-shell:*"
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
for action in stop disable; do
  systemctl "$action" audspect 2>/dev/null && log "Service ${action}d." || warn "Service not ${action}able (may not be installed)."
done
if [[ -f "$SERVICE_UNIT" ]]; then
  rm -f "$SERVICE_UNIT"
  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null || true
  log "Unit file removed."
fi

step "2/6  Removing containers via compose..."
for compose_dir in "$INSTALL_DIR" "$(pwd)"; do
  if [[ -f "${compose_dir}/docker-compose.yml" ]]; then
    (cd "${compose_dir}" && docker compose -p audspect down --volumes --remove-orphans 2>&1) \
      && log "Compose stack torn down." && break \
      || warn "Compose down had warnings (continuing)."
  fi
done
for ctr in audspect-orchestrator audspect-caldera audspect-postgres audspect-chrome; do
  if docker inspect "$ctr" &>/dev/null 2>&1; then
    docker rm -f "$ctr" && log "Removed: $ctr" || warn "Could not remove $ctr"
  fi
done

step "3/6  Removing Docker volumes..."
mapfile -t vols < <(docker volume ls --format '{{.Name}}' | grep -E 'audspect.*postgres|bas.*postgres' || true)
for vol in "${vols[@]:-}"; do
  [[ -z "$vol" ]] && continue
  docker volume rm "$vol" && log "Removed volume: $vol" || warn "Could not remove: $vol"
done
[[ ${#vols[@]} -eq 0 ]] && warn "No matching volumes found."

step "4/6  Removing Docker network..."
mapfile -t nets < <(docker network ls --format '{{.Name}}' | grep -E 'bas-internal|audspect.*internal' || true)
for net in "${nets[@]:-}"; do
  [[ -z "$net" ]] && continue
  docker network rm "$net" && log "Removed network: $net" || warn "Could not remove: $net"
done
[[ ${#nets[@]} -eq 0 ]] && warn "No matching networks found."

step "5/6  Removing Docker images..."
if $PURGE_IMAGES; then
  mapfile -t imgs < <(docker images --format '{{.Repository}}:{{.Tag}}' \
    | grep -E '^bas-orchestrator:|^bas-caldera:' || true)
  for img in "${imgs[@]:-}" "postgres:16-alpine" "chromedp/headless-shell:latest" "chromedp/headless-shell:151.0.7922.109"; do
    [[ -z "$img" ]] && continue
    if docker image inspect "$img" &>/dev/null 2>&1; then
      docker rmi -f "$img" && log "Removed image: $img" || warn "Could not remove: $img"
    fi
  done
  docker image prune -f && log "Dangling layers pruned." || true
else
  warn "Images retained (re-run with --purge-images to remove them)."
fi

step "6/6  Removing install directory..."
if [[ -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR" && log "Removed $INSTALL_DIR."
else
  warn "Directory not found -already removed."
fi

# ═════════════════════════════════════════════════════════════════════════════
# VERIFICATION
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}===  Verification  ===${NC}"
echo ""

PASS=true
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
fail() { echo -e "  ${RED}[X]${NC}  $*"; PASS=false; }

# Containers
for ctr in audspect-orchestrator audspect-caldera audspect-postgres audspect-chrome; do
  docker inspect "$ctr" &>/dev/null 2>&1 \
    && fail "Container still exists: $ctr" \
    || ok  "Container removed: $ctr"
done

# Volumes
mapfile -t remaining_vols < <(docker volume ls --format '{{.Name}}' \
  | grep -E 'audspect.*postgres|bas.*postgres' || true)
[[ ${#remaining_vols[@]} -eq 0 ]] \
  && ok "All BAS volumes removed" \
  || { for v in "${remaining_vols[@]}"; do fail "Volume still exists: $v"; done; }

# Networks
mapfile -t remaining_nets < <(docker network ls --format '{{.Name}}' \
  | grep -E 'bas-internal|audspect.*internal' || true)
[[ ${#remaining_nets[@]} -eq 0 ]] \
  && ok "All BAS networks removed" \
  || { for n in "${remaining_nets[@]}"; do fail "Network still exists: $n"; done; }

# Systemd service unit file
[[ -f "$SERVICE_UNIT" ]] \
  && fail "Systemd unit still present: $SERVICE_UNIT" \
  || ok  "Systemd unit removed"

# Ports
for port in 9443 8888 5432; do
  ss -tlnp 2>/dev/null | grep -q ":${port}" \
    && fail "Port $port still in use" \
    || ok  "Port $port free"
done

# Install directory
[[ -d "$INSTALL_DIR" ]] \
  && fail "Install directory still present: $INSTALL_DIR" \
  || ok  "Install directory removed: $INSTALL_DIR"

# Images (only checked when --purge-images was requested)
if $PURGE_IMAGES; then
  for img in "postgres:16-alpine" "chromedp/headless-shell:latest" "chromedp/headless-shell:151.0.7922.109"; do
    docker image inspect "$img" &>/dev/null 2>&1 \
      && fail "Image still present: $img" \
      || ok  "Image removed: $img"
  done
  docker images --format '{{.Repository}}:{{.Tag}}' | grep -q '^bas-orchestrator' \
    && fail "Image still present: bas-orchestrator:*" \
    || ok  "Image removed: bas-orchestrator:*"
  docker images --format '{{.Repository}}:{{.Tag}}' | grep -q '^bas-caldera' \
    && fail "Image still present: bas-caldera:*" \
    || ok  "Image removed: bas-caldera:*"
fi

echo ""
if $PASS; then
  echo -e "${GREEN}${BOLD}[OK]  BAS Platform completely removed. All checks passed.${NC}"
else
  echo -e "${RED}${BOLD}[X]  Uninstall incomplete -review the failures above.${NC}"
  exit 1
fi
echo ""
