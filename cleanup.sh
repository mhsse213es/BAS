#!/usr/bin/env bash
# Audspect BAS — Full cleanup for fresh reinstall
# Usage: sudo bash cleanup.sh [--purge-images] [--yes]
#   --purge-images   Also remove all BAS Docker images (frees ~2-4 GB)
#   --yes / -y       Skip confirmation prompt
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
fail() { echo -e "  ${RED}✘${NC}  $*"; PASS=false; }

PURGE_IMAGES=false
YES=false
for arg in "$@"; do
  case "$arg" in
    --purge-images) PURGE_IMAGES=true ;;
    --yes|-y)       YES=true ;;
  esac
done

[[ $EUID -ne 0 ]] && { err "Run with sudo: sudo bash $0 $*"; exit 1; }

# ── Detect install directory ──────────────────────────────────────────────────
# Prefer the systemd unit's WorkingDirectory; fall back to /opt/audspect.
INSTALL_DIR="/opt/audspect"
SVC_UNIT="/etc/systemd/system/audspect.service"
if [[ -f "$SVC_UNIT" ]]; then
  detected=$(grep -Po '(?<=WorkingDirectory=)[^\s]+' "$SVC_UNIT" 2>/dev/null || true)
  [[ -n "$detected" ]] && INSTALL_DIR="$detected"
fi

echo ""
echo -e "${RED}${BOLD}━━━  Audspect BAS — Full Cleanup  ━━━${NC}"
echo "  Install directory : ${INSTALL_DIR}"
echo "  Purge images      : ${PURGE_IMAGES}"
echo ""
echo "  This will permanently delete:"
echo "    • Systemd service   audspect"
echo "    • Containers        audspect-orchestrator  audspect-caldera"
echo "                        audspect-postgres       audspect-chrome"
echo "    • All BAS volumes   (ALL database data will be lost)"
echo "    • BAS networks"
if $PURGE_IMAGES; then
echo "    • Docker images     bas-orchestrator:*  bas-caldera:*"
echo "                        postgres:16-alpine  chromedp/headless-shell:latest"
fi
echo "    • Install directory ${INSTALL_DIR}"
echo ""

if ! $YES; then
  read -rp "  Type 'yes' to confirm: " confirm
  [[ "$confirm" != "yes" ]] && { echo "Aborted."; exit 0; }
fi

# ── 1. Stop systemd service ───────────────────────────────────────────────────
echo -e "\n${BOLD}── 1/6  Stopping systemd service${NC}"
for action in stop disable; do
  systemctl "$action" audspect 2>/dev/null && log "Service ${action}d." || warn "Service not ${action}able (may not be installed)."
done
if [[ -f "$SVC_UNIT" ]]; then
  rm -f "$SVC_UNIT"
  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null || true
  log "Unit file removed."
fi

# ── 2. Tear down compose stack ────────────────────────────────────────────────
# Using docker compose down -v handles container + volume + network cleanup in
# one shot, regardless of the compose project name used at install time.
echo -e "\n${BOLD}── 2/6  Tearing down compose stack${NC}"
for compose_dir in "$INSTALL_DIR" "$(pwd)"; do
  if [[ -f "${compose_dir}/docker-compose.yml" ]]; then
    (cd "${compose_dir}" && docker compose -p audspect down --volumes --remove-orphans 2>&1) \
      && log "Compose stack (project=audspect) torn down." && break \
      || warn "Compose down had warnings (continuing)."
  fi
done

# ── 3. Remove containers by name (belt-and-suspenders) ───────────────────────
echo -e "\n${BOLD}── 3/6  Removing containers${NC}"
for ctr in audspect-orchestrator audspect-caldera audspect-postgres audspect-chrome; do
  if docker inspect "$ctr" &>/dev/null; then
    docker rm -f "$ctr" && log "Removed container: $ctr" || warn "Could not remove: $ctr"
  else
    warn "Container not found: $ctr (already gone)"
  fi
done

# ── 4. Remove volumes ─────────────────────────────────────────────────────────
# Covers both project-prefixed variants (audspect_ and bas-install-*_)
echo -e "\n${BOLD}── 4/6  Removing volumes${NC}"
mapfile -t vols < <(docker volume ls --format '{{.Name}}' | grep -E 'audspect.*postgres|bas.*postgres' || true)
if [[ ${#vols[@]} -eq 0 ]]; then
  warn "No matching volumes found."
else
  for vol in "${vols[@]}"; do
    docker volume rm "$vol" && log "Removed volume: $vol" || warn "Could not remove: $vol"
  done
fi

# ── 5. Remove networks ────────────────────────────────────────────────────────
echo -e "\n${BOLD}── 5/6  Removing networks${NC}"
mapfile -t nets < <(docker network ls --format '{{.Name}}' | grep -E 'bas-internal|audspect.*internal' || true)
if [[ ${#nets[@]} -eq 0 ]]; then
  warn "No matching networks found."
else
  for net in "${nets[@]}"; do
    docker network rm "$net" && log "Removed network: $net" || warn "Could not remove: $net"
  done
fi

# ── 6. Remove Docker images ───────────────────────────────────────────────────
echo -e "\n${BOLD}── 6/6  Removing images${NC}"
if $PURGE_IMAGES; then
  mapfile -t imgs < <(docker images --format '{{.Repository}}:{{.Tag}}' \
    | grep -E '^bas-orchestrator:|^bas-caldera:' || true)
  for img in "${imgs[@]}" "postgres:16-alpine" "chromedp/headless-shell:latest"; do
    [[ -z "$img" ]] && continue
    if docker image inspect "$img" &>/dev/null; then
      docker rmi -f "$img" && log "Removed image: $img" || warn "Could not remove: $img"
    fi
  done
  docker image prune -f && log "Dangling image layers pruned." || true
else
  warn "Images retained — rerun with --purge-images to free disk space."
fi

# ── Remove install directory ──────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR" && log "Removed: $INSTALL_DIR"
else
  warn "Install directory not found: $INSTALL_DIR"
fi

# ─────────────────────────────────────────────────────────────────────────────
# VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━  Verification  ━━━${NC}"
echo ""
PASS=true

for ctr in audspect-orchestrator audspect-caldera audspect-postgres audspect-chrome; do
  docker inspect "$ctr" &>/dev/null && fail "Container still exists: $ctr" || ok "Container removed: $ctr"
done

mapfile -t remaining_vols < <(docker volume ls --format '{{.Name}}' \
  | grep -E 'audspect.*postgres|bas.*postgres' || true)
if [[ ${#remaining_vols[@]} -eq 0 ]]; then
  ok "All BAS volumes removed"
else
  for v in "${remaining_vols[@]}"; do fail "Volume still exists: $v"; done
fi

mapfile -t remaining_nets < <(docker network ls --format '{{.Name}}' \
  | grep -E 'bas-internal|audspect.*internal' || true)
if [[ ${#remaining_nets[@]} -eq 0 ]]; then
  ok "All BAS networks removed"
else
  for n in "${remaining_nets[@]}"; do fail "Network still exists: $n"; done
fi

[[ -f "$SVC_UNIT" ]] && fail "Systemd unit still present" || ok "Systemd unit removed"

for port in 9443 8888 5432; do
  ss -tlnp 2>/dev/null | grep -q ":${port}" \
    && fail "Port ${port} still in use" \
    || ok "Port ${port} free"
done

[[ -d "$INSTALL_DIR" ]] && fail "Install directory still present: $INSTALL_DIR" || ok "Install directory removed"

echo ""
if $PASS; then
  echo -e "${GREEN}${BOLD}✔  Audspect BAS completely removed. Ready for fresh install.${NC}"
else
  echo -e "${RED}${BOLD}✘  Cleanup incomplete — review the failures above.${NC}"
  exit 1
fi
echo ""
