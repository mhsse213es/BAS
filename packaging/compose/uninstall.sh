#!/usr/bin/env bash
# BAS Platform - Uninstaller.
#
#   sudo bash uninstall.sh                run it; it shows what it found and asks you to type "yes"
#   sudo bash uninstall.sh --yes          no question (scripted use)
#
# It finds the install directory itself, removes everything BAS put on this server (containers, database, deployment
# CA and signing key, secrets, backups, the systemd service and the backup timers, the Docker network), and then checks
# that it is really gone. It can be run again at any time: a half-removed install is finished, a clean server is a no-op.
#
# Options
#   --yes, -y            do not ask for confirmation
#   --dry-run            show what would be removed and change nothing
#   --backup-to DIR      first save the parts that cannot be recreated (deployment CA, signing key, .env) to
#                        DIR/audspect-final-backup-<time>.tar.gz (mode 600). Nothing is deleted if that fails.
#   --purge-images       also remove the BAS Docker images
#   --data-dir DIR       use this install directory instead of detecting it (it must look like a BAS install)
#
# NOT removed: other applications' containers, volumes, networks and images; firewall (ufw) rules; the folder you
# unpacked the installer from, and its setup.conf.
#
# What a fresh install after this means: a NEW deployment CA, signing key and agent secret. Every enrolled agent stops
# working and must be uninstalled and installed again.
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[X]${NC} $*" >&2; }
step() { echo -e "\n${BOLD}--${NC} $*"; }

SYSTEMD_DIR="${BAS_SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_UNIT="${SYSTEMD_DIR}/audspect.service"
PROJECT="audspect"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

YES=false; DRY=false; PURGE_IMAGES=false; BACKUP_TO=""; EXPLICIT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)        YES=true ;;
    --dry-run)       DRY=true ;;
    --purge-images)  PURGE_IMAGES=true ;;
    --backup-to)     BACKUP_TO="${2:-}"; shift ;;
    --backup-to=*)   BACKUP_TO="${1#--backup-to=}" ;;
    --data-dir)      EXPLICIT_DIR="${2:-}"; shift ;;
    --data-dir=*)    EXPLICIT_DIR="${1#--data-dir=}" ;;
    -h|--help)       sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)               err "Unknown option: $1 (see --help)"; exit 2 ;;
  esac
  shift
done

if [[ "$(id -u)" -ne 0 ]]; then
  err "Run with sudo: sudo bash $0 $*"
  exit 1
fi

# ── Is Docker usable? Everything that does not need it is still removed if it is not. ──────────────────────────
DOCKER_OK=false
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then DOCKER_OK=true; fi
$DOCKER_OK || warn "Docker is not available or not running: containers, volumes, networks and images cannot be checked or removed."

# ── Which directory is the install? ─────────────────────────────────────────────────────────────────────────────
# A directory qualifies only if it is not a system location and looks like a BAS install.
looks_like_install() {
  local d="$1"
  [[ -d "$d" ]] || return 1
  [[ -f "$d/docker-compose.yml" || -f "$d/.env" || -d "$d/pki" || -d "$d/data/postgres" ]]
}

is_protected() {
  local d; d="$(realpath -m "$1" 2>/dev/null || echo "$1")"
  case "$d" in
    ""|/|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var) return 0 ;;
  esac
  [[ -n "${HOME:-}" && "$d" == "$(realpath -m "$HOME" 2>/dev/null || echo "$HOME")" ]] && return 0
  return 1
}

detect_install_dir() {
  local c d
  local -a candidates=()
  # 1. the systemd unit
  if [[ -f "$SERVICE_UNIT" ]]; then
    d="$(sed -n 's/^[[:space:]]*WorkingDirectory=[[:space:]]*//p' "$SERVICE_UNIT" 2>/dev/null | head -1 | sed 's/[[:space:]]*$//')"; [[ -n "$d" ]] && candidates+=("$d")
  fi
  # 2. where the running (or stopped) orchestrator keeps its CA: <install dir>/pki
  if $DOCKER_OK; then
    d="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/audspect/pki"}}{{.Source}}{{end}}{{end}}' audspect-orchestrator 2>/dev/null || true)"
    [[ -n "$d" ]] && candidates+=("$(dirname "$d")")
  fi
  # 3. the DATA_DIR in a setup.conf next to this script or in the current folder
  for c in "$SCRIPT_DIR/setup.conf" "$PWD/setup.conf"; do
    [[ -f "$c" ]] || continue
    d="$(grep -E '^[[:space:]]*DATA_DIR=' "$c" 2>/dev/null | tail -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//')"
    [[ -n "$d" ]] && candidates+=("$d")
  done
  # 4. the default
  candidates+=("/opt/audspect")
  for c in "${candidates[@]}"; do
    if ! is_protected "$c" && looks_like_install "$c"; then echo "$c"; return 0; fi
  done
  return 1
}

INSTALL_DIR=""
if [[ -n "$EXPLICIT_DIR" ]]; then
  if is_protected "$EXPLICIT_DIR"; then
    err "Refusing to remove '$EXPLICIT_DIR': it is a system or personal location, not a BAS install directory."
    exit 1
  fi
  if ! looks_like_install "$EXPLICIT_DIR"; then
    err "'$EXPLICIT_DIR' does not look like a BAS install (no docker-compose.yml, .env, pki or data/postgres inside). Nothing was changed."
    exit 1
  fi
  INSTALL_DIR="$EXPLICIT_DIR"
else
  INSTALL_DIR="$(detect_install_dir || true)"
fi

# ── What exists? ────────────────────────────────────────────────────────────────────────────────────────────────
mapfile -t CONTAINERS < <($DOCKER_OK && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^audspect-' || true)
mapfile -t VOLUMES    < <($DOCKER_OK && docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E '^audspect[_-]' || true)
mapfile -t NETWORKS   < <($DOCKER_OK && docker network ls --format '{{.Name}}' 2>/dev/null | grep -E '^audspect[_-]' || true)
mapfile -t IMAGES     < <($DOCKER_OK && $PURGE_IMAGES && docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '^(bas-orchestrator|bas-caldera|audspect-)' || true)
UNITS=()
for u in audspect.service audspect-backup-worker.service audspect-backup-worker.timer audspect-backup-schedule.service audspect-backup-schedule.timer; do
  [[ -e "$SYSTEMD_DIR/$u" ]] && UNITS+=("$u")
done

# Ports this install published, read before the .env is deleted.
PORTS=()
if [[ -n "$INSTALL_DIR" && -f "$INSTALL_DIR/.env" ]]; then
  mapfile -t PORTS < <(grep -E '^[A-Z_]*PORT=[0-9]+' "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2 | sort -u)
fi

NOTHING=true
[[ -n "$INSTALL_DIR" || ${#CONTAINERS[@]} -gt 0 || ${#VOLUMES[@]} -gt 0 || ${#NETWORKS[@]} -gt 0 || ${#IMAGES[@]} -gt 0 || ${#UNITS[@]} -gt 0 ]] && NOTHING=false

if $NOTHING; then
  echo ""
  log "Nothing to remove: no BAS install directory, containers, volumes, network or services were found. This server is clean."
  exit 0
fi

echo ""
echo -e "${RED}${BOLD}===  Audspect BAS - Uninstaller  ===${NC}"
echo ""
if [[ -n "$INSTALL_DIR" ]]; then
  size="$(du -sh "$INSTALL_DIR" 2>/dev/null | cut -f1)"
  echo "  Install directory : $INSTALL_DIR  (${size:-?})"
else
  echo "  Install directory : none found (only the items below will be removed)"
fi
echo "  The following will be PERMANENTLY DELETED:"
[[ -n "$INSTALL_DIR" ]] && {
  echo "    - the database (every agent, run, report, user and audit record)"
  echo "    - the deployment CA and the command-signing key: every already-enrolled agent is locked out until it is"
  echo "      uninstalled and installed again against the new CA"
  echo "    - .env (the agent secret and all settings), backups, logs"
}
((${#UNITS[@]}))      && echo "    - systemd units:   ${UNITS[*]}"
((${#CONTAINERS[@]})) && echo "    - containers:      ${CONTAINERS[*]}"
((${#VOLUMES[@]}))    && echo "    - Docker volumes:  ${VOLUMES[*]}"
((${#NETWORKS[@]}))   && echo "    - Docker networks: ${NETWORKS[*]}"
((${#IMAGES[@]}))     && echo "    - Docker images:   ${IMAGES[*]}"
echo "  Not touched: other applications' containers/volumes/networks/images, firewall rules, your installer folder."
[[ -n "$BACKUP_TO" ]] && echo "  A backup of the CA, signing key and .env is saved to: $BACKUP_TO"
echo ""

if $DRY; then
  warn "Dry run: nothing was changed."
  exit 0
fi

if ! $YES; then
  confirm=""
  read -r -p "  Type 'yes' to confirm complete removal: " confirm || true
  if [[ -z "$confirm" ]]; then
    err "No answer was given (not an interactive terminal?). Nothing was changed. Run again with --yes to confirm in advance."
    exit 1
  fi
  if [[ "$confirm" != "yes" ]]; then
    echo "Aborted. Nothing was changed."; exit 0
  fi
fi

# ── Back up what cannot be recreated, and stop if that fails ────────────────────────────────────────────────────
if [[ -n "$BACKUP_TO" ]]; then
  if [[ -z "$INSTALL_DIR" ]]; then
    err "--backup-to was given but there is no install directory to back up. Nothing was changed."; exit 1
  fi
  if [[ ! -d "$BACKUP_TO" ]] || [[ ! -w "$BACKUP_TO" ]]; then
    err "Backup folder '$BACKUP_TO' does not exist or cannot be written. Nothing was changed."; exit 1
  fi
  ARCHIVE="$BACKUP_TO/audspect-final-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
  items=()
  for i in pki signing .env; do [[ -e "$INSTALL_DIR/$i" ]] && items+=("$i"); done
  if ! (umask 077 && tar -czf "$ARCHIVE" -C "$INSTALL_DIR" "${items[@]}") || ! tar -tzf "$ARCHIVE" >/dev/null 2>&1; then
    rm -f "$ARCHIVE"
    err "The backup could not be written. Nothing was changed."; exit 1
  fi
  chmod 600 "$ARCHIVE"
  log "Backup saved: $ARCHIVE  (holds the CA private key and secrets: keep it safe)"
fi

# ════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# REMOVAL: every step is attempted whatever happened before; the verification below decides the outcome.
# ════════════════════════════════════════════════════════════════════════════════════════════════════════════════
step "1/6  Stopping and removing the services"
systemctl stop audspect-backup-worker.timer audspect-backup-schedule.timer >/dev/null 2>&1 || true
systemctl stop audspect >/dev/null 2>&1 || true
systemctl disable audspect audspect-backup-worker.timer audspect-backup-schedule.timer >/dev/null 2>&1 || true
for u in "${UNITS[@]:-}"; do
  [[ -z "$u" ]] && continue
  rm -f "$SYSTEMD_DIR/$u" && log "Removed unit: $u"
done
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed >/dev/null 2>&1 || true

step "2/6  Removing containers"
if $DOCKER_OK; then
  if [[ -n "$INSTALL_DIR" && -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    (cd "$INSTALL_DIR" && docker compose -p "$PROJECT" down --volumes --remove-orphans >/dev/null 2>&1) \
      && log "Compose stack removed." || warn "Compose down reported problems; removing the containers directly."
  fi
  for c in "${CONTAINERS[@]:-}"; do
    [[ -z "$c" ]] && continue
    docker rm -f "$c" >/dev/null 2>&1 && log "Removed container: $c" || warn "Could not remove container: $c"
  done
else
  warn "Skipped (Docker unavailable)."
fi

step "3/6  Removing Docker volumes"
if $DOCKER_OK; then
  for v in "${VOLUMES[@]:-}"; do
    [[ -z "$v" ]] && continue
    docker volume rm "$v" >/dev/null 2>&1 && log "Removed volume: $v" || warn "Could not remove volume: $v"
  done
fi

step "4/6  Removing Docker networks"
if $DOCKER_OK; then
  for n in "${NETWORKS[@]:-}"; do
    [[ -z "$n" ]] && continue
    docker network rm "$n" >/dev/null 2>&1 && log "Removed network: $n" || warn "Could not remove network: $n"
  done
fi

step "5/6  Removing Docker images"
if $DOCKER_OK && $PURGE_IMAGES; then
  for i in "${IMAGES[@]:-}"; do
    [[ -z "$i" ]] && continue
    docker rmi -f "$i" >/dev/null 2>&1 && log "Removed image: $i" || warn "Could not remove image: $i"
  done
  docker image prune -f >/dev/null 2>&1 || true
else
  warn "Images kept (add --purge-images to remove them)."
fi

step "6/6  Removing the install directory"
if [[ -n "$INSTALL_DIR" && -d "$INSTALL_DIR" ]]; then
  # re-check right before deleting: never remove a protected or unrelated location
  if is_protected "$INSTALL_DIR"; then
    err "Refusing to remove '$INSTALL_DIR' (protected location)."
  else
    cd / || true   # this script may live inside the directory being removed
    rm -rf -- "$INSTALL_DIR" 2>/dev/null
    if [[ -e "$INSTALL_DIR" ]]; then
      command -v chattr >/dev/null 2>&1 && chattr -R -i "$INSTALL_DIR" >/dev/null 2>&1 || true
      rm -rf -- "$INSTALL_DIR" 2>/dev/null
    fi
    [[ -e "$INSTALL_DIR" ]] || log "Removed $INSTALL_DIR."
  fi
else
  warn "No install directory to remove."
fi

# ════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# VERIFICATION
# ════════════════════════════════════════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}===  Verification  ===${NC}"
echo ""
PASS=true
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
fail() { echo -e "  ${RED}[X]${NC}  $*"; PASS=false; }

if [[ -n "$INSTALL_DIR" ]]; then
  [[ ! -e "$INSTALL_DIR" ]] && ok "Install directory removed: $INSTALL_DIR" || fail "Install directory still present: $INSTALL_DIR"
  [[ ! -e "$INSTALL_DIR/pki" ]] && ok "Deployment CA removed" || fail "Deployment CA still present: $INSTALL_DIR/pki"
  [[ ! -e "$INSTALL_DIR/data/postgres" ]] && ok "Database files removed" || fail "Database files still present: $INSTALL_DIR/data/postgres"
fi

for u in audspect.service audspect-backup-worker.service audspect-backup-worker.timer audspect-backup-schedule.service audspect-backup-schedule.timer; do
  [[ ! -e "$SYSTEMD_DIR/$u" ]] || fail "Systemd unit still present: $u"
done
[[ ! -e "$SYSTEMD_DIR/audspect.service" ]] && ok "Systemd service and backup timers removed"

if $DOCKER_OK; then
  left="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^audspect-' || true)"
  [[ -z "$left" ]] && ok "All BAS containers removed" || fail "Containers still exist: $(echo "$left" | tr '\n' ' ')"
  left="$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E '^audspect[_-]' || true)"
  [[ -z "$left" ]] && ok "All BAS volumes removed" || fail "Volumes still exist: $(echo "$left" | tr '\n' ' ')"
  left="$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -E '^audspect[_-]' || true)"
  [[ -z "$left" ]] && ok "All BAS networks removed" || fail "Networks still exist: $(echo "$left" | tr '\n' ' ')"
  if $PURGE_IMAGES; then
    left="$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '^(bas-orchestrator|bas-caldera|audspect-)' || true)"
    [[ -z "$left" ]] && ok "BAS images removed" || fail "Images still exist: $(echo "$left" | tr '\n' ' ')"
  fi
fi

# Ports: a BAS container still publishing one is a failure; any other program using it is only worth a note.
for port in "${PORTS[@]:-}" ; do
  [[ -z "$port" ]] && continue
  line="$(ss -tlnp 2>/dev/null | grep -E "[:.]${port}[[:space:]]" | head -1 || true)"
  if [[ -z "$line" ]]; then
    ok "Port $port free"
  elif echo "$line" | grep -q docker-proxy; then
    fail "Port $port is still held by Docker (a container may still be running)"
  else
    warn "Port $port is in use by another program (not BAS): $(echo "$line" | awk '{print $NF}')"
  fi
done

echo ""
if $PASS; then
  echo -e "${GREEN}${BOLD}[OK]  BAS Platform completely removed. All checks passed.${NC}"
  echo ""
  echo "  To install again:  sudo bash install.sh --install --config setup.conf"
  echo "  Remember: the new install has a NEW CA and agent secret. Uninstall each agent and install it again."
  echo ""
else
  echo -e "${RED}${BOLD}[X]  Uninstall incomplete - review the failures above, fix them, and run this script again.${NC}"
  echo ""
  exit 1
fi
