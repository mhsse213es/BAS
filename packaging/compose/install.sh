#!/usr/bin/env bash
# Audspect BAS Platform — BFSI-Grade Installer
#
# Usage:
#   sudo bash install.sh --check                          # prereq report (attach to CAB)
#   sudo bash install.sh --install  --config setup.conf  # first-time install
#   sudo bash install.sh --upgrade  --config setup.conf  # in-place upgrade
#   sudo bash install.sh --rollback                      # restore previous version
#   sudo bash install.sh --status                        # current state
#   sudo bash install.sh --uninstall [--purge-images] [--yes]
#
# All secrets not supplied in setup.conf are auto-generated and written to
# ${DATA_DIR}/.env which is readable only by root. setup.conf is the
# change-management artefact approved before the maintenance window.
#
# Supported OS: Ubuntu 20.04/22.04/24.04, Rocky Linux / RHEL 9
set -euo pipefail

# ── Audspect licence public key ───────────────────────────────────────────────
readonly _LIC_PUBKEY='-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1Tkfvrt9afADqXrViDca
CMqjC9YC7FPQ/cEG5Uyw/mHa17/oeVAselWrfyw3sd8c/aS8dCUzE+DhMGRmnPm7
Kf9eCT4pGxVbkKq6h1/ospdsFUgWmrfHECmPgVLK6fppLPnpOEoC8g6ZDm0N5+Wi
v7r1Ke7ZAfKIxjkOHY2J4/sbexV5yNshO7y54nuhV2HO5aO8bIcbleqEejYB5p+o
waz/nlY+CQEQvkhvAb3ycBmcdUn1JJx3/uFNRANzWMjXvUm6svc89PqmeztFQyh1
D3JN8H8DP3tpu6sYJB546Bp/ibha3q2daQdaZBzPMG3stqx8vuRBDk6oP3Git1Oc
sLwFvk21TPctYgG2ZIIe79X6OZURBM3pmh2MMv3EGGosZQjwjKK2XJHBXTQRKbOu
DALVvcNDHOHJuJ79uN4ZQgRKcTh9+rbc+U8ItiqxMPaz6PgnWXp232MknfNd0o5c
+FgMfeAWEUyZwu2iO172ghWYkM5JzFCijJz9u5yTxL/25qferhhD9XcerdPJT1uS
viWhPS0KAZel/o+9jJg2H4P7H1NrZc4diIMhPMhmm6jxC9S3TyCQjf2rvl8oNeD6
ZKTftlLSAELFxhi81iDw7789G53Ur0+PQTcf9wCVFAPFk7DjCykHNcMf3c05vTdn
/CNAusfhqKmVI/VkLgROhr0CAwEAAQ==
-----END PUBLIC KEY-----'

# ── Constants ─────────────────────────────────────────────────────────────────
readonly PRODUCT="Audspect BAS"
readonly DEFAULT_DATA_DIR="/opt/audspect"
readonly DEFAULT_PORT="9443"
readonly MIN_RAM_MB=3800
readonly MIN_DISK_MB=10240        # 10 GB — images + DB + logs
readonly MIN_CPU_CORES=2
readonly COMPOSE_PROJECT="audspect"
readonly SERVICE_NAME="audspect"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Read version from bundle VERSION file (written by windows-build.ps1).
_ver="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || true)"
_ver="${_ver#$'\xEF\xBB\xBF'}"; _ver="${_ver//$'\r'/}"; _ver="${_ver//[[:space:]]/}"
readonly BAS_VERSION="${_ver:-latest}"

# ── Colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  BOLD='\033[1m';   CYAN='\033[0;36m';  NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; CYAN=''; NC=''
fi

log()   { echo -e "${GREEN}[PASS]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[FAIL]${NC} $*" >&2; }
step()  { echo -e "\n${BOLD}${CYAN}──  $*${NC}"; }
info()  { echo -e "      $*"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
MODE=""
CONFIG_FILE=""
PURGE_IMAGES=false
YES=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)        MODE="check"     ;;
    --install)      MODE="install"   ;;
    --upgrade)      MODE="upgrade"   ;;
    --rollback)     MODE="rollback"  ;;
    --status)       MODE="status"    ;;
    --uninstall)    MODE="uninstall" ;;
    --config)       shift; CONFIG_FILE="$1" ;;
    --purge-images) PURGE_IMAGES=true ;;
    --yes|-y)       YES=true ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: sudo bash install.sh --check | --install --config setup.conf | --upgrade --config setup.conf | --rollback | --status | --uninstall [--purge-images] [--yes]"
      exit 1 ;;
  esac
  shift
done

if [[ -z "$MODE" ]]; then
  echo "Usage: sudo bash install.sh --check | --install --config setup.conf | --upgrade --config setup.conf | --rollback | --status | --uninstall [--purge-images] [--yes]"
  exit 1
fi

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "This installer must be run as root: sudo bash $0 $*"
  exit 1
fi

# ── Config variables (populated by load_config) ───────────────────────────────
DATA_DIR=""
BAS_PORT=""
BAS_TLS=""
TLS_CERT=""
TLS_KEY=""
DB_PASSWORD=""
ADMIN_EMAIL=""
ADMIN_PASSWORD=""
LOG_RETENTION_DAYS=""
JWT_SECRET=""
AGENT_SECRET=""
LIC_PATH=""

# ── Config loader — safe key=value parser (no source / eval) ─────────────────
load_config() {
  local cfg="$1"
  [[ -f "$cfg" ]] || { err "Config file not found: $cfg"; exit 1; }

  local key val
  while IFS='=' read -r key val; do
    # strip comments and blank lines
    key="${key%%#*}"
    val="${val%%[[:space:]]#*}"
    [[ -z "${key// }" ]] && continue
    # trim whitespace
    key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"
    val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
    # strip surrounding quotes
    val="${val#\'}"; val="${val%\'}"; val="${val#\"}"; val="${val%\"}"
    case "$key" in
      DATA_DIR)             DATA_DIR="$val"             ;;
      BAS_PORT)             BAS_PORT="$val"             ;;
      BAS_TLS)              BAS_TLS="$val"              ;;
      TLS_CERT)             TLS_CERT="$val"             ;;
      TLS_KEY)              TLS_KEY="$val"              ;;
      DB_PASSWORD)          DB_PASSWORD="$val"          ;;
      ADMIN_EMAIL)          ADMIN_EMAIL="$val"          ;;
      ADMIN_PASSWORD)       ADMIN_PASSWORD="$val"       ;;
      LOG_RETENTION_DAYS)   LOG_RETENTION_DAYS="$val"  ;;
      JWT_SECRET)           JWT_SECRET="$val"           ;;
      AGENT_SECRET)         AGENT_SECRET="$val"         ;;
      LIC_PATH)             LIC_PATH="$val"             ;;
    esac
  done < "$cfg"

  # Defaults
  [[ -z "$DATA_DIR"           ]] && DATA_DIR="$DEFAULT_DATA_DIR"
  [[ -z "$BAS_PORT"           ]] && BAS_PORT="$DEFAULT_PORT"
  [[ -z "$BAS_TLS"            ]] && BAS_TLS="false"
  [[ -z "$LOG_RETENTION_DAYS" ]] && LOG_RETENTION_DAYS="90"

  # Validate required fields
  local missing=false
  [[ -z "$DB_PASSWORD"    ]] && { err "setup.conf: DB_PASSWORD is required.";    missing=true; }
  [[ -z "$ADMIN_EMAIL"    ]] && { err "setup.conf: ADMIN_EMAIL is required.";    missing=true; }
  [[ -z "$ADMIN_PASSWORD" ]] && { err "setup.conf: ADMIN_PASSWORD is required."; missing=true; }
  [[ -z "$LIC_PATH"       ]] && { err "setup.conf: LIC_PATH is required.";       missing=true; }
  $missing && exit 1

  [[ ${#DB_PASSWORD}    -lt 8  ]] && { err "DB_PASSWORD must be at least 8 characters.";      exit 1; }
  [[ ${#ADMIN_PASSWORD} -lt 10 ]] && { err "ADMIN_PASSWORD must be at least 10 characters.";  exit 1; }
  [[ "$ADMIN_EMAIL" != *@*     ]] && { err "ADMIN_EMAIL must be a valid email address.";       exit 1; }

  # TLS cert paths
  if [[ "$BAS_TLS" == "true" ]]; then
    [[ -z "$TLS_CERT" ]] && { err "setup.conf: TLS_CERT path required when BAS_TLS=true."; exit 1; }
    [[ -z "$TLS_KEY"  ]] && { err "setup.conf: TLS_KEY path required when BAS_TLS=true.";  exit 1; }
  fi

  # Auto-generate secrets if not supplied
  [[ -z "$JWT_SECRET"   ]] && JWT_SECRET=$(openssl rand -hex 32)
  [[ -z "$AGENT_SECRET" ]] && AGENT_SECRET=$(openssl rand -hex 24)
  local CALDERA_KEY CALDERA_KEY_BLUE
  CALDERA_KEY=$(openssl rand -hex 20)
  CALDERA_KEY_BLUE=$(openssl rand -hex 20)

  # Expose caldera keys to callers via global
  _CALDERA_KEY="$CALDERA_KEY"
  _CALDERA_KEY_BLUE="$CALDERA_KEY_BLUE"
}

# ── Prerequisite checks ───────────────────────────────────────────────────────
# Each check function prints one line: "PASS:<msg>" | "FAIL:<msg>" | "WARN:<msg>"
# The check mode renders these with colour; the report mode writes them raw.

_check_os() {
  local os_id os_ver
  os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
  os_ver=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "0")
  case "$os_id" in
    ubuntu)
      [[ "${os_ver%%.*}" -ge 20 ]] && echo "PASS:OS — Ubuntu ${os_ver} LTS" \
                                    || echo "FAIL:OS — Ubuntu ${os_ver} not supported (need 20.04+)";;
    rocky|rhel|centos)
      [[ "${os_ver%%.*}" -ge 9  ]] && echo "PASS:OS — Rocky/RHEL ${os_ver}" \
                                    || echo "FAIL:OS — Rocky/RHEL ${os_ver} not supported (need 9+)";;
    *) echo "WARN:OS — ${os_id} ${os_ver} (untested)" ;;
  esac
}

_check_docker() {
  if ! command -v docker &>/dev/null; then
    echo "FAIL:Docker — not installed (required)"; return
  fi
  if ! docker info &>/dev/null 2>&1; then
    echo "FAIL:Docker — daemon not running (start it before install)"; return
  fi
  local ver
  ver=$(docker --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
  echo "PASS:Docker — ${ver}"
}

_check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    local ver
    ver=$(docker compose version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
    echo "PASS:Docker Compose — ${ver}"
  else
    echo "FAIL:Docker Compose — plugin not found (install docker-compose-plugin)"
  fi
}

_check_ram() {
  local mb
  mb=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
  [[ $mb -ge $MIN_RAM_MB ]] && echo "PASS:RAM — ${mb} MB available" \
                              || echo "FAIL:RAM — ${mb} MB available (need ${MIN_RAM_MB} MB)"
}

_check_cpu() {
  local cores
  cores=$(nproc 2>/dev/null || echo 0)
  [[ $cores -ge $MIN_CPU_CORES ]] && echo "PASS:CPU — ${cores} cores" \
                                   || echo "FAIL:CPU — ${cores} cores (need ${MIN_CPU_CORES})"
}

_check_disk() {
  local dir="${1:-$DEFAULT_DATA_DIR}"
  local parent="$dir"
  while [[ ! -d "$parent" ]]; do parent="$(dirname "$parent")"; done
  local mb
  mb=$(df -m "$parent" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
  [[ $mb -ge $MIN_DISK_MB ]] && echo "PASS:Disk — ${mb} MB free on $(df -m "$parent" | awk 'NR==2{print $6}')" \
                              || echo "FAIL:Disk — ${mb} MB free (need ${MIN_DISK_MB} MB)"
}

_check_port() {
  local port="${1:-$DEFAULT_PORT}"
  if ss -tlnp 2>/dev/null | grep -q ":${port}[[:space:]]"; then
    local proc
    proc=$(ss -tlnp 2>/dev/null | grep ":${port}[[:space:]]" | grep -oP '"[^"]+"' | head -1 || echo "unknown")
    echo "FAIL:Port ${port} — already in use by ${proc}"
  else
    echo "PASS:Port ${port} — available"
  fi
}

_check_openssl() {
  command -v openssl &>/dev/null \
    && echo "PASS:openssl — $(openssl version 2>/dev/null | awk '{print $1,$2}')" \
    || echo "FAIL:openssl — not found (required for secret generation)"
}

_check_bundle_integrity() {
  local manifest="${SCRIPT_DIR}/MANIFEST.sha256"
  if [[ ! -f "$manifest" ]]; then
    echo "WARN:Bundle integrity — MANIFEST.sha256 not found (standalone run?)"
    return
  fi
  local fail=0
  while IFS='  ' read -r hash rel; do
    if [[ -z "$hash" || -z "$rel" ]]; then continue; fi
    local fp="${SCRIPT_DIR}/${rel}"
    if [[ ! -f "$fp" ]]; then
      echo "FAIL:Bundle — missing file: $rel"
      fail=1; continue
    fi
    local actual
    actual=$(sha256sum "$fp" | awk '{print $1}')
    if [[ "$actual" != "$hash" ]]; then
      echo "FAIL:Bundle — hash mismatch: $rel"
      fail=1
    fi
  done < "$manifest"
  if [[ $fail -eq 0 ]]; then echo "PASS:Bundle integrity — all files verified"; fi
}

_check_tls_certs() {
  local cert="$1" key="$2"
  [[ -z "$cert" && -z "$key" ]] && { echo "INFO:TLS — disabled in setup.conf"; return; }
  [[ ! -f "$cert" ]] && { echo "FAIL:TLS cert — not found: $cert"; return; }
  [[ ! -f "$key"  ]] && { echo "FAIL:TLS key  — not found: $key";  return; }
  if ! openssl x509 -noout -in "$cert" &>/dev/null 2>&1; then
    echo "FAIL:TLS cert — not a valid X.509 certificate: $cert"
    return
  fi
  local expiry
  expiry=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2 || echo "unknown")
  echo "PASS:TLS certs — cert valid, expires ${expiry}"
}

_check_licence() {
  local lic="$1"
  [[ -z "$lic" ]] && { echo "WARN:Licence — LIC_PATH not set in setup.conf"; return; }
  [[ ! -f "$lic" ]] && { echo "FAIL:Licence — file not found: $lic"; return; }
  # Structural check only — cryptographic validation happens at orchestrator start.
  if grep -q "AUDSPECT" "$lic" 2>/dev/null; then
    echo "PASS:Licence — file present: $lic"
  else
    echo "WARN:Licence — file present but format unrecognised: $lic"
  fi
}

# ── Render check results ──────────────────────────────────────────────────────
render_checks() {
  local results=("$@")
  local fails=0 warns=0
  for line in "${results[@]}"; do
    local severity="${line%%:*}"
    local msg="${line#*:}"
    case "$severity" in
      PASS) echo -e "  ${GREEN}[PASS]${NC} $msg" ;;
      FAIL) echo -e "  ${RED}[FAIL]${NC} $msg"; (( fails++ )) ;;
      WARN) echo -e "  ${YELLOW}[WARN]${NC} $msg"; (( warns++ )) ;;
      INFO) echo -e "        $msg" ;;
    esac
  done
  echo ""
  if [[ $fails -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}${fails} prerequisite(s) failed — resolve before install.${NC}"
    return 1
  fi
  [[ $warns -gt 0 ]] && echo -e "  ${YELLOW}${BOLD}${warns} warning(s) — review before install.${NC}"
  echo -e "  ${GREEN}${BOLD}All checks passed — system is ready.${NC}"
  return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# MODE: --check
# ═════════════════════════════════════════════════════════════════════════════
mode_check() {
  echo ""
  echo -e "${BOLD}${CYAN}━━━  ${PRODUCT} — Prerequisite Report  ━━━${NC}"
  echo "    Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "    Host     : $(hostname -f 2>/dev/null || hostname)"
  echo "    Bundle   : ${BAS_VERSION}"
  if [[ -n "$CONFIG_FILE" ]]; then
    echo "    Config   : ${CONFIG_FILE}"
  fi
  echo ""

  # Collect all check results
  local results=()
  results+=( "$(_check_os)" )
  results+=( "$(_check_docker)" )
  results+=( "$(_check_compose)" )
  results+=( "$(_check_ram)" )
  results+=( "$(_check_cpu)" )

  # Disk and port checks use config values if supplied
  local check_dir="$DEFAULT_DATA_DIR"
  local check_port="$DEFAULT_PORT"
  local check_cert="" check_key="" check_lic=""
  if [[ -n "$CONFIG_FILE" ]]; then
    load_config "$CONFIG_FILE" 2>/dev/null || true
    [[ -n "$DATA_DIR" ]] && check_dir="$DATA_DIR"
    [[ -n "$BAS_PORT" ]] && check_port="$BAS_PORT"
    check_cert="$TLS_CERT"; check_key="$TLS_KEY"; check_lic="$LIC_PATH"
  fi

  results+=( "$(_check_disk "$check_dir")" )
  results+=( "$(_check_port "$check_port")" )
  results+=( "$(_check_openssl)" )
  results+=( "$(_check_bundle_integrity)" )
  if [[ -n "$check_cert" || -n "$CONFIG_FILE" ]]; then results+=( "$(_check_tls_certs "$check_cert" "$check_key")" ); fi
  if [[ -n "$check_lic"  || -n "$CONFIG_FILE" ]]; then results+=( "$(_check_licence "$check_lic")" ); fi

  render_checks "${results[@]}"
}

# ═════════════════════════════════════════════════════════════════════════════
# MODE: --install
# ═════════════════════════════════════════════════════════════════════════════
mode_install() {
  [[ -z "$CONFIG_FILE" ]] && { err "--install requires --config <file>"; exit 1; }
  load_config "$CONFIG_FILE"

  local LOG_FILE="${DATA_DIR}/install.log"

  step "1/9  Prerequisite checks"
  local results=()
  results+=( "$(_check_os)" )
  results+=( "$(_check_docker)" )
  results+=( "$(_check_compose)" )
  results+=( "$(_check_ram)" )
  results+=( "$(_check_cpu)" )
  results+=( "$(_check_disk "$DATA_DIR")" )
  results+=( "$(_check_port "$BAS_PORT")" )
  results+=( "$(_check_openssl)" )
  results+=( "$(_check_bundle_integrity)" )
  if [[ "$BAS_TLS" == "true" ]]; then results+=( "$(_check_tls_certs "$TLS_CERT" "$TLS_KEY")" ); fi
  results+=( "$(_check_licence "$LIC_PATH")" )
  render_checks "${results[@]}" || exit 1

  step "2/9  Creating data directories"
  mkdir -p "${DATA_DIR}"/{data/postgres,logs,backups,scenarios,wwwroot,art-payloads,sharphound}
  chmod 750 "${DATA_DIR}"
  log "Created: ${DATA_DIR}"

  step "3/9  Loading Docker images (air-gap safe — no pull)"
  local images_dir="${SCRIPT_DIR}/images"
  if [[ -d "$images_dir" ]]; then
    for tar in "${images_dir}"/*.tar; do
      [[ -f "$tar" ]] || continue
      info "Loading $(basename "$tar")..."
      docker load < "$tar"
      log "Loaded: $(basename "$tar")"
    done
  else
    warn "images/ directory not found — Docker will attempt to pull (requires internet)"
  fi

  step "4/9  Staging bundle files"
  # Scenarios
  if [[ -d "${SCRIPT_DIR}/scenarios" ]]; then
    cp -r "${SCRIPT_DIR}/scenarios/." "${DATA_DIR}/scenarios/"
    log "Scenarios staged"
  fi
  # wwwroot
  if [[ -d "${SCRIPT_DIR}/wwwroot" ]]; then
    cp -r "${SCRIPT_DIR}/wwwroot/." "${DATA_DIR}/wwwroot/"
    log "wwwroot staged"
  fi
  # ART payloads
  if [[ -d "${SCRIPT_DIR}/art-payloads" ]]; then
    cp -r "${SCRIPT_DIR}/art-payloads/." "${DATA_DIR}/art-payloads/"
    log "ART payloads staged"
  fi
  # Licence
  if [[ -f "$LIC_PATH" ]]; then
    cp "$LIC_PATH" "${DATA_DIR}/bas.lic"
    chmod 644 "${DATA_DIR}/bas.lic"
    log "Licence installed"
  fi
  # TLS certs
  if [[ "$BAS_TLS" == "true" ]]; then
    mkdir -p "${DATA_DIR}/certs"
    cp "$TLS_CERT" "${DATA_DIR}/certs/bas.crt"
    cp "$TLS_KEY"  "${DATA_DIR}/certs/bas.key"
    chmod 640 "${DATA_DIR}/certs/bas.key"
    log "TLS certificates installed"
  fi

  step "5/9  Writing .env (root-readable only)"
  _write_env
  log ".env written to ${DATA_DIR}/.env"

  step "6/9  Installing docker-compose.yml"
  cp "${SCRIPT_DIR}/docker-compose.yml" "${DATA_DIR}/docker-compose.yml"
  log "Compose file installed"

  step "7/9  Installing systemd service (auto-start on boot)"
  _write_systemd_unit
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  log "Systemd service enabled: ${SERVICE_NAME}.service"

  step "8/9  Starting stack"
  systemctl start "${SERVICE_NAME}"
  log "Stack started via systemd"
  _wait_healthy

  step "9/9  Creating admin user"
  _create_admin

  _write_install_log "$LOG_FILE"
  echo ""
  echo -e "${GREEN}${BOLD}━━━  ${PRODUCT} — Installation Complete  ━━━${NC}"
  _print_access_info
}

# ═════════════════════════════════════════════════════════════════════════════
# MODE: --upgrade
# ═════════════════════════════════════════════════════════════════════════════
mode_upgrade() {
  [[ -z "$CONFIG_FILE" ]] && { err "--upgrade requires --config <file>"; exit 1; }
  load_config "$CONFIG_FILE"

  # Detect existing install
  local existing_compose="${DATA_DIR}/docker-compose.yml"
  if [[ ! -f "$existing_compose" ]]; then
    err "No existing installation found at ${DATA_DIR}."
    info "Run --install to perform a fresh installation."
    exit 1
  fi

  step "1/5  Backup current installation"
  local backup_ts backup_dir
  backup_ts=$(date -u '+%Y%m%d-%H%M%S')
  backup_dir="${DATA_DIR}/backups/${backup_ts}"
  mkdir -p "$backup_dir"
  cp "${DATA_DIR}/docker-compose.yml" "${backup_dir}/docker-compose.yml"
  [[ -f "${DATA_DIR}/.env" ]] && cp "${DATA_DIR}/.env" "${backup_dir}/.env"
  echo "$BAS_VERSION" > "${backup_dir}/VERSION"
  log "Backup created: ${backup_dir}"

  step "2/5  Loading new images"
  local images_dir="${SCRIPT_DIR}/images"
  if [[ -d "$images_dir" ]]; then
    for tar in "${images_dir}"/*.tar; do
      [[ -f "$tar" ]] || continue
      docker load < "$tar" && log "Loaded: $(basename "$tar")"
    done
  fi

  step "3/5  Updating bundle files"
  [[ -d "${SCRIPT_DIR}/scenarios"   ]] && cp -r "${SCRIPT_DIR}/scenarios/."   "${DATA_DIR}/scenarios/"
  [[ -d "${SCRIPT_DIR}/wwwroot"     ]] && cp -r "${SCRIPT_DIR}/wwwroot/."     "${DATA_DIR}/wwwroot/"
  [[ -d "${SCRIPT_DIR}/art-payloads" ]] && cp -r "${SCRIPT_DIR}/art-payloads/." "${DATA_DIR}/art-payloads/"
  [[ -f "$LIC_PATH"                 ]] && { cp "$LIC_PATH" "${DATA_DIR}/bas.lic"; chmod 644 "${DATA_DIR}/bas.lic"; }
  cp "${SCRIPT_DIR}/docker-compose.yml" "${DATA_DIR}/docker-compose.yml"
  _write_env        # refreshes BAS_VERSION; preserves existing secrets via load_config
  _write_systemd_unit  # refresh WorkingDirectory in case DATA_DIR changed
  systemctl daemon-reload
  log "Files updated"

  step "4/5  Rolling restart"
  systemctl restart "${SERVICE_NAME}" 2>/dev/null \
    || (cd "${DATA_DIR}" && docker compose -p "$COMPOSE_PROJECT" up -d --remove-orphans)
  log "Stack restarted"
  _wait_healthy

  step "5/5  Verifying upgrade"
  mode_status
  log "Upgrade to v${BAS_VERSION} complete. Rollback: sudo bash install.sh --rollback"
}

# ═════════════════════════════════════════════════════════════════════════════
# MODE: --rollback
# ═════════════════════════════════════════════════════════════════════════════
mode_rollback() {
  local backup_root="${DEFAULT_DATA_DIR}/backups"
  # Find existing DATA_DIR from systemd or default
  if [[ -f /etc/systemd/system/${SERVICE_NAME}.service ]]; then
    detected=$(grep -oP '(?<=WorkingDirectory=)[^\s]+' /etc/systemd/system/${SERVICE_NAME}.service || true)
    [[ -n "$detected" ]] && backup_root="${detected}/backups"
  fi

  # Find most recent backup
  local latest
  latest=$(ls -1dt "${backup_root}"/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]/ 2>/dev/null | head -1 || true)
  if [[ -z "$latest" ]]; then
    err "No backup found under ${backup_root}. Cannot rollback."
    exit 1
  fi

  local install_dir
  install_dir=$(dirname "$backup_root")

  echo -e "${YELLOW}${BOLD}━━━  Rollback  ━━━${NC}"
  echo "  Restoring from: ${latest}"
  echo "  Install dir   : ${install_dir}"
  echo ""

  if ! $YES; then
    read -rp "  Confirm rollback? [yes/N] " confirm
    [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 0; }
  fi

  cp "${latest}/docker-compose.yml" "${install_dir}/docker-compose.yml"
  [[ -f "${latest}/.env" ]] && cp "${latest}/.env" "${install_dir}/.env"
  local prev_ver
  prev_ver=$(cat "${latest}/VERSION" 2>/dev/null || echo "unknown")
  log "Compose and .env restored (version: ${prev_ver})"

  systemctl restart "${SERVICE_NAME}" 2>/dev/null \
    || (cd "${install_dir}" && docker compose -p "$COMPOSE_PROJECT" up -d --remove-orphans)
  log "Stack restarted with previous version"
  _wait_healthy
  log "Rollback complete (v${BAS_VERSION} → v${prev_ver})"
}

# ═════════════════════════════════════════════════════════════════════════════
# MODE: --status
# ═════════════════════════════════════════════════════════════════════════════
mode_status() {
  # Detect install dir
  local data_dir="$DEFAULT_DATA_DIR"
  if [[ -f /etc/systemd/system/${SERVICE_NAME}.service ]]; then
    detected=$(grep -oP '(?<=WorkingDirectory=)[^\s]+' /etc/systemd/system/${SERVICE_NAME}.service || true)
    [[ -n "$detected" ]] && data_dir="$detected"
  fi

  echo ""
  echo -e "${BOLD}${CYAN}━━━  ${PRODUCT} — Status  ━━━${NC}"
  echo ""

  # Containers
  local running=0 total=0
  for ctr in audspect-orchestrator audspect-caldera audspect-postgres audspect-chrome; do
    if docker inspect "$ctr" &>/dev/null 2>&1; then
      total=$(( total + 1 ))
      local st
      st=$(docker inspect --format '{{.State.Status}}' "$ctr" 2>/dev/null || echo "unknown")
      local health=""
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$ctr" 2>/dev/null || true)
      if [[ "$st" == "running" ]]; then
        running=$(( running + 1 ))
        [[ -n "$health" ]] \
          && echo -e "  ${GREEN}●${NC} ${ctr} — running (health: ${health})" \
          || echo -e "  ${GREEN}●${NC} ${ctr} — running"
      else
        echo -e "  ${RED}●${NC} ${ctr} — ${st}"
      fi
    fi
  done

  echo ""
  # Version + port from .env
  local env_file="${data_dir}/.env"
  local bas_port="9443"
  if [[ -f "$env_file" ]]; then
    local ver
    ver=$(grep -oP '(?<=BAS_VERSION=).+' "$env_file" 2>/dev/null | head -1 || echo "unknown")
    info "Version   : ${ver}"
    local ep
    ep=$(grep -oP '(?<=BAS_PORT=).+' "$env_file" 2>/dev/null | head -1 || true)
    [[ -n "$ep" ]] && bas_port="$ep"
  fi
  # Listening URL
  if ss -tlnp 2>/dev/null | grep -qP ":${bas_port}[[:space:]]"; then
    info "Listening : http://$(hostname -f 2>/dev/null || hostname):${bas_port}"
  else
    info "Listening : port ${bas_port} not yet bound"
  fi
  # systemd
  if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    info "systemd   : active (auto-restart enabled)"
  else
    info "systemd   : not enabled (containers managed manually)"
  fi
  echo ""
  [[ $running -eq $total && $total -gt 0 ]] \
    && echo -e "  ${GREEN}${BOLD}${running}/${total} containers running${NC}" \
    || echo -e "  ${YELLOW}${BOLD}${running}/${total} containers running${NC}"
  echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# MODE: --uninstall
# ═════════════════════════════════════════════════════════════════════════════
mode_uninstall() {
  local data_dir="$DEFAULT_DATA_DIR"
  if [[ -f /etc/systemd/system/${SERVICE_NAME}.service ]]; then
    detected=$(grep -oP '(?<=WorkingDirectory=)[^\s]+' /etc/systemd/system/${SERVICE_NAME}.service || true)
    [[ -n "$detected" ]] && data_dir="$detected"
  fi

  echo ""
  echo -e "${RED}${BOLD}━━━  ${PRODUCT} — Uninstall  ━━━${NC}"
  echo ""
  echo "  This will PERMANENTLY DELETE:"
  echo "    • All running containers"
  echo "    • Docker volumes (ALL database data)"
  echo "    • Docker network"
  echo "    • Install directory: ${data_dir}"
  echo "    • systemd service: ${SERVICE_NAME}"
  $PURGE_IMAGES && echo "    • Docker images"
  echo ""

  if ! $YES; then
    read -rp "  Type 'yes' to confirm complete removal: " confirm
    [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 0; }
  fi

  step "1/5  Stopping systemd service"
  local svc_unit="/etc/systemd/system/${SERVICE_NAME}.service"
  if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl stop "${SERVICE_NAME}" && log "Service stopped" || warn "Stop failed (continuing)"
  fi
  if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl disable "${SERVICE_NAME}" && log "Service disabled"
  fi
  if [[ -f "$svc_unit" ]]; then
    rm -f "$svc_unit"; systemctl daemon-reload; log "Unit file removed"
  fi

  step "2/5  Removing containers and volumes"
  if [[ -f "${data_dir}/docker-compose.yml" ]]; then
    (cd "${data_dir}" && docker compose -p "$COMPOSE_PROJECT" down --volumes --remove-orphans 2>&1) \
      && log "Compose stack removed" || warn "Compose down had errors (continuing)"
  else
    for ctr in audspect-orchestrator audspect-caldera audspect-postgres audspect-chrome; do
      docker inspect "$ctr" &>/dev/null 2>&1 && docker rm -f "$ctr" && log "Removed: $ctr"
    done
  fi

  step "3/5  Removing Docker network"
  for net in "${COMPOSE_PROJECT}_bas-internal" "bas-internal"; do
    docker network inspect "$net" &>/dev/null 2>&1 \
      && docker network rm "$net" && log "Removed network: $net"
  done

  step "4/5  Removing images"
  if $PURGE_IMAGES; then
    for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep '^audspect-\|^bas-' || true); do
      docker rmi -f "$img" && log "Removed image: $img"
    done
  else
    warn "Images retained (re-run with --purge-images to remove them)"
  fi

  step "5/5  Removing install directory"
  [[ -d "$data_dir" ]] && rm -rf "$data_dir" && log "Removed: ${data_dir}"

  echo ""
  echo -e "${GREEN}${BOLD}Uninstall complete.${NC}"
}

# ── Helpers ───────────────────────────────────────────────────────────────────
_write_systemd_unit() {
  local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"
  cat > "$unit_file" << EOF
[Unit]
Description=Audspect BAS Platform (Docker Compose)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${DATA_DIR}
EnvironmentFile=${DATA_DIR}/.env
ExecStart=/usr/bin/docker compose -p ${COMPOSE_PROJECT} up -d --remove-orphans
ExecStop=/usr/bin/docker compose -p ${COMPOSE_PROJECT} down
TimeoutStartSec=300
TimeoutStopSec=120
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$unit_file"
}

_write_env() {
  local env_file="${DATA_DIR}/.env"
  cat > "$env_file" << EOF
# Audspect BAS — Runtime environment
# Generated by install.sh — do not edit manually.
# Regenerated on upgrade; secrets survive in this file.
BAS_VERSION=${BAS_VERSION}
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT}
POSTGRES_DB=bas_platform
POSTGRES_USER=bas_user
POSTGRES_PASSWORD=${DB_PASSWORD}
JWT_SECRET=${JWT_SECRET}
AGENT_SECRET=${AGENT_SECRET}
CALDERA_API_KEY=${_CALDERA_KEY:-$(openssl rand -hex 20)}
CALDERA_API_KEY_BLUE=${_CALDERA_KEY_BLUE:-$(openssl rand -hex 20)}
BAS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
BAS_ADMIN_EMAIL=${ADMIN_EMAIL}
BAS_PORT=${BAS_PORT}
BAS_TLS=${BAS_TLS}
TLS_CERT=${TLS_CERT:-}
TLS_KEY=${TLS_KEY:-}
DATA_DIR=${DATA_DIR}
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS}
SHARPHOUND_DIR=${DATA_DIR}/sharphound
EOF
  chmod 600 "$env_file"
}

_wait_healthy() {
  local max=60 elapsed=0
  info "Waiting for orchestrator to become healthy..."
  while [[ $elapsed -lt $max ]]; do
    local st
    st=$(docker inspect --format '{{.State.Health.Status}}' audspect-orchestrator 2>/dev/null || echo "starting")
    if [[ "$st" == "healthy" ]]; then
      log "Orchestrator healthy"
      return
    fi
    sleep 3; elapsed=$(( elapsed + 3 ))
  done
  warn "Orchestrator health check timed out — check: docker compose -p ${COMPOSE_PROJECT} logs"
}

_create_admin() {
  # Give the orchestrator a moment then POST the admin user via its internal API.
  local url="http://localhost:${BAS_PORT}/api/auth/setup"
  local attempts=0
  while [[ $attempts -lt 5 ]]; do
    local http
    http=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "$url" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" 2>/dev/null || echo "000")
    if [[ "$http" == "200" || "$http" == "201" || "$http" == "409" ]]; then
      log "Admin user ready: ${ADMIN_EMAIL}"
      return
    fi
    sleep 3; attempts=$(( attempts + 1 ))
  done
  warn "Could not create admin automatically — log in and create manually if needed"
}

_write_install_log() {
  local log_file="$1"
  {
    echo "Audspect BAS — Install Log"
    echo "Timestamp : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Version   : ${BAS_VERSION}"
    echo "Host      : $(hostname -f 2>/dev/null || hostname)"
    echo "Data dir  : ${DATA_DIR}"
    echo "Port      : ${BAS_PORT}"
    echo "TLS       : ${BAS_TLS}"
    echo "Admin     : ${ADMIN_EMAIL}"
  } >> "$log_file"
  chmod 640 "$log_file"
}

_print_access_info() {
  local proto="http"
  [[ "$BAS_TLS" == "true" ]] && proto="https"
  local host
  host=$(hostname -f 2>/dev/null || hostname)
  echo ""
  echo "  Access dashboard : ${proto}://${host}:${BAS_PORT}"
  echo "  Admin login      : ${ADMIN_EMAIL}"
  echo "  Install log      : ${DATA_DIR}/install.log"
  echo ""
  echo "  Status check     : sudo bash install.sh --status"
  echo "  Upgrade          : sudo bash install.sh --upgrade --config setup.conf"
  echo "  Uninstall        : sudo bash install.sh --uninstall"
  echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# Dispatch
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${CYAN}━━━  ${PRODUCT} v${BAS_VERSION}  ━━━${NC}"
echo ""

case "$MODE" in
  check)     mode_check     ;;
  install)   mode_install   ;;
  upgrade)   mode_upgrade   ;;
  rollback)  mode_rollback  ;;
  status)    mode_status    ;;
  uninstall) mode_uninstall ;;
esac
