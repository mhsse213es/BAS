#!/usr/bin/env bash
# Audspect BAS Platform -BFSI-Grade Installer
#
# Usage:
#   sudo bash install.sh --check                          # prereq report (attach to CAB)
#   sudo bash install.sh --install  --config setup.conf [--yes]  # first-time install
#   sudo bash install.sh --upgrade  --config setup.conf  # in-place upgrade
#   sudo bash install.sh --rollback                      # restore previous version
#   sudo bash install.sh --status                        # current state
#   sudo bash install.sh --uninstall [--purge-images] [--yes]
#
# If Docker/Docker Compose are missing, --install asks for explicit
# confirmation before installing Docker CE from Docker's official
# repository. --yes also grants that consent, for unattended runs.
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
readonly DEFAULT_ENROLL_PORT="9444"
readonly DEFAULT_LEGACY_PORT="9000"
readonly DEFAULT_DASHBOARD_PORT="9543"
readonly MIN_RAM_MB=3800
readonly MIN_DISK_MB=10240        # 10 GB -images + DB + logs
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
step()  { CURRENT_STEP="$*"; echo -e "\n${BOLD}${CYAN}--  $*${NC}"; }
info()  { echo -e "      $*"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
MODE=""
CONFIG_FILE=""
PURGE_IMAGES=false
YES=false
NEED_DOCKER=false
NEED_COMPOSE=false
DOCKER_AUTO_INSTALLED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)        MODE="check"     ;;
    --install)      MODE="install"   ;;
    --upgrade)      MODE="upgrade"   ;;
    --rollback)     MODE="rollback"  ;;
    --status)       MODE="status"    ;;
    --uninstall)    MODE="uninstall" ;;
    --backup)          MODE="backup"          ;;
    --backup-request)  MODE="backup-request"  ;;
    --backup-worker)   MODE="backup-worker"   ;;
    --restore)
      MODE="restore"
      shift
      RESTORE_ARCHIVE="${1:-}"
      ;;
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

# ── Interrupt handling ────────────────────────────────────────────────────────
# Message-only: no automatic cleanup/rollback. Most steps below are safe to
# re-run as-is (mkdir -p, docker load, .env/file staging are all idempotent);
# the one non-obvious gotcha is that once docker-compose.yml has been copied
# into DATA_DIR (step 7/10 of --install), a plain --install re-run refuses
# with "already installed" even though the run never finished. This handler
# just tells the operator which resume command is correct -- it doesn't touch
# Docker or DATA_DIR itself, matching this script's existing policy elsewhere
# (see _diagnose_orchestrator_failure) of leaving risky actions to the operator.
CURRENT_STEP=""
_on_interrupt() {
  echo ""
  echo -e "${YELLOW}${BOLD}Interrupted${NC} (mode: ${MODE:-none}${CURRENT_STEP:+, during: ${CURRENT_STEP}})"
  if [[ -n "${DATA_DIR:-}" && -f "${DATA_DIR}/docker-compose.yml" ]]; then
    echo "  docker-compose.yml is already installed at ${DATA_DIR} -- a plain --install"
    echo "  re-run will refuse with \"already installed\". To resume:"
    echo "    sudo bash install.sh --upgrade --config ${CONFIG_FILE:-setup.conf}"
  elif [[ "${MODE:-}" == "install" ]]; then
    echo "  Nothing has been finalised yet -- safe to resume with:"
    echo "    sudo bash install.sh --install --config ${CONFIG_FILE:-setup.conf}"
  fi
  exit 130
}
trap _on_interrupt INT TERM

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "This installer must be run as root: sudo bash $0 $*"
  exit 1
fi

# ── Config variables (populated by load_config) ───────────────────────────────
DATA_DIR=""
BAS_PORT=""
BAS_ENROLL_PORT=""
BAS_LEGACY_PORT=""
BAS_DASHBOARD_PORT=""
DNS_SINK_BIND_IP=""
BAS_TLS=""
TLS_CERT=""
TLS_KEY=""
DB_PASSWORD=""
ADMIN_EMAIL=""
ADMIN_PASSWORD=""
LOG_RETENTION_DAYS=""
JWT_SECRET=""
AGENT_SECRET=""
SINK_SFTP_PORT=""
SINK_SFTP_HOST=""
SINK_SMTP_PORT=""
SINK_SMTP_HOST=""
LIC_PATH=""
# LICENSE_FILE is never set directly by the operator's config -- it's
# derived from LIC_PATH's own basename (see _resolve_license_file) so the
# customer-ID-named file a license is issued as (e.g. hdfc-prod-001.lic,
# see packaging/licensing/licensegen) is used verbatim end-to-end, with no
# forced rename to a generic "bas.lic" anywhere in the stack.
LICENSE_FILE=""
BACKUP_RETENTION_DAILY=""
BACKUP_RETENTION_WEEKLY=""
BACKUP_RETENTION_MONTHLY=""
BACKUP_SCHEDULE_TIME=""
REMOTE_BACKUP_ENABLED=""
REMOTE_BACKUP_TYPE=""
REMOTE_BACKUP_PATH=""
REMOTE_BACKUP_RETENTION=""
RESTORE_ARCHIVE=""

# ── Config loader -safe key=value parser (no source / eval) ─────────────────
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
      BAS_ENROLL_PORT)      BAS_ENROLL_PORT="$val"      ;;
      BAS_LEGACY_PORT)      BAS_LEGACY_PORT="$val"      ;;
      BAS_DASHBOARD_PORT)   BAS_DASHBOARD_PORT="$val"   ;;
      DNS_SINK_BIND_IP)     DNS_SINK_BIND_IP="$val"     ;;
      BAS_TLS)              BAS_TLS="$val"              ;;
      TLS_CERT)             TLS_CERT="$val"             ;;
      TLS_KEY)              TLS_KEY="$val"              ;;
      DB_PASSWORD)          DB_PASSWORD="$val"          ;;
      ADMIN_EMAIL)          ADMIN_EMAIL="$val"          ;;
      ADMIN_PASSWORD)       ADMIN_PASSWORD="$val"       ;;
      LOG_RETENTION_DAYS)   LOG_RETENTION_DAYS="$val"  ;;
      JWT_SECRET)              JWT_SECRET="$val"              ;;
      AGENT_SECRET)            AGENT_SECRET="$val"            ;;
      SINK_SFTP_PORT)          SINK_SFTP_PORT="$val"          ;;
      SINK_SFTP_HOST)          SINK_SFTP_HOST="$val"          ;;
      SINK_SMTP_PORT)          SINK_SMTP_PORT="$val"          ;;
      SINK_SMTP_HOST)          SINK_SMTP_HOST="$val"          ;;
      LIC_PATH)                LIC_PATH="$val"                ;;
      BACKUP_RETENTION_DAILY)   BACKUP_RETENTION_DAILY="$val"   ;;
      BACKUP_RETENTION_WEEKLY)  BACKUP_RETENTION_WEEKLY="$val"  ;;
      BACKUP_RETENTION_MONTHLY) BACKUP_RETENTION_MONTHLY="$val" ;;
      BACKUP_SCHEDULE_TIME)     BACKUP_SCHEDULE_TIME="$val"     ;;
      REMOTE_BACKUP_ENABLED)    REMOTE_BACKUP_ENABLED="$val"    ;;
      REMOTE_BACKUP_TYPE)       REMOTE_BACKUP_TYPE="$val"       ;;
      REMOTE_BACKUP_PATH)       REMOTE_BACKUP_PATH="$val"       ;;
      REMOTE_BACKUP_RETENTION)  REMOTE_BACKUP_RETENTION="$val"  ;;
    esac
  done < "$cfg"

  # Defaults
  [[ -z "$DATA_DIR"           ]] && DATA_DIR="$DEFAULT_DATA_DIR"
  [[ -z "$BAS_PORT"           ]] && BAS_PORT="$DEFAULT_PORT"
  [[ -z "$BAS_ENROLL_PORT"    ]] && BAS_ENROLL_PORT="$DEFAULT_ENROLL_PORT"
  [[ -z "$BAS_LEGACY_PORT"    ]] && BAS_LEGACY_PORT="$DEFAULT_LEGACY_PORT"
  [[ -z "$BAS_DASHBOARD_PORT" ]] && BAS_DASHBOARD_PORT="$DEFAULT_DASHBOARD_PORT"
  # Auto-detect the DNS sink's bind IP: first non-loopback address `hostname
  # -I` reports. Deliberately NOT a route-lookup (e.g. `ip route get`) --
  # this must work identically on air-gapped hosts with no route to the
  # internet, since it only reads local interface config, never sends a
  # packet. See setup.conf.template's DNS_SINK_BIND_IP comment for why this
  # can't be 0.0.0.0.
  [[ -z "$DNS_SINK_BIND_IP"   ]] && DNS_SINK_BIND_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  [[ -z "$BAS_TLS"            ]] && BAS_TLS="false"
  [[ -z "$LOG_RETENTION_DAYS" ]] && LOG_RETENTION_DAYS="90"
  [[ -z "$BACKUP_RETENTION_DAILY"   ]] && BACKUP_RETENTION_DAILY="7"
  [[ -z "$BACKUP_RETENTION_WEEKLY"  ]] && BACKUP_RETENTION_WEEKLY="4"
  [[ -z "$BACKUP_RETENTION_MONTHLY" ]] && BACKUP_RETENTION_MONTHLY="3"
  [[ -z "$BACKUP_SCHEDULE_TIME"     ]] && BACKUP_SCHEDULE_TIME="02:00"
  [[ -z "$REMOTE_BACKUP_ENABLED"    ]] && REMOTE_BACKUP_ENABLED="false"
  [[ -z "$REMOTE_BACKUP_RETENTION"  ]] && REMOTE_BACKUP_RETENTION="30"

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
  [[ -z "$DNS_SINK_BIND_IP"    ]] && { err "Could not auto-detect a host IP for DNS_SINK_BIND_IP (hostname -I returned nothing). Set DNS_SINK_BIND_IP explicitly in setup.conf."; exit 1; }

  [[ -z "$SINK_SFTP_PORT" ]] && SINK_SFTP_PORT="2222"
  [[ "$SINK_SFTP_PORT" == "22" ]] && { err "setup.conf: SINK_SFTP_PORT must not be 22 -- this collides with the deployment host's own sshd. Leave unset for the default (2222) or choose a different unused host port."; exit 1; }

  # SMTP sink: container-internal and host-published are the SAME value
  # (unlike SFTP's 22-vs-2222 split) -- 587 carries no equivalent
  # collision risk (a host's local MTA, if any, conventionally listens on
  # 25, not 587), so this needs only a default, no rejection check.
  [[ -z "$SINK_SMTP_PORT" ]] && SINK_SMTP_PORT="587"

  # TLS cert paths
  if [[ "$BAS_TLS" == "true" ]]; then
    [[ -z "$TLS_CERT" ]] && { err "setup.conf: TLS_CERT path required when BAS_TLS=true."; exit 1; }
    [[ -z "$TLS_KEY"  ]] && { err "setup.conf: TLS_KEY path required when BAS_TLS=true.";  exit 1; }
  fi

  # JWT/agent secrets — priority order:
  #   1. explicit setup.conf value
  #   2. existing .env in DATA_DIR (upgrade of an already-installed system —
  #      regenerating here would invalidate every enrolled agent's secret
  #      and every live session's JWT with no visible error to the operator)
  #   3. generate fresh random value (very first install)
  local existing_env="${DATA_DIR}/.env"
  if [[ -z "$JWT_SECRET" && -f "$existing_env" ]]; then
    JWT_SECRET=$(grep -oP '(?<=^JWT_SECRET=).+' "$existing_env" 2>/dev/null || true)
  fi
  if [[ -z "$AGENT_SECRET" && -f "$existing_env" ]]; then
    AGENT_SECRET=$(grep -oP '(?<=^AGENT_SECRET=).+' "$existing_env" 2>/dev/null || true)
  fi
  [[ -z "$JWT_SECRET"   ]] && JWT_SECRET=$(openssl rand -hex 32)
  [[ -z "$AGENT_SECRET" ]] && AGENT_SECRET=$(openssl rand -hex 24)

  # Caldera keys — priority order:
  #   1. running Caldera container (ground truth — what is actually deployed)
  #   2. existing .env in DATA_DIR (no container running yet, e.g. fresh install)
  #   3. generate fresh random key (very first install)
  #
  # The container is checked FIRST so that install/upgrade never silently writes
  # a different key than what Caldera is running with, which would cause every
  # orchestrator→Caldera call to get a 401 with no visible error to the operator.
  local CALDERA_KEY CALDERA_KEY_BLUE
  CALDERA_KEY=""
  CALDERA_KEY_BLUE=""

  if docker inspect audspect-caldera &>/dev/null 2>&1; then
    CALDERA_KEY=$(docker exec audspect-caldera python3 -c \
      "import yaml; c=yaml.safe_load(open('conf/local.yml')); print(c.get('api_key_red',''))" \
      2>/dev/null | tr -d '[:space:]' || true)
    CALDERA_KEY_BLUE=$(docker exec audspect-caldera python3 -c \
      "import yaml; c=yaml.safe_load(open('conf/local.yml')); print(c.get('api_key_blue',''))" \
      2>/dev/null | tr -d '[:space:]' || true)
  fi

  if [[ -z "$CALDERA_KEY" && -f "$existing_env" ]]; then
    CALDERA_KEY=$(grep -oP '(?<=^CALDERA_API_KEY=).+' "$existing_env" 2>/dev/null || true)
    CALDERA_KEY_BLUE=$(grep -oP '(?<=^CALDERA_API_KEY_BLUE=).+' "$existing_env" 2>/dev/null || true)
  fi

  [[ -z "$CALDERA_KEY"      ]] && CALDERA_KEY=$(openssl rand -hex 20)
  [[ -z "$CALDERA_KEY_BLUE" ]] && CALDERA_KEY_BLUE=$(openssl rand -hex 20)

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
      [[ "${os_ver%%.*}" -ge 20 ]] && echo "PASS:OS -Ubuntu ${os_ver} LTS" \
                                    || echo "FAIL:OS -Ubuntu ${os_ver} not supported (need 20.04+)";;
    rocky|rhel|centos)
      [[ "${os_ver%%.*}" -ge 9  ]] && echo "PASS:OS -Rocky/RHEL ${os_ver}" \
                                    || echo "FAIL:OS -Rocky/RHEL ${os_ver} not supported (need 9+)";;
    *) echo "WARN:OS -${os_id} ${os_ver} (untested)" ;;
  esac
}

# Callers use results+=( "$(_check_docker)" ) -- that $(...) runs this in a
# subshell, so it cannot set NEED_DOCKER itself; mode_install sets it directly.
_check_docker() {
  if ! command -v docker &>/dev/null; then
    echo "INST:Docker -not installed (installer can install it with your consent)"; return
  fi
  if ! docker info &>/dev/null 2>&1; then
    echo "FAIL:Docker -daemon not running (start it before install)"; return
  fi
  local ver
  ver=$(docker --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
  echo "PASS:Docker -${ver}"
}

_check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    local ver
    ver=$(docker compose version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
    echo "PASS:Docker Compose -${ver}"
  else
    echo "INST:Docker Compose -not installed (installer can install it with your consent)"
  fi
}

# ── Docker CE installation ─────────────────────────────────────────────────────
# Installs from Docker's own officially documented apt/dnf repositories.
# Called only after explicit operator consent (see mode_install).
_install_docker() {
  local os_id
  os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
  case "$os_id" in
    ubuntu|debian)
      apt-get update -qq
      apt-get install -y -qq ca-certificates curl gnupg lsb-release
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${os_id} $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
      apt-get update -qq
      apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
      ;;
    rocky|rhel|centos)
      dnf install -y -q dnf-plugins-core
      dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
      dnf install -y -q \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
      ;;
    *)
      err "Automatic Docker install is not supported on this OS (${os_id})."
      info "Install Docker CE manually: https://docs.docker.com/engine/install/"
      exit 1
      ;;
  esac
  systemctl enable --now docker
}

_check_ram() {
  local mb
  mb=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
  [[ $mb -ge $MIN_RAM_MB ]] && echo "PASS:RAM -${mb} MB available" \
                              || echo "FAIL:RAM -${mb} MB available (need ${MIN_RAM_MB} MB)"
}

_check_cpu() {
  local cores
  cores=$(nproc 2>/dev/null || echo 0)
  [[ $cores -ge $MIN_CPU_CORES ]] && echo "PASS:CPU -${cores} cores" \
                                   || echo "FAIL:CPU -${cores} cores (need ${MIN_CPU_CORES})"
}

_check_disk() {
  local dir="${1:-$DEFAULT_DATA_DIR}"
  local parent="$dir"
  while [[ ! -d "$parent" ]]; do parent="$(dirname "$parent")"; done
  local mb
  mb=$(df -m "$parent" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
  [[ $mb -ge $MIN_DISK_MB ]] && echo "PASS:Disk -${mb} MB free on $(df -m "$parent" | awk 'NR==2{print $6}')" \
                              || echo "FAIL:Disk -${mb} MB free (need ${MIN_DISK_MB} MB)"
}

_check_port() {
  local port="${1:-$DEFAULT_PORT}"
  if ss -tlnp 2>/dev/null | grep -q ":${port}[[:space:]]"; then
    local proc
    proc=$(ss -tlnp 2>/dev/null | grep ":${port}[[:space:]]" | grep -oP '"[^"]+"' | head -1 || echo "unknown")
    echo "FAIL:Port ${port} -already in use by ${proc}"
  else
    echo "PASS:Port ${port} -available"
  fi
}

# Checks UDP/53 on the specific DNS_SINK_BIND_IP (not the wildcard address --
# see setup.conf.template's DNS_SINK_BIND_IP comment). Binding to a specific
# non-loopback IP means this only conflicts with something else that has
# ALSO bound that exact IP:53/udp -- systemd-resolved's stub listener
# (127.0.0.53/127.0.0.54, loopback-only) never collides with it. If this
# still FAILs, a real service (not systemd-resolved) already owns that IP.
_check_dns_sink_port() {
  local bind_ip="$1"
  if [[ -z "$bind_ip" ]]; then
    echo "FAIL:DNS sink (UDP/53) -DNS_SINK_BIND_IP is empty, cannot check"
    return
  fi
  if ss -ulnp 2>/dev/null | grep -q "${bind_ip}:53[[:space:]]"; then
    local proc
    proc=$(ss -ulnp 2>/dev/null | grep "${bind_ip}:53[[:space:]]" | grep -oP '"[^"]+"' | head -1 || echo "unknown")
    echo "FAIL:DNS sink (UDP/53) -${bind_ip}:53 already in use by ${proc}"
  else
    echo "PASS:DNS sink (UDP/53) -${bind_ip}:53 available"
  fi
}

_check_openssl() {
  command -v openssl &>/dev/null \
    && echo "PASS:openssl -$(openssl version 2>/dev/null | awk '{print $1,$2}')" \
    || echo "FAIL:openssl -not found (required for secret generation)"
}

_check_bundle_integrity() {
  local manifest="${SCRIPT_DIR}/MANIFEST.sha256"
  if [[ ! -f "$manifest" ]]; then
    echo "WARN:Bundle integrity -MANIFEST.sha256 not found (standalone run?)"
    return
  fi
  local fail=0
  while IFS='  ' read -r hash rel; do
    if [[ -z "$hash" || -z "$rel" ]]; then continue; fi
    local fp="${SCRIPT_DIR}/${rel}"
    if [[ ! -f "$fp" ]]; then
      echo "FAIL:Bundle -missing file: $rel"
      fail=1; continue
    fi
    local actual
    actual=$(sha256sum "$fp" | awk '{print $1}')
    if [[ "$actual" != "$hash" ]]; then
      echo "FAIL:Bundle -hash mismatch: $rel"
      fail=1
    fi
  done < "$manifest"
  if [[ $fail -eq 0 ]]; then echo "PASS:Bundle integrity -all files verified"; fi
}

_check_tls_certs() {
  local cert="$1" key="$2"
  [[ -z "$cert" && -z "$key" ]] && { echo "INFO:TLS -disabled in setup.conf"; return; }
  [[ ! -f "$cert" ]] && { echo "FAIL:TLS cert -not found: $cert"; return; }
  [[ ! -f "$key"  ]] && { echo "FAIL:TLS key  -not found: $key";  return; }
  if ! openssl x509 -noout -in "$cert" &>/dev/null 2>&1; then
    echo "FAIL:TLS cert -not a valid X.509 certificate: $cert"
    return
  fi
  local expiry
  expiry=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2 || echo "unknown")
  echo "PASS:TLS certs -cert valid, expires ${expiry}"
}

_check_licence() {
  local lic="$1"
  [[ -z "$lic" ]] && { echo "WARN:Licence -LIC_PATH not set in setup.conf"; return; }
  [[ ! -f "$lic" ]] && { echo "FAIL:Licence -file not found: $lic"; return; }
  # Structural check: must be JSON with the three fields the orchestrator requires.
  # Full cryptographic validation happens at orchestrator start.
  if grep -q '"customer_id"' "$lic" 2>/dev/null && \
     grep -q '"signature"'   "$lic" 2>/dev/null && \
     grep -q '"expires_at"'  "$lic" 2>/dev/null; then
    echo "PASS:Licence -file present and valid format: $lic"
  else
    echo "WARN:Licence -file present but missing required fields (customer_id/expires_at/signature): $lic"
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
      FAIL) echo -e "  ${RED}[FAIL]${NC} $msg"; fails=$((fails + 1)) ;;
      WARN) echo -e "  ${YELLOW}[WARN]${NC} $msg"; warns=$((warns + 1)) ;;
      INST) echo -e "  ${CYAN}[INST]${NC} $msg" ;;
      INFO) echo -e "        $msg" ;;
    esac
  done
  echo ""
  if [[ $fails -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}${fails} prerequisite(s) failed -resolve before install.${NC}"
    return 1
  fi
  [[ $warns -gt 0 ]] && echo -e "  ${YELLOW}${BOLD}${warns} warning(s) -review before install.${NC}"
  echo -e "  ${GREEN}${BOLD}All checks passed -system is ready.${NC}"
  return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# MODE: --check
# ═════════════════════════════════════════════════════════════════════════════
mode_check() {
  echo ""
  echo -e "${BOLD}${CYAN}===  ${PRODUCT} -Prerequisite Report  ===${NC}"
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
  local check_dns_ip=""
  local check_cert="" check_key="" check_lic=""
  if [[ -n "$CONFIG_FILE" ]]; then
    load_config "$CONFIG_FILE" 2>/dev/null || true
    [[ -n "$DATA_DIR" ]] && check_dir="$DATA_DIR"
    [[ -n "$BAS_PORT" ]] && check_port="$BAS_PORT"
    check_dns_ip="$DNS_SINK_BIND_IP"
    check_cert="$TLS_CERT"; check_key="$TLS_KEY"; check_lic="$LIC_PATH"
  fi
  [[ -z "$check_dns_ip" ]] && check_dns_ip=$(hostname -I 2>/dev/null | awk '{print $1}')

  results+=( "$(_check_disk "$check_dir")" )
  results+=( "$(_check_port "$check_port")" )
  results+=( "$(_check_dns_sink_port "$check_dns_ip")" )
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

  # Refuse to install over an existing installation -- same detection
  # mode_upgrade already uses (${DATA_DIR}/docker-compose.yml presence),
  # inverted: error here instead of there.
  local existing_compose="${DATA_DIR}/docker-compose.yml"
  if [[ -f "$existing_compose" ]]; then
    local existing_ver="unknown" existing_env="${DATA_DIR}/.env"
    if [[ -f "$existing_env" ]]; then
      existing_ver=$(grep -oP '(?<=BAS_VERSION=).+' "$existing_env" 2>/dev/null | head -1 || echo "unknown")
    fi
    err "${PRODUCT} v${existing_ver} is already installed at ${DATA_DIR}."
    info "Run 'sudo bash install.sh --uninstall' first, or --upgrade to update in place."
    exit 1
  fi

  local LOG_FILE="${DATA_DIR}/install.log"

  step "1/10  Prerequisite checks"
  local results=()
  results+=( "$(_check_os)" )
  results+=( "$(_check_docker)" )
  results+=( "$(_check_compose)" )
  # _check_docker/_check_compose run inside $(...) subshells above and can't
  # set NEED_DOCKER/NEED_COMPOSE themselves -- mirror their own detection here.
  command -v docker &>/dev/null || NEED_DOCKER=true
  docker compose version &>/dev/null 2>&1 || NEED_COMPOSE=true
  results+=( "$(_check_ram)" )
  results+=( "$(_check_cpu)" )
  results+=( "$(_check_disk "$DATA_DIR")" )
  results+=( "$(_check_port "$BAS_PORT")" )
  results+=( "$(_check_dns_sink_port "$DNS_SINK_BIND_IP")" )
  results+=( "$(_check_openssl)" )
  results+=( "$(_check_bundle_integrity)" )
  if [[ "$BAS_TLS" == "true" ]]; then results+=( "$(_check_tls_certs "$TLS_CERT" "$TLS_KEY")" ); fi
  results+=( "$(_check_licence "$LIC_PATH")" )
  render_checks "${results[@]}" || exit 1

  step "2/10  Docker Engine"
  if $NEED_DOCKER || $NEED_COMPOSE; then
    echo ""
    echo "  Docker and/or Docker Compose are not installed on this host."
    echo "  The installer can download and install Docker CE from Docker's official"
    echo "  repository (download.docker.com) and enable it as a system service."
    echo ""
    if ! $YES; then
      read -rp "  Install Docker CE now from the official Docker repository? [yes/N] " confirm
      [[ "$confirm" == "yes" ]] || { err "Docker is required to continue. Install it manually (or re-run with --yes) and re-run --install."; exit 1; }
    fi
    _install_docker
    DOCKER_AUTO_INSTALLED=true
    log "Docker CE installed: $(docker --version)"
  else
    log "Docker already present -skipping"
  fi

  step "3/10  Creating data directories"
  mkdir -p "${DATA_DIR}"/{data/postgres,logs,backups,scenarios,wwwroot,art-payloads,sharphound,pki,certs}
  chmod 750 "${DATA_DIR}"
  # scenarios is written by the orchestrator container (runs as UID 65532 -distroless nonroot).
  # Without this the UI cannot create or save custom scenarios.
  chown -R 65532:65532 "${DATA_DIR}/scenarios"
  # pki holds the deployment CA (agent mTLS trust root) -- the orchestrator
  # container writes it (same UID 65532 nonroot user as above) via the
  # ./pki:/etc/audspect/pki bind mount in docker-compose.yml. A host
  # directory created here while running as root (this script requires
  # sudo) defaults to root ownership, which UID 65532 cannot write into
  # without this chown. certs is read-only from the container's side and
  # only ever written by this script itself (BAS_TLS=true path below), so
  # it doesn't need the same treatment.
  chown 65532:65532 "${DATA_DIR}/pki"
  chmod 700 "${DATA_DIR}/pki"
  log "Created: ${DATA_DIR}"

  step "4/10  Loading Docker images (air-gap safe -no pull)"
  local images_dir="${SCRIPT_DIR}/images"
  if [[ -d "$images_dir" ]]; then
    for tar in "${images_dir}"/*.tar; do
      [[ -f "$tar" ]] || continue
      info "Loading $(basename "$tar")..."
      docker load < "$tar"
      log "Loaded: $(basename "$tar")"
    done
  else
    warn "images/ directory not found -Docker will attempt to pull (requires internet)"
  fi

  step "5/10  Staging bundle files"
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
  # Licence -- kept under its own issued filename (e.g. hdfc-prod-001.lic),
  # never renamed to a generic bas.lic. See _resolve_license_file.
  _resolve_license_file
  if [[ -f "$LIC_PATH" ]]; then
    cp "$LIC_PATH" "${DATA_DIR}/${LICENSE_FILE}"
    chmod 644 "${DATA_DIR}/${LICENSE_FILE}"
    log "Licence installed: ${LICENSE_FILE}"
  fi
  # TLS certs
  if [[ "$BAS_TLS" == "true" ]]; then
    mkdir -p "${DATA_DIR}/certs"
    cp "$TLS_CERT" "${DATA_DIR}/certs/bas.crt"
    cp "$TLS_KEY"  "${DATA_DIR}/certs/bas.key"
    chmod 640 "${DATA_DIR}/certs/bas.key"
    log "TLS certificates installed"
  fi

  # Backup archive encryption key -- generated once, never touches the app
  # container or the database. Losing this file makes existing backups
  # unrecoverable; --status reminds the operator to preserve it.
  if [[ ! -f "${DATA_DIR}/.backup_key" ]]; then
    openssl rand -base64 48 > "${DATA_DIR}/.backup_key"
    chmod 600 "${DATA_DIR}/.backup_key"
    chown root:root "${DATA_DIR}/.backup_key"
  fi

  step "6/10  Writing .env (root-readable only)"
  _write_env
  log ".env written to ${DATA_DIR}/.env"

  step "7/10  Installing docker-compose.yml"
  cp "${SCRIPT_DIR}/docker-compose.yml" "${DATA_DIR}/docker-compose.yml"
  cp "${SCRIPT_DIR}/install.sh" "${DATA_DIR}/install.sh"
  log "Compose file installed"

  step "8/10  Installing systemd service (auto-start on boot)"
  _write_systemd_unit
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  log "Systemd service enabled: ${SERVICE_NAME}.service"

  step "8b/10  Installing backup worker + schedule timers"
  _write_backup_systemd_units

  step "9/10  Starting stack"
  systemctl start "${SERVICE_NAME}"
  log "Stack started via systemd"
  _wait_healthy

  step "10/10  Creating admin user"
  _create_admin

  _write_install_log "$LOG_FILE"
  echo ""
  echo -e "${GREEN}${BOLD}===  ${PRODUCT} -Installation Complete  ===${NC}"
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

  # Detect an upgrade FROM a pre-mTLS install: BAS_ENROLL_PORT's absence
  # from the existing .env means the current deployment predates the
  # four-listener topology, so every enrolled agent is still configured
  # for http://<host>:9443 in plaintext. After this upgrade, 9443 requires
  # a client certificate -- those agents go dark unless repointed to the
  # new legacy listener (:9000) BEFORE this upgrade runs. See
  # docs/guides/upgrade-guide.md's migration-runbook section.
  if [[ -f "${DATA_DIR}/.env" ]] && ! grep -q '^BAS_ENROLL_PORT=' "${DATA_DIR}/.env"; then
    warn "This upgrade moves your existing deployment to a new per-agent mTLS"
    warn "trust model. Your CURRENT fleet is configured for plaintext"
    warn "http://<host>:9443 -- after this upgrade, that port requires a"
    warn "client certificate and those agents will go dark."
    warn ""
    warn "Read the migration section in docs/guides/upgrade-guide.md and"
    warn "repoint your existing agents to :9000 BEFORE proceeding, or they"
    warn "will lose connectivity until manually reconfigured."
    if ! $YES; then
      warn ""
      read -rp "Have you already repointed the existing fleet to :9000? [yes/N] " confirm
      [[ "$confirm" == "yes" ]] || { err "Upgrade aborted -- repoint the fleet first (or re-run with --yes), then re-run --upgrade."; exit 1; }
    fi
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
  _resolve_license_file
  [[ -f "$LIC_PATH" ]] && { cp "$LIC_PATH" "${DATA_DIR}/${LICENSE_FILE}"; chmod 644 "${DATA_DIR}/${LICENSE_FILE}"; }
  cp "${SCRIPT_DIR}/docker-compose.yml" "${DATA_DIR}/docker-compose.yml"
  cp "${SCRIPT_DIR}/install.sh" "${DATA_DIR}/install.sh"
  _write_env        # refreshes BAS_VERSION; preserves existing secrets via load_config
  _write_systemd_unit  # refresh WorkingDirectory in case DATA_DIR changed
  _write_backup_systemd_units
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

  echo -e "${YELLOW}${BOLD}===  Rollback  ===${NC}"
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
  echo -e "${BOLD}${CYAN}===  ${PRODUCT} -Status  ===${NC}"
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
          && echo -e "  ${GREEN}●${NC} ${ctr} -running (health: ${health})" \
          || echo -e "  ${GREEN}●${NC} ${ctr} -running"
      else
        echo -e "  ${RED}●${NC} ${ctr} -${st}"
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
  echo -e "${RED}${BOLD}===  ${PRODUCT} -Uninstall  ===${NC}"
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

_write_backup_systemd_units() {
  cat > /etc/systemd/system/audspect-backup-worker.service << EOF
[Unit]
Description=Audspect backup worker (executes requested backup_jobs rows)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=${DATA_DIR}
ExecStart=/usr/bin/env bash ${DATA_DIR}/install.sh --backup-worker
EOF
  chmod 644 /etc/systemd/system/audspect-backup-worker.service

  cat > /etc/systemd/system/audspect-backup-worker.timer << 'EOF'
[Unit]
Description=Poll backup_jobs every 60s

[Timer]
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
  chmod 644 /etc/systemd/system/audspect-backup-worker.timer

  cat > /etc/systemd/system/audspect-backup-schedule.service << EOF
[Unit]
Description=Audspect scheduled backup request (inserts one requested row)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
Environment=TRIGGER=scheduled
WorkingDirectory=${DATA_DIR}
ExecStart=/usr/bin/env bash ${DATA_DIR}/install.sh --backup-request
EOF
  chmod 644 /etc/systemd/system/audspect-backup-schedule.service

  cat > /etc/systemd/system/audspect-backup-schedule.timer << EOF
[Unit]
Description=Daily scheduled backup trigger

[Timer]
OnCalendar=*-*-* ${BACKUP_SCHEDULE_TIME}:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  chmod 644 /etc/systemd/system/audspect-backup-schedule.timer

  systemctl daemon-reload
  systemctl enable --now audspect-backup-worker.timer audspect-backup-schedule.timer
}

# _resolve_license_file sets LICENSE_FILE to the actual filename the
# license should be known by everywhere (the compose mount, the container's
# BAS_LICENSE_PATH, .env). If LIC_PATH was supplied this run (fresh install,
# or an explicit license refresh during --upgrade), it wins and LICENSE_FILE
# becomes that file's own basename -- e.g. LIC_PATH=/tmp/hdfc-prod-001.lic
# -> LICENSE_FILE=hdfc-prod-001.lic, preserving the customer-ID name
# licensegen issued it under. Otherwise (a routine upgrade not re-supplying
# a license) falls back to whatever LICENSE_FILE the existing .env already
# has, so it survives an upgrade run untouched. Only a brand-new install
# with no prior .env and no LIC_PATH falls back to "bas.lic" for backward
# compatibility with deployments from before this existed.
_resolve_license_file() {
  if [[ -n "$LIC_PATH" ]]; then
    LICENSE_FILE="$(basename "$LIC_PATH")"
  elif [[ -z "$LICENSE_FILE" && -f "${DATA_DIR}/.env" ]]; then
    LICENSE_FILE=$(grep -oP '(?<=^LICENSE_FILE=).+' "${DATA_DIR}/.env" 2>/dev/null | head -1 || true)
  fi
  LICENSE_FILE="${LICENSE_FILE:-bas.lic}"
}

_write_env() {
  local env_file="${DATA_DIR}/.env"
  # In-container paths for the operator-supplied dashboard TLS cert -- only
  # set when BAS_TLS=true, so docker-compose.yml's TLS_CERT/TLS_KEY env vars
  # (sourced from these, via ${TLS_CERT_CONTAINER_PATH:-}) stay empty
  # otherwise and config.go's DashboardTLSCertPath/DashboardTLSKeyPath
  # correctly default empty too, falling back to the deployment CA's own
  # certificate. Distinct var names from the existing TLS_CERT/TLS_KEY keys
  # below (which hold the HOST paths install.sh itself validates/copies
  # from) -- compose reads THESE for the in-container path instead.
  local tls_cert_container_path="" tls_key_container_path=""
  if [[ "$BAS_TLS" == "true" ]]; then
    tls_cert_container_path="/etc/bas/certs/bas.crt"
    tls_key_container_path="/etc/bas/certs/bas.key"
  fi
  cat > "$env_file" << EOF
# Audspect BAS -Runtime environment
# Generated by install.sh -do not edit manually.
# Regenerated on upgrade; secrets survive in this file.
BAS_VERSION=${BAS_VERSION}
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT}
POSTGRES_DB=bas_platform
POSTGRES_USER=bas_user
POSTGRES_PASSWORD=${DB_PASSWORD}
JWT_SECRET=${JWT_SECRET}
AGENT_SECRET=${AGENT_SECRET}
SINK_SFTP_PORT=${SINK_SFTP_PORT}
SINK_SFTP_HOST=${SINK_SFTP_HOST}
SINK_SMTP_PORT=${SINK_SMTP_PORT}
SINK_SMTP_HOST=${SINK_SMTP_HOST}
CALDERA_API_KEY=${_CALDERA_KEY:-$(openssl rand -hex 20)}
CALDERA_API_KEY_BLUE=${_CALDERA_KEY_BLUE:-$(openssl rand -hex 20)}
BAS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
BAS_ADMIN_EMAIL=${ADMIN_EMAIL}
LICENSE_FILE=${LICENSE_FILE:-bas.lic}
BAS_PORT=${BAS_PORT}
BAS_ENROLL_PORT=${BAS_ENROLL_PORT}
BAS_LEGACY_PORT=${BAS_LEGACY_PORT}
BAS_DASHBOARD_PORT=${BAS_DASHBOARD_PORT}
DNS_SINK_BIND_IP=${DNS_SINK_BIND_IP}
BAS_TLS=${BAS_TLS}
TLS_CERT=${TLS_CERT:-}
TLS_KEY=${TLS_KEY:-}
TLS_CERT_CONTAINER_PATH=${tls_cert_container_path}
TLS_KEY_CONTAINER_PATH=${tls_key_container_path}
DATA_DIR=${DATA_DIR}
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS}
SHARPHOUND_DIR=${DATA_DIR}/sharphound
BACKUP_RETENTION_DAILY=${BACKUP_RETENTION_DAILY}
BACKUP_RETENTION_WEEKLY=${BACKUP_RETENTION_WEEKLY}
BACKUP_RETENTION_MONTHLY=${BACKUP_RETENTION_MONTHLY}
BACKUP_SCHEDULE_TIME=${BACKUP_SCHEDULE_TIME}
REMOTE_BACKUP_ENABLED=${REMOTE_BACKUP_ENABLED}
REMOTE_BACKUP_TYPE=${REMOTE_BACKUP_TYPE:-}
REMOTE_BACKUP_PATH=${REMOTE_BACKUP_PATH:-}
REMOTE_BACKUP_RETENTION=${REMOTE_BACKUP_RETENTION}
EOF
  chmod 600 "$env_file"
}

# ── Backup & Recovery engine ──────────────────────────────────────────────────
# Shared by `--backup` (run directly) and `--backup-worker` (polls
# backup_jobs for a 'requested' row and calls this same code). See
# docs/superpowers/specs/2026-08-17-backup-recovery-design.md.

_run_pg_dump() {
  local out_file="$1"
  docker exec audspect-postgres pg_dump -U bas_user -Fc bas_platform > "$out_file"
}

_package_config() {
  local out_file="$1"
  # LIC_PATH is never set in a backup context (no --config file is loaded
  # here) -- _resolve_license_file falls back to reading the already-
  # installed .env's own LICENSE_FILE, which is exactly what's on disk.
  _resolve_license_file
  tar -cf "$out_file" -C "${DATA_DIR}" \
    --ignore-failed-read \
    .env "${LICENSE_FILE}" certs scenarios docker-compose.yml pki 2>/dev/null || true
}

_write_backup_manifest() {
  local out_file="$1" pg_version
  pg_version=$(docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc "SHOW server_version" 2>/dev/null | tr -d '[:space:]')
  cat > "$out_file" << EOF
{
  "basVersion": "${BAS_VERSION}",
  "postgresVersion": "${pg_version}",
  "createdAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "contents": ["postgres/audspect.dump", "config/.env", "config/${LICENSE_FILE}", "config/certs", "config/scenarios", "config/docker-compose.yml"],
  "retention": {
    "dailyDays": ${BACKUP_RETENTION_DAILY},
    "weeklyWeeks": ${BACKUP_RETENTION_WEEKLY},
    "monthlyMonths": ${BACKUP_RETENTION_MONTHLY}
  }
}
EOF
}

_encrypt_backup_archive() {
  local in_file="$1" out_file="$2"
  openssl enc -aes-256-cbc -pbkdf2 -salt -in "$in_file" -out "$out_file" -pass "file:${DATA_DIR}/.backup_key"
}

# _push_remote_backup copies the finished local archive to REMOTE_BACKUP_PATH.
# REMOTE_BACKUP_TYPE=mount assumes the operator already mounted the remote
# filesystem (NFS/SMB) at that path -- this function only copies into it.
# REMOTE_BACKUP_TYPE=rsync treats REMOTE_BACKUP_PATH as an rsync destination
# (local path or user@host:/path). Returns non-zero on failure; callers must
# not report "protected" unless this returns 0.
_push_remote_backup() {
  local archive="$1"
  [[ "$REMOTE_BACKUP_ENABLED" == "true" ]] || return 1
  [[ -n "$REMOTE_BACKUP_PATH" ]] || return 1
  case "$REMOTE_BACKUP_TYPE" in
    mount) cp "$archive" "${REMOTE_BACKUP_PATH}/" ;;
    rsync) rsync -a "$archive" "${REMOTE_BACKUP_PATH}/" ;;
    *) return 1 ;;
  esac
}

# _prune_backups keeps every archive within BACKUP_RETENTION_DAILY days,
# thins to one-per-week for BACKUP_RETENTION_WEEKLY weeks after that, one-
# per-month for BACKUP_RETENTION_MONTHLY months after that, deletes the rest.
_prune_backups() {
  local dir="${DATA_DIR}/backups"
  local daily_cutoff weekly_cutoff monthly_cutoff
  daily_cutoff=$(date -d "-${BACKUP_RETENTION_DAILY} days" +%s 2>/dev/null || date -v-"${BACKUP_RETENTION_DAILY}"d +%s)
  weekly_cutoff=$(date -d "-$((BACKUP_RETENTION_WEEKLY * 7)) days" +%s 2>/dev/null || date -v-"$((BACKUP_RETENTION_WEEKLY * 7))"d +%s)
  monthly_cutoff=$(date -d "-$((BACKUP_RETENTION_MONTHLY * 30)) days" +%s 2>/dev/null || date -v-"$((BACKUP_RETENTION_MONTHLY * 30))"d +%s)

  local seen_weeks="" seen_months=""
  for f in $(ls -1t "${dir}"/audspect-backup-*.tar.enc 2>/dev/null); do
    local mtime week_key month_key
    mtime=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f")
    [[ "$mtime" -ge "$daily_cutoff" ]] && continue
    week_key=$(date -d "@$mtime" +%G-%V 2>/dev/null || date -r "$mtime" +%G-%V)
    month_key=$(date -d "@$mtime" +%Y-%m 2>/dev/null || date -r "$mtime" +%Y-%m)
    if [[ "$mtime" -ge "$weekly_cutoff" ]]; then
      if [[ "$seen_weeks" == *"|${week_key}|"* ]]; then rm -f "$f"; else seen_weeks="${seen_weeks}|${week_key}|"; fi
    elif [[ "$mtime" -ge "$monthly_cutoff" ]]; then
      if [[ "$seen_months" == *"|${month_key}|"* ]]; then rm -f "$f"; else seen_months="${seen_months}|${month_key}|"; fi
    else
      rm -f "$f"
    fi
  done
}

# _run_backup_engine performs one full backup and prints the result as
# "STATUS|filename|size_bytes|sha256|local_path|remote_path|error" so both
# mode_backup (human-readable) and mode_backup_worker (writes to
# backup_jobs) can consume the same run.
_run_backup_engine() {
  local ts archive_dir work_dir tar_path enc_path status="protected" error=""
  ts=$(date -u +%Y%m%d-%H%M%S)
  archive_dir="${DATA_DIR}/backups"
  work_dir=$(mktemp -d)
  mkdir -p "${work_dir}/postgres" "${work_dir}/config"

  if ! _run_pg_dump "${work_dir}/postgres/audspect.dump"; then
    echo "FAILED|||||pg_dump failed"; rm -rf "$work_dir"; return 1
  fi
  _package_config "${work_dir}/config.tar"
  _write_backup_manifest "${work_dir}/manifest.json"

  tar_path="${work_dir}/audspect-backup-${ts}.tar"
  tar -cf "$tar_path" -C "$work_dir" postgres/audspect.dump config.tar manifest.json

  enc_path="${archive_dir}/audspect-backup-${ts}.tar.enc"
  if ! _encrypt_backup_archive "$tar_path" "$enc_path"; then
    echo "FAILED|||||encryption failed"; rm -rf "$work_dir"; return 1
  fi

  local size sha
  size=$(stat -c %s "$enc_path" 2>/dev/null || stat -f %z "$enc_path")
  sha=$(sha256sum "$enc_path" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$enc_path" | awk '{print $1}')
  echo "$sha" > "${enc_path}.sha256"

  local remote_path=""
  if [[ "$REMOTE_BACKUP_ENABLED" == "true" ]]; then
    if _push_remote_backup "$enc_path"; then
      remote_path="${REMOTE_BACKUP_PATH}/$(basename "$enc_path")"
    else
      status="local_success"
      error="local backup succeeded, remote replication failed"
    fi
  else
    status="local_success"
  fi

  _prune_backups
  rm -rf "$work_dir"
  echo "${status}|$(basename "$enc_path")|${size}|${sha}|${enc_path}|${remote_path}|${error}"
}

mode_backup() {
  [[ -f "${DATA_DIR}/docker-compose.yml" ]] || { err "No installation found at ${DATA_DIR}."; exit 1; }
  step "Running backup..."
  local result
  result=$(_run_backup_engine)
  IFS='|' read -r status filename size sha local_path remote_path error <<< "$result"
  if [[ "$status" == "FAILED" ]]; then
    err "Backup failed: ${error}"
    exit 1
  fi
  log "Backup complete: ${filename} (${size} bytes, status=${status})"
  [[ -n "$error" ]] && info "$error"
}

# mode_backup_request inserts one 'requested' row and exits -- it never
# performs a backup itself. Called by audspect-backup-schedule.timer (daily)
# and directly for CLI-triggered scheduling tests.
mode_backup_request() {
  local trigger="${TRIGGER:-cli}"
  docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc \
    "INSERT INTO backup_jobs (job_type, trigger) VALUES ('backup', '${trigger}')" >/dev/null
}

# mode_backup_worker performs exactly one poll-and-execute pass: claim the
# oldest 'requested' backup row (if any), run the same engine as --backup,
# write the result back. Called every 60s by audspect-backup-worker.timer --
# this is what makes console-requested, scheduled, and CLI-requested backups
# all execute through one path.
mode_backup_worker() {
  local id
  id=$(docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc \
    "SELECT id FROM backup_jobs WHERE status = 'requested' AND job_type = 'backup' ORDER BY requested_at LIMIT 1" 2>/dev/null | tr -d '[:space:]')
  [[ -z "$id" ]] && return 0

  local claimed
  claimed=$(docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc \
    "UPDATE backup_jobs SET status = 'running', started_at = now() WHERE id = '${id}' AND status = 'requested' RETURNING id" 2>/dev/null | tr -d '[:space:]')
  [[ -z "$claimed" ]] && return 0  # lost the race to another worker instance

  local result status filename size sha local_path remote_path error
  result=$(_run_backup_engine)
  IFS='|' read -r status filename size sha local_path remote_path error <<< "$result"
  if [[ "$status" == "FAILED" ]]; then status="failed"; fi

  docker exec audspect-postgres psql -U bas_user -d bas_platform -c "
    UPDATE backup_jobs SET
      status = '${status}',
      finished_at = now(),
      archive_filename = NULLIF('${filename}', ''),
      archive_size_bytes = NULLIF('${size}', '')::bigint,
      sha256 = NULLIF('${sha}', ''),
      local_path = NULLIF('${local_path}', ''),
      remote_path = NULLIF('${remote_path}', ''),
      error_message = NULLIF('${error}', '')
    WHERE id = '${claimed}'
  " >/dev/null
}

# mode_restore is the only place a restore ever actually executes. Requires
# root, an existing archive under DATA_DIR/backups (or an absolute path),
# and the literal word RESTORE typed at the confirmation prompt -- mirrors
# this script's other destructive-op confirmations (see mode_uninstall).
mode_restore() {
  local archive="$1"
  [[ -z "$archive" ]] && { err "Usage: sudo bash install.sh --restore <archive-filename-or-path>"; exit 1; }
  [[ "$archive" != /* ]] && archive="${DATA_DIR}/backups/${archive}"
  [[ -f "$archive" ]] || { err "Archive not found: ${archive}"; exit 1; }

  step "1/8  Verifying archive integrity"
  if [[ -f "${archive}.sha256" ]]; then
    local expected actual
    expected=$(cat "${archive}.sha256")
    actual=$(sha256sum "$archive" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$archive" | awk '{print $1}')
    [[ "$expected" == "$actual" ]] || { err "Checksum mismatch -- archive may be corrupt. Refusing to restore."; exit 1; }
  else
    info "No .sha256 sidecar found for this archive -- skipping integrity check."
  fi

  step "2/8  Decrypting and reading manifest"
  local work_dir tar_path
  work_dir=$(mktemp -d)
  tar_path="${work_dir}/archive.tar"
  openssl enc -d -aes-256-cbc -pbkdf2 -in "$archive" -out "$tar_path" -pass "file:${DATA_DIR}/.backup_key" \
    || { err "Decryption failed -- wrong .backup_key or corrupt archive."; rm -rf "$work_dir"; exit 1; }
  tar -xf "$tar_path" -C "$work_dir"
  [[ -f "${work_dir}/manifest.json" ]] || { err "Archive missing manifest.json -- refusing to restore."; rm -rf "$work_dir"; exit 1; }
  local archive_version
  archive_version=$(grep -o '"basVersion"[^,]*' "${work_dir}/manifest.json" | grep -o '"[^"]*"$' | tr -d '"')
  info "Archive BAS version: ${archive_version:-unknown}. Installed: ${BAS_VERSION}."

  echo
  echo "  This will STOP Audspect, REPLACE the current database and configuration"
  echo "  with the contents of ${archive}, then restart."
  echo
  read -r -p "  Type RESTORE to continue: " confirm
  [[ "$confirm" == "RESTORE" ]] || { info "Aborted -- no changes made."; rm -rf "$work_dir"; exit 0; }

  step "3/8  Taking a pre-restore safety snapshot"
  TRIGGER=pre_restore _run_backup_engine >/dev/null || info "Pre-restore snapshot failed -- continuing anyway (you typed RESTORE)."

  step "4/8  Stopping services"
  (cd "${DATA_DIR}" && docker compose -p "$COMPOSE_PROJECT" stop orchestrator caldera chrome)

  step "5/8  Restoring PostgreSQL"
  docker exec -i audspect-postgres pg_restore -U bas_user -d bas_platform --clean --if-exists < "${work_dir}/postgres/audspect.dump" \
    || { err "pg_restore failed -- database may be in a partial state. The pre-restore snapshot is at ${DATA_DIR}/backups/ if you need to recover from before this attempt."; rm -rf "$work_dir"; exit 1; }

  step "6/8  Restoring configuration"
  tar -xf "${work_dir}/config.tar" -C "${DATA_DIR}"

  step "7/8  Starting services"
  (cd "${DATA_DIR}" && docker compose -p "$COMPOSE_PROJECT" up -d --remove-orphans)
  _wait_healthy

  step "8/8  Health check"
  if curl -fsSk "https://localhost:${BAS_ENROLL_PORT:-9444}/health" >/dev/null 2>&1; then
    log "Restore complete and healthy."
  else
    err "Restore finished but health check failed -- inspect 'docker compose logs orchestrator'."
  fi
  rm -rf "$work_dir"
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
  warn "Orchestrator health check timed out after ${max}s -- running diagnostics..."
  _diagnose_orchestrator_failure
}

# _diagnose_orchestrator_failure runs targeted checks for the failure mode
# hit in production 2026-08-20 AND AGAIN 2026-08-24 (both HDFC, both port
# 53/udp): a port-bind conflict left the orchestrator container with NO
# network attached at all (not a DNS/config problem -- Docker aborts the
# whole network setup when a published port fails to bind), which just
# looked like a generic DB-connect crash-loop until someone manually worked
# through `docker inspect`/`journalctl` by hand.
#
# 2026-08-24 root-caused the RECURRING trigger: the port was published as
# "53:53/udp" (the 0.0.0.0 wildcard), which conflicts at the kernel level
# with systemd-resolved's stub listener (127.0.0.53/.54:53, loopback-only --
# Linux won't let a wildcard and a specific-address bind coexist on one
# port). Fixed structurally: the port is now published against a specific
# host IP (DNS_SINK_BIND_IP, auto-detected in load_config, see
# setup.conf.template) instead of the wildcard, so it can never overlap
# with a loopback-scoped listener again -- this also removes the 2026-08-20
# "stale reservation" case's actual trigger, since that was a stale
# reservation FOR THE WILDCARD BIND specifically; a differently-addressed
# bind request doesn't reuse the same stale entry. This function stays as
# defense-in-depth (e.g. DNS_SINK_BIND_IP genuinely colliding with a real
# service on that IP), not the primary line of defense anymore.
#
# Deliberately does NOT restart the Docker daemon automatically -- that was
# the 2026-08-20 workaround for a stale port reservation, but it briefly
# stops every container on the host, including anything else sharing it;
# that's an operator decision, not something this script should do
# unattended.
_diagnose_orchestrator_failure() {
  echo ""
  echo "  --  Orchestrator diagnostics  -----------------------------------"

  local state
  state=$(docker inspect --format '{{.State.Status}}' audspect-orchestrator 2>/dev/null || echo "missing")
  echo "  Container state : ${state}"

  if [[ "$state" == "created" ]]; then
    echo "  - Container never started (stuck in 'created') -- its network"
    echo "    setup likely failed. Removing it so the next attempt gets a"
    echo "    clean slate:"
    if docker rm audspect-orchestrator >/dev/null 2>&1; then
      echo "    Removed -- re-run this command to try again."
    fi
  fi

  local networks
  networks=$(docker inspect --format '{{json .NetworkSettings.Networks}}' audspect-orchestrator 2>/dev/null || echo "{}")
  if [[ "$networks" == "{}" || "$networks" == "null" ]]; then
    echo "  - Container has NO network attached (NetworkSettings.Networks"
    echo "    is empty). Docker failed to attach networking entirely --"
    echo "    usually because a published port failed to bind. Checking"
    echo "    the Docker daemon log for a port conflict..."
    if journalctl -u docker --since "5 minutes ago" 2>/dev/null | grep -q "address already in use"; then
      echo ""
      echo "  - CONFIRMED: Docker failed to bind a published port:"
      journalctl -u docker --since "5 minutes ago" 2>/dev/null | grep "address already in use" | tail -3 | sed 's/^/      /' || true
      echo ""
      echo "    This exact failure hit HDFC prod 2026-08-20 on port 53/udp"
      echo "    (the DNS-tunneling exfiltration listener) with nothing"
      echo "    visible in 'ss -ulnp' or 'lsof' holding it -- a stale"
      echo "    Docker-level port reservation can survive even after the"
      echo "    process that held it is gone. Restarting the Docker daemon"
      echo "    clears it, but that briefly stops EVERY container on this"
      echo "    host -- not something to do unattended. To do it manually:"
      echo "      sudo systemctl restart docker"
      echo "      docker compose -p ${COMPOSE_PROJECT} up -d"
      echo "    If you can't take that downtime right now, temporarily drop"
      echo "    the conflicting port from the orchestrator service's"
      echo "    'ports:' list in ${DATA_DIR}/docker-compose.yml and re-run"
      echo "    this command -- everything except that one feature keeps"
      echo "    working."
    fi
  fi

  echo "  Recent orchestrator logs:"
  docker compose -p "$COMPOSE_PROJECT" logs --tail=15 orchestrator 2>/dev/null | sed 's/^/    /' || true
  echo "  -------------------------------------------------------------------"
  echo ""
  warn "Orchestrator did not become healthy -- see diagnostics above, or: docker compose -p ${COMPOSE_PROJECT} logs orchestrator"
}

_create_admin() {
  # Give the orchestrator a moment then POST the admin user via its internal API.
  # Dashboard listener (Task 2/4 of the deployment-topology plan) is always
  # TLS, self-signed against the deployment CA by default -- -k skips
  # verification, same reasoning as the enrollment-listener health probe.
  local url="https://localhost:${BAS_DASHBOARD_PORT:-9543}/api/auth/setup"
  local attempts=0
  while [[ $attempts -lt 5 ]]; do
    local http
    http=$(curl -sfk -o /dev/null -w "%{http_code}" -X POST "$url" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" 2>/dev/null || echo "000")
    if [[ "$http" == "200" || "$http" == "201" || "$http" == "409" ]]; then
      log "Admin user ready: ${ADMIN_EMAIL}"
      return
    fi
    sleep 3; attempts=$(( attempts + 1 ))
  done
  warn "Could not create admin automatically -log in and create manually if needed"
}

_write_install_log() {
  local log_file="$1"
  local docker_note="pre-existing"
  $DOCKER_AUTO_INSTALLED && docker_note="auto-installed by installer"
  {
    echo "Audspect BAS -Install Log"
    echo "Timestamp : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Version   : ${BAS_VERSION}"
    echo "Host      : $(hostname -f 2>/dev/null || hostname)"
    echo "Data dir  : ${DATA_DIR}"
    echo "mTLS port (agents)     : ${BAS_PORT}"
    echo "Enroll port (agents)   : ${BAS_ENROLL_PORT}"
    echo "Legacy port (agents)   : ${BAS_LEGACY_PORT}"
    echo "Dashboard port         : ${BAS_DASHBOARD_PORT}"
    echo "TLS       : ${BAS_TLS}"
    echo "Admin     : ${ADMIN_EMAIL}"
    echo "Docker CE : ${docker_note}"
  } >> "$log_file"
  chmod 640 "$log_file"
}

_print_access_info() {
  local host
  host=$(hostname -f 2>/dev/null || hostname)
  echo ""
  echo "  Access dashboard : https://${host}:${BAS_DASHBOARD_PORT:-9543}"
  if [[ "$BAS_TLS" != "true" ]]; then
    echo "                     (your browser will show a certificate warning on first"
    echo "                     visit -- the dashboard uses a self-signed certificate by"
    echo "                     default; this is expected. Set TLS_CERT/TLS_KEY in"
    echo "                     setup.conf to use a properly-trusted certificate instead.)"
  fi
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
echo -e "${BOLD}${CYAN}===  ${PRODUCT} v${BAS_VERSION}  ===${NC}"
echo ""

case "$MODE" in
  check)     mode_check     ;;
  install)   mode_install   ;;
  upgrade)   mode_upgrade   ;;
  rollback)  mode_rollback  ;;
  status)    mode_status    ;;
  uninstall) mode_uninstall ;;
  backup)         mode_backup         ;;
  backup-request) mode_backup_request ;;
  backup-worker)  mode_backup_worker  ;;
  restore)        mode_restore "$RESTORE_ARCHIVE" ;;
esac
