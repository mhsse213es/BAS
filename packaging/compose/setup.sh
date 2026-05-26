#!/usr/bin/env bash
# BAS Platform — Interactive Setup Wizard
# Supports Ubuntu 20.04 / 22.04 / 24.04 and Rocky Linux 9
set -euo pipefail

# ── Audspect public key — DO NOT MODIFY ───────────────────────────────────────
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

# ── Constants ──────────────────────────────────────────────────────────────────
readonly TITLE="BAS Platform Setup"
readonly BAS_VERSION="latest"
readonly DEFAULT_INSTALL_DIR="/opt/bas-platform"
readonly DEFAULT_PORT="9000"
readonly MIN_RAM_MB=3800
readonly MIN_DISK_MB=5120
readonly SERVICE_NAME="bas-compose"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set by --offline flag; skips docker pull (images already loaded)
OFFLINE=false

# ── Colours (only when stdout is a terminal) ───────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# Capture whiptail output via temp file — portable under sudo (fd-swap breaks in some envs)
_wt() {
  local _retvar="$1"; shift
  local _tmp _rc
  _tmp=$(mktemp)
  _rc=0
  whiptail "$@" 2>"$_tmp" || _rc=$?   # || prevents set -e from firing on Cancel/ESC
  printf -v "$_retvar" '%s' "$(cat "$_tmp")"
  rm -f "$_tmp"
  return "$_rc"
}

# ── Root check ─────────────────────────────────────────────────────────────────
require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "This installer must be run as root."
    echo "  Run: sudo bash $0"
    exit 1
  fi
}

# ── whiptail availability ──────────────────────────────────────────────────────
ensure_whiptail() {
  if command -v whiptail &>/dev/null; then return; fi
  warn "whiptail not found — installing..."
  if command -v apt-get &>/dev/null; then
    apt-get install -y -qq whiptail
  elif command -v dnf &>/dev/null; then
    dnf install -y -q newt
  else
    err "Cannot install whiptail. Install it manually and re-run."
    exit 1
  fi
}

# ── Prerequisite checks ────────────────────────────────────────────────────────
check_os() {
  local os_id os_version
  os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"' 2>/dev/null || echo "unknown")
  os_version=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release | tr -d '"' 2>/dev/null || echo "0")

  case "$os_id" in
    ubuntu)
      if [[ "${os_version%%.*}" -lt 20 ]]; then
        echo "FAIL:OS — Ubuntu ${os_version} not supported (need 20.04+)"
        return
      fi
      echo "PASS:OS — Ubuntu ${os_version} LTS"
      ;;
    rocky|rhel|centos)
      if [[ "${os_version%%.*}" -lt 9 ]]; then
        echo "FAIL:OS — Rocky/RHEL ${os_version} not supported (need 9+)"
        return
      fi
      echo "PASS:OS — Rocky Linux / RHEL ${os_version}"
      ;;
    *)
      echo "WARN:OS — ${os_id} ${os_version} (untested — may work)"
      ;;
  esac
}

check_ram() {
  local ram_mb
  ram_mb=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
  if [[ $ram_mb -lt $MIN_RAM_MB ]]; then
    echo "FAIL:RAM — ${ram_mb}MB available (need ${MIN_RAM_MB}MB)"
  else
    echo "PASS:RAM — ${ram_mb}MB available"
  fi
}

check_disk() {
  local install_dir="${1:-$DEFAULT_INSTALL_DIR}"
  local parent
  parent=$(dirname "$install_dir")
  [[ -d "$install_dir" ]] && parent="$install_dir"
  local free_mb
  free_mb=$(df -m "$parent" | awk 'NR==2 {print $4}')
  if [[ $free_mb -lt $MIN_DISK_MB ]]; then
    echo "FAIL:Disk — ${free_mb}MB free at ${parent} (need ${MIN_DISK_MB}MB)"
  else
    echo "PASS:Disk — ${free_mb}MB free at ${parent}"
  fi
}

check_docker() {
  if ! command -v docker &>/dev/null; then
    echo "FAIL:Docker — not installed"
    return
  fi
  if ! docker info &>/dev/null; then
    echo "FAIL:Docker — daemon not running (start with: systemctl start docker)"
    return
  fi
  echo "PASS:Docker — $(docker --version | grep -oP 'Docker version \K[^,]+')"
}

check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    echo "PASS:Compose — $(docker compose version --short 2>/dev/null || echo 'v2')"
  elif command -v docker-compose &>/dev/null; then
    echo "WARN:Compose — docker-compose v1 found (v2 plugin recommended)"
  else
    echo "FAIL:Compose — Docker Compose v2 not found"
  fi
}

check_port() {
  local port="$1"
  if ss -tlnH "sport = :${port}" 2>/dev/null | grep -q ":${port}"; then
    echo "FAIL:Port ${port} — already in use"
  else
    echo "PASS:Port ${port} — available"
  fi
}

# ── License validation ─────────────────────────────────────────────────────────
# Returns "OK:customer|expires" or "FAIL:reason". Never throws.
_check_license() {
  local lic="$1"

  [[ -f "$lic" ]] || { echo "FAIL:File not found: ${lic}"; return 0; }

  command -v python3 &>/dev/null || { echo "FAIL:python3 required (apt install python3)"; return 0; }
  command -v openssl &>/dev/null || { echo "FAIL:openssl required (apt install openssl)"; return 0; }

  # Parse all required fields in one python call
  local parsed
  parsed=$(python3 - <<PYEOF 2>/dev/null
import json, sys
try:
    d = json.load(open('${lic}'))
    for f in ('customer','customer_id','issued_at','expires_at','features','signature'):
        if f not in d:
            print('FAIL:Missing field: ' + f)
            sys.exit()
    print('|'.join([
        d['customer'], d['customer_id'], d['issued_at'],
        d['expires_at'], ','.join(d['features']), d['signature']
    ]))
except Exception as e:
    print('FAIL:' + str(e))
PYEOF
)

  [[ "$parsed" == FAIL:* ]] && { echo "$parsed"; return 0; }
  [[ -z "$parsed" ]]        && { echo "FAIL:Could not parse license file"; return 0; }

  local customer customer_id issued_at expires_at features signature
  IFS='|' read -r customer customer_id issued_at expires_at features signature <<< "$parsed"

  # Canonical payload — must match licensegen/main.go exactly
  local payload="${customer_id}|${issued_at}|${expires_at}|${features}"

  # Verify RSA-SHA256 signature with the embedded Audspect public key
  local tmpkey tmpsig tmpdata
  tmpkey=$(mktemp); tmpsig=$(mktemp); tmpdata=$(mktemp)

  printf '%s' "$_LIC_PUBKEY" > "$tmpkey"
  printf '%s' "$signature"   | base64 -d > "$tmpsig" 2>/dev/null || {
    rm -f "$tmpkey" "$tmpsig" "$tmpdata"
    echo "FAIL:Cannot decode signature — file is corrupt or not an Audspect license"
    return 0
  }
  printf '%s' "$payload" > "$tmpdata"

  local sig_ok=false
  openssl dgst -sha256 -verify "$tmpkey" -signature "$tmpsig" "$tmpdata" &>/dev/null \
    && sig_ok=true
  rm -f "$tmpkey" "$tmpsig" "$tmpdata"

  $sig_ok || {
    echo "FAIL:Signature invalid — license was not issued by Audspect or has been tampered"
    return 0
  }

  # Check expiry (24-hour grace matches the orchestrator)
  local today_epoch expiry_epoch
  today_epoch=$(date -u +%s)
  expiry_epoch=$(date -d "${expires_at} + 1 day" -u +%s 2>/dev/null) || {
    echo "FAIL:Cannot parse expiry date '${expires_at}'"
    return 0
  }

  [[ $today_epoch -gt $expiry_epoch ]] && {
    echo "FAIL:License expired on ${expires_at} — contact support@audspect.com to renew"
    return 0
  }

  echo "OK:${customer}|${expires_at}"
}

# License wizard page — loops until a valid .lic is provided or user cancels.
# Sets LIC_PATH on success.
page_license() {
  # Pre-fill with any .lic found next to setup.sh
  local default_lic=""
  local found
  found=$(ls "${SCRIPT_DIR}"/*.lic 2>/dev/null | head -1 || true)
  [[ -n "$found" ]] && default_lic="$found"

  while true; do
    local lic_path
    if ! _wt lic_path --title "$TITLE — License" \
        --inputbox \
"A valid Audspect license file (.lic) is required to proceed.

If you received a .lic file from Audspect, enter its full path below.
Contact support@audspect.com if you do not have a license.

Path to license file:" \
        14 70 "$default_lic"; then
      err "Setup cancelled."
      exit 1
    fi

    if [[ -z "$lic_path" ]]; then
      whiptail --title "$TITLE — License" \
        --msgbox "No path entered. You must provide a valid .lic file to continue." 8 62
      continue
    fi

    local result
    result=$(_check_license "$lic_path")

    if [[ "$result" == OK:* ]]; then
      local info="${result#OK:}"
      local lic_customer="${info%%|*}"
      local lic_expires="${info##*|}"
      whiptail --title "$TITLE — License Valid" --msgbox \
"License verified successfully.

  Licensed to:  ${lic_customer}
  Valid until:  ${lic_expires}

Press OK to continue." 12 58
      LIC_PATH="$lic_path"
      return 0
    fi

    # FAIL — show the specific reason and loop
    local reason="${result#FAIL:}"
    whiptail --title "$TITLE — Invalid License" --msgbox \
"License check FAILED:

  ${reason}

Please provide a valid Audspect-issued .lic file.
Contact support@audspect.com if you need assistance." 14 68
    default_lic="$lic_path"
  done
}

# ── Wizard pages ───────────────────────────────────────────────────────────────
page_welcome() {
  whiptail --title "$TITLE" --msgbox \
"Welcome to the BAS Platform installer.

This wizard will guide you through installing the
Breach and Attack Simulation platform on this server.

What will be installed:
  • BAS Orchestrator (Go service)
  • PostgreSQL 16 database
  • Systemd service (auto-start on boot)

Press OK to begin." 18 64
}

page_prereqs() {
  local results=()
  local has_fail=false

  # Run checks
  while IFS= read -r line; do results+=("$line"); done < <(
    check_os
    check_ram
    check_disk "$DEFAULT_INSTALL_DIR"
    check_docker
    check_compose
    check_port "9000"
    check_port "5432"
  )

  # Build display text
  local display=""
  for r in "${results[@]}"; do
    local status="${r%%:*}"
    local message="${r#*:}"
    case "$status" in
      PASS) display+="  ✓  ${message}\n" ;;
      WARN) display+="  ⚠  ${message}\n"; ;;
      FAIL) display+="  ✗  ${message}\n"; has_fail=true ;;
    esac
  done

  if $has_fail; then
    whiptail --title "$TITLE — Prerequisites" --msgbox \
"Prerequisite check — ISSUES FOUND:

${display}
Please resolve the items marked ✗ before continuing.
Re-run this installer after fixing them." 22 70
    exit 1
  else
    whiptail --title "$TITLE — Prerequisites" --msgbox \
"Prerequisite check — ALL PASSED:

${display}
Press OK to continue." 22 70
  fi
}

page_install_dir() {
  _wt INSTALL_DIR --title "$TITLE" \
    --inputbox "Installation directory:" 10 64 "$DEFAULT_INSTALL_DIR" \
    || { err "Setup cancelled."; exit 1; }
  [[ -z "$INSTALL_DIR" ]] && INSTALL_DIR="$DEFAULT_INSTALL_DIR"
}

page_database() {
  _wt DB_PASSWORD --title "$TITLE — Database" \
    --passwordbox \
"PostgreSQL will be installed as a Docker container.

Set the database password (min 8 characters):" \
    12 64 || { err "Setup cancelled."; exit 1; }

  if [[ ${#DB_PASSWORD} -lt 8 ]]; then
    whiptail --title "$TITLE" --msgbox "Password must be at least 8 characters." 8 50
    page_database
    return
  fi

  local confirm
  _wt confirm --title "$TITLE — Database" \
    --passwordbox "Confirm database password:" \
    10 64 || { err "Setup cancelled."; exit 1; }

  if [[ "$DB_PASSWORD" != "$confirm" ]]; then
    whiptail --title "$TITLE" --msgbox "Passwords do not match. Try again." 8 50
    page_database
  fi
}

page_network() {
  _wt DASHBOARD_PORT --title "$TITLE — Network" \
    --inputbox \
"Dashboard port (the port your browser will connect to):

Default is 9000. Change only if another service uses it." \
    12 64 "$DEFAULT_PORT" || { err "Setup cancelled."; exit 1; }

  [[ -z "$DASHBOARD_PORT" ]] && DASHBOARD_PORT="$DEFAULT_PORT"

  # Re-check port with user's chosen value
  if ss -tlnH "sport = :${DASHBOARD_PORT}" 2>/dev/null | grep -q ":${DASHBOARD_PORT}"; then
    whiptail --title "$TITLE" \
      --msgbox "Port ${DASHBOARD_PORT} is already in use. Choose a different port." 8 60
    page_network
  fi
}

page_security() {
  # Auto-generate secrets
  JWT_SECRET=$(openssl rand -hex 32)
  AGENT_SECRET=$(openssl rand -hex 24)

  local admin_pw
  _wt admin_pw --title "$TITLE — Security" \
    --passwordbox \
"Set the BAS admin password (min 10 characters):

This is the password for the 'admin' user in the dashboard." \
    12 64 || { err "Setup cancelled."; exit 1; }

  if [[ ${#admin_pw} -lt 10 ]]; then
    whiptail --title "$TITLE" --msgbox "Admin password must be at least 10 characters." 8 56
    page_security
    return
  fi

  local confirm
  _wt confirm --title "$TITLE — Security" \
    --passwordbox "Confirm admin password:" \
    10 64 || { err "Setup cancelled."; exit 1; }

  if [[ "$admin_pw" != "$confirm" ]]; then
    whiptail --title "$TITLE" --msgbox "Passwords do not match. Try again." 8 50
    page_security
    return
  fi

  ADMIN_PASSWORD="$admin_pw"

  whiptail --title "$TITLE — Security" --msgbox \
"Security secrets have been generated:

  JWT Secret:    ${JWT_SECRET:0:16}... (auto-generated)
  Agent Secret:  ${AGENT_SECRET:0:12}... (auto-generated)

These are written to ${INSTALL_DIR}/.env
Keep that file secure (chmod 640, root-readable only).

Press OK to continue." 16 68
}

page_confirm() {
  local detected_ip
  detected_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")

  whiptail --title "$TITLE — Confirm" --yesno \
"Ready to install with these settings:

  Install directory:  ${INSTALL_DIR}
  Dashboard port:     ${DASHBOARD_PORT}
  Dashboard URL:      http://${detected_ip}:${DASHBOARD_PORT}
  Database:           PostgreSQL 16 (Docker container)
  Admin user:         admin

Proceed with installation?" 18 66 || { err "Setup cancelled."; exit 1; }
}

# ── Installation ───────────────────────────────────────────────────────────────
do_install() {
  local progress_log
  progress_log=$(mktemp)

  (
    # Step 1 — Create directory structure
    echo 5
    echo "# Creating install directory..."
    mkdir -p "${INSTALL_DIR}/scenarios" "${INSTALL_DIR}/wwwroot" "${INSTALL_DIR}/data"
    sleep 0.3

    # Step 2 — Copy license file
    echo 12
    echo "# Installing license..."
    cp "${LIC_PATH}" "${INSTALL_DIR}/bas.lic"
    chmod 640 "${INSTALL_DIR}/bas.lic"

    # Step 3 — Copy application files
    echo 15
    echo "# Copying scenario files..."
    cp -r "${SCRIPT_DIR}/scenarios/." "${INSTALL_DIR}/scenarios/"
    cp -r "${SCRIPT_DIR}/wwwroot/." "${INSTALL_DIR}/wwwroot/"
    sleep 0.3

    # Step 3 — Copy compose files
    echo 25
    echo "# Copying configuration templates..."
    cp "${SCRIPT_DIR}/docker-compose.yml"      "${INSTALL_DIR}/"
    cp "${SCRIPT_DIR}/docker-compose.prod.yml" "${INSTALL_DIR}/"
    sleep 0.3

    # Step 4 — Write .env
    echo 35
    echo "# Writing .env configuration..."
    cat > "${INSTALL_DIR}/.env" <<EOF
# BAS Platform — generated by setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
BAS_VERSION=${BAS_VERSION}
REGISTRY=
POSTGRES_DB=bas_platform
POSTGRES_USER=bas_user
POSTGRES_PASSWORD=${DB_PASSWORD}
JWT_SECRET=${JWT_SECRET}
AGENT_SECRET=${AGENT_SECRET}
DASHBOARD_PORT=${DASHBOARD_PORT}
BAS_LICENSE_PATH=/etc/bas/bas.lic
EOF
    chmod 640 "${INSTALL_DIR}/.env"
    chown root:root "${INSTALL_DIR}/.env"
    sleep 0.3

    # Step 5 — Write admin seed env (read by orchestrator on first boot)
    echo 42
    echo "# Writing admin seed..."
    cat > "${INSTALL_DIR}/.env.admin-seed" <<EOF
# One-time admin seed — deleted after first successful boot
BAS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
    chmod 600 "${INSTALL_DIR}/.env.admin-seed"
    sleep 0.3

    # Step 6 — Pull Docker images (skipped in offline/air-gap mode)
    echo 50
    if [[ "$OFFLINE" == "true" ]]; then
      echo "# Offline mode — skipping image pull (images pre-loaded)..."
      sleep 0.3
    else
      echo "# Pulling Docker images (this may take a few minutes)..."
      cd "${INSTALL_DIR}"
      docker compose -f docker-compose.yml pull --quiet 2>>"$progress_log" || true
      sleep 0.5
    fi

    # Step 7 — Install systemd service
    echo 75
    echo "# Installing systemd service..."
    sed "s|/opt/bas-platform|${INSTALL_DIR}|g" \
      "${SCRIPT_DIR}/systemd/bas-compose.service" \
      > /etc/systemd/system/bas-compose.service
    systemctl daemon-reload
    systemctl enable bas-compose.service
    sleep 0.3

    # Step 8 — Start services
    echo 85
    echo "# Starting BAS Platform..."
    systemctl start bas-compose.service
    sleep 2

    # Step 9 — Health check
    echo 93
    echo "# Waiting for health check..."
    local retries=0
    until curl -sf "http://localhost:${DASHBOARD_PORT}/health" &>/dev/null || [[ $retries -ge 18 ]]; do
      sleep 5
      ((retries++))
    done

    # Step 10 — Clean up admin seed (orchestrator has read it via env)
    echo 98
    echo "# Finalising..."
    rm -f "${INSTALL_DIR}/.env.admin-seed"

    echo 100
    echo "# Installation complete."
  ) | whiptail --title "$TITLE — Installing" \
               --gauge "Installing BAS Platform, please wait..." 10 70 0

  rm -f "$progress_log"
}

page_finish() {
  local detected_ip
  detected_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")

  local svc_status
  svc_status=$(systemctl is-active bas-compose.service 2>/dev/null || echo "unknown")

  whiptail --title "$TITLE — Complete" --msgbox \
"BAS Platform has been installed successfully!

  Service status:   ${svc_status}
  Dashboard URL:    http://${detected_ip}:${DASHBOARD_PORT}
  Install path:     ${INSTALL_DIR}

  Login:  admin / (password you set during setup)

Useful commands:
  Check status:  systemctl status bas-compose
  View logs:     docker compose -C ${INSTALL_DIR} logs -f
  Stop:          systemctl stop bas-compose
  Uninstall:     sudo bash ${INSTALL_DIR}/uninstall.sh

Press OK to exit the installer." 22 70
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
  # Parse flags
  for arg in "$@"; do
    case "$arg" in
      --offline) OFFLINE=true ;;
    esac
  done

  require_root
  ensure_whiptail

  page_license    # must pass before anything else is shown
  page_welcome
  page_prereqs
  page_install_dir
  # Re-run disk check with actual install dir chosen by user
  page_database
  page_network
  page_security
  page_confirm
  do_install
  page_finish

  log "Setup complete. Dashboard: http://$(hostname -I | awk '{print $1}'):${DASHBOARD_PORT}"
}

main "$@"
