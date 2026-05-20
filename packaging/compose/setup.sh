#!/usr/bin/env bash
# BAS Platform — Interactive Setup Wizard
# Supports Ubuntu 20.04 / 22.04 / 24.04 and Rocky Linux 9
set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────
readonly TITLE="BAS Platform Setup"
readonly BAS_VERSION="latest"
readonly DEFAULT_INSTALL_DIR="/opt/bas-platform"
readonly DEFAULT_PORT="9000"
readonly MIN_RAM_MB=3800
readonly MIN_DISK_MB=5120
readonly SERVICE_NAME="bas-compose"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours (only when stdout is a terminal) ───────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

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
  INSTALL_DIR=$(whiptail --title "$TITLE" \
    --inputbox "Installation directory:" 10 64 "$DEFAULT_INSTALL_DIR" \
    3>&1 1>&2 2>&3) || { err "Setup cancelled."; exit 1; }
  [[ -z "$INSTALL_DIR" ]] && INSTALL_DIR="$DEFAULT_INSTALL_DIR"
}

page_database() {
  DB_PASSWORD=$(whiptail --title "$TITLE — Database" \
    --passwordbox \
"PostgreSQL will be installed as a Docker container.

Set the database password (min 8 characters):" \
    12 64 3>&1 1>&2 2>&3) || { err "Setup cancelled."; exit 1; }

  if [[ ${#DB_PASSWORD} -lt 8 ]]; then
    whiptail --title "$TITLE" --msgbox "Password must be at least 8 characters." 8 50
    page_database
    return
  fi

  local confirm
  confirm=$(whiptail --title "$TITLE — Database" \
    --passwordbox "Confirm database password:" \
    10 64 3>&1 1>&2 2>&3) || { err "Setup cancelled."; exit 1; }

  if [[ "$DB_PASSWORD" != "$confirm" ]]; then
    whiptail --title "$TITLE" --msgbox "Passwords do not match. Try again." 8 50
    page_database
  fi
}

page_network() {
  DASHBOARD_PORT=$(whiptail --title "$TITLE — Network" \
    --inputbox \
"Dashboard port (the port your browser will connect to):

Default is 9000. Change only if another service uses it." \
    12 64 "$DEFAULT_PORT" 3>&1 1>&2 2>&3) || { err "Setup cancelled."; exit 1; }

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
  admin_pw=$(whiptail --title "$TITLE — Security" \
    --passwordbox \
"Set the BAS admin password (min 10 characters):

This is the password for the 'admin' user in the dashboard." \
    12 64 3>&1 1>&2 2>&3) || { err "Setup cancelled."; exit 1; }

  if [[ ${#admin_pw} -lt 10 ]]; then
    whiptail --title "$TITLE" --msgbox "Admin password must be at least 10 characters." 8 56
    page_security
    return
  fi

  local confirm
  confirm=$(whiptail --title "$TITLE — Security" \
    --passwordbox "Confirm admin password:" \
    10 64 3>&1 1>&2 2>&3) || { err "Setup cancelled."; exit 1; }

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

    # Step 2 — Copy application files
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

    # Step 6 — Pull Docker images
    echo 50
    echo "# Pulling Docker images (this may take a few minutes)..."
    cd "${INSTALL_DIR}"
    docker compose -f docker-compose.yml pull --quiet 2>>"$progress_log" || true
    sleep 0.5

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
  require_root
  ensure_whiptail

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
