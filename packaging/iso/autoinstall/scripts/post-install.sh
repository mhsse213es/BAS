#!/usr/bin/env bash
# BAS Platform — Post-Install Script
#
# Runs on first boot (via bas-postinstall.service) after OS installation.
# Installs Docker, loads BAS images, and launches the first-boot config wizard.
#
# Expects either:
#   (a) /var/tmp/bas-airgap.tar.gz  — embedded bundle (offline install)
#   (b) Internet access             — Docker pulled, BAS setup via setup.sh
set -euo pipefail

LOG="/var/log/bas-postinstall.log"
STAGING="/opt/bas-platform-src"
DONE_MARKER="/opt/bas-platform/.postinstall-done"
AIRGAP_BUNDLE="/var/tmp/bas-airgap.tar.gz"
IMPORT_SCRIPT="/opt/bas-install/import.sh"

exec >> "${LOG}" 2>&1

log() { echo "[$(date -u +%T)] $*"; }

log "BAS post-install starting..."

# ── Idempotency guard ──────────────────────────────────────────────────────────
if [[ -f "$DONE_MARKER" ]]; then
  log "Already completed — exiting."
  exit 0
fi

# ── Install Docker CE ─────────────────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null; then
  log "Docker already installed."
else
  log "Installing Docker CE..."
  export DEBIAN_FRONTEND=noninteractive
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  usermod -aG docker bas 2>/dev/null || true
  log "Docker $(docker --version) installed."
fi

# ── Install BAS ───────────────────────────────────────────────────────────────
if [[ -f "$AIRGAP_BUNDLE" ]]; then
  # Offline path — airgap bundle embedded in ISO
  log "Airgap bundle found — running offline import..."

  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  tar -xzf "$AIRGAP_BUNDLE" -C "$WORK"
  BUNDLE_DIR=$(find "$WORK" -maxdepth 1 -mindepth 1 -type d | head -1)

  # Install the pinned cosign staged on the ISO (re-checked against cosign.pin).
  APPLIANCE_DIR="/opt/bas-install/appliance"
  if ! command -v cosign &>/dev/null; then
    if [[ -f "${APPLIANCE_DIR}/cosign-linux-amd64" ]] && \
       bash "${APPLIANCE_DIR}/fetch-cosign.sh" --verify "${APPLIANCE_DIR}/cosign-linux-amd64" "${APPLIANCE_DIR}/cosign.pin"; then
      install -m 0755 "${APPLIANCE_DIR}/cosign-linux-amd64" /usr/local/bin/cosign
      log "Installed pinned cosign to /usr/local/bin/cosign."
    else
      echo "ERROR: pinned cosign missing or failed its checksum -- cannot verify the orchestrator image." >&2
      exit 1
    fi
  fi

  # Refuse a legacy (unsigned) orchestrator image BEFORE any docker load.
  if compgen -G "${BUNDLE_DIR}/images/bas-orchestrator-*.tar.gz" >/dev/null; then
    echo "ERROR: legacy unsigned orchestrator image (bas-orchestrator-*.tar.gz) in bundle -- refusing. Re-pack with the current packaging/airgap/pack.sh." >&2
    exit 1
  fi
  # The orchestrator image is a cosign-signed bas-orchestrator-<v>.tar (not .tar.gz):
  # it is NOT loaded here. It is staged below and setup.sh --offline verifies the
  # signature (cosign >= v3.1.0 required on this host) before loading it.
  # Fail a bad bundle at provisioning time where cosign already exists; otherwise
  # setup.sh --offline performs the (mandatory) verification at first boot.
  if command -v cosign &>/dev/null; then
    err() { echo "ERROR: $*" >&2; }
    # shellcheck source=/dev/null
    source "${BUNDLE_DIR}/cosign-verify-lib.sh"
    BV=$(cat "${BUNDLE_DIR}/VERSION")
    airgap_verify_orchestrator "${BUNDLE_DIR}/images/bas-orchestrator-${BV}.tar" "${BUNDLE_DIR}/cosign.pub" || exit 1
  fi
  log "Loading Docker images (non-orchestrator)..."
  for img in "${BUNDLE_DIR}"/images/*.tar.gz; do
    case "$(basename "$img")" in bas-orchestrator-*) continue ;; esac
    log "  Loading $(basename "$img")..."
    docker load < "$img"
  done

  BAS_VERSION=$(cat "${BUNDLE_DIR}/VERSION" 2>/dev/null || echo "latest")
  # No :latest tagging: compose is pinned to the verified bas-orchestrator:<version>
  # via compose/VERSION, and setup.sh --offline loads that image after verification.

  log "Staging BAS files..."
  rm -rf "$STAGING"
  mkdir -p "$STAGING/compose"
  cp -r "${BUNDLE_DIR}/compose/." "$STAGING/compose/"
  mkdir -p "$STAGING/compose/images"
  cp "${BUNDLE_DIR}"/images/bas-orchestrator-* "$STAGING/compose/images/"
  cp "${BUNDLE_DIR}/cosign.pub" "$STAGING/compose/cosign.pub"
  echo "${BAS_VERSION}" > "$STAGING/VERSION"

  rm -f "$AIRGAP_BUNDLE"
  log "Airgap import complete."
else
  # Online path — images will be pulled at setup time
  log "No airgap bundle — BAS images will be pulled from registry during setup."
  mkdir -p "$STAGING/compose"
  # Copy compose files if they were bundled with the OS image by the Packer build
  # (they would be at /opt/bas-platform-src already if using Packer-built base)
fi

# ── Install first-boot wizard service ─────────────────────────────────────────
log "Installing bas-firstboot service..."
cat > /usr/local/sbin/bas-firstboot <<'FBEOF'
#!/usr/bin/env bash
set -euo pipefail
SETUP_SCRIPT="/opt/bas-platform-src/compose/setup.sh"
CONFIGURED_MARKER="/opt/bas-platform/.configured"
[[ -f "$CONFIGURED_MARKER" ]] && exit 0
[[ ! -f "$SETUP_SCRIPT" ]] && { echo "BAS: setup.sh not found." >&2; exit 1; }
clear
echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║         BAS Platform — Initial Configuration            ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  See /root/LUKS-PASSPHRASE.txt for your disk encryption key."
echo ""
bash "$SETUP_SCRIPT" --offline
if [[ $? -eq 0 ]]; then
  mkdir -p "$(dirname "$CONFIGURED_MARKER")"
  touch "$CONFIGURED_MARKER"
  systemctl disable bas-firstboot.service 2>/dev/null || true
fi
FBEOF
chmod 0755 /usr/local/sbin/bas-firstboot

cat > /etc/systemd/system/bas-firstboot.service <<'UNIT'
[Unit]
Description=BAS Platform First-Boot Configuration Wizard
After=multi-user.target bas-postinstall.service
Requires=bas-postinstall.service
ConditionPathExists=!/opt/bas-platform/.configured

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/bas-firstboot
StandardInput=tty
StandardOutput=tty
StandardError=journal+console
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable bas-firstboot.service
systemctl disable bas-postinstall.service 2>/dev/null || true

mkdir -p "$(dirname "$DONE_MARKER")"
touch "$DONE_MARKER"
log "Post-install complete. First-boot wizard will launch on next boot."
