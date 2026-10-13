#!/usr/bin/env bash
# BAS Platform — Post-Install Script
#
# Runs on first boot (via bas-postinstall.service) after OS installation.
# Installs Docker, loads BAS images, and launches the first-boot config wizard.
#
# Expects either:
#   (a) /var/tmp/bas-airgap.tar.gz  — embedded bundle (offline install)
#   (b) signed images already staged in /opt/bas-platform-src/compose/images
#       (Packer-built base); setup.sh never pulls BAS images from a registry
set -euo pipefail

# BAS_ROOT is a path prefix used ONLY by the test suite to sandbox every path
# below (empty on a real host).
R="${BAS_ROOT:-}"
LOG="${R}/var/log/bas-postinstall.log"
STAGING="${R}/opt/bas-platform-src"
DONE_MARKER="${R}/opt/bas-platform/.postinstall-done"
AIRGAP_BUNDLE="${R}/var/tmp/bas-airgap.tar.gz"
APPLIANCE_DIR="${APPLIANCE_DIR:-${R}/opt/bas-install/appliance}"
COSIGN_BIN="${R}/usr/local/bin/cosign"

exec >> "${LOG}" 2>&1

log() { echo "[$(date -u +%T)] $*"; }
# Fail-closed errors go to the log, the journal AND the console (the log alone
# is invisible to an operator watching first boot).
fatal() {
  echo "ERROR: $*" >&2
  logger -t bas-postinstall -p user.err -- "$*" 2>/dev/null || true
  { echo "bas-postinstall: ERROR: $*" > /dev/console; } 2>/dev/null || true
  exit 1
}
err() { echo "ERROR: $*" >&2; }

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

  BAS_VERSION=$(cat "${BUNDLE_DIR}/VERSION" 2>/dev/null || echo "latest")
  # setup.sh pins .env to compose/VERSION: it must equal the version we verify.
  [[ "$(tr -d '[:space:]' < "${BUNDLE_DIR}/compose/VERSION" 2>/dev/null)" == "$(echo "$BAS_VERSION" | tr -d '[:space:]')" ]] \
    || fatal "compose/VERSION does not match bundle VERSION (${BAS_VERSION}) -- compose would run a different image than the verified one."

  # Install the pinned cosign staged on the ISO (re-checked against cosign.pin).
  if ! command -v cosign &>/dev/null; then
    if [[ -f "${APPLIANCE_DIR}/cosign-linux-amd64" ]] && \
       bash "${APPLIANCE_DIR}/fetch-cosign.sh" --verify "${APPLIANCE_DIR}/cosign-linux-amd64" "${APPLIANCE_DIR}/cosign.pin"; then
      mkdir -p "$(dirname "$COSIGN_BIN")"
      install -m 0755 "${APPLIANCE_DIR}/cosign-linux-amd64" "$COSIGN_BIN"
      PATH="$(dirname "$COSIGN_BIN"):$PATH"; export PATH
      log "Installed pinned cosign to ${COSIGN_BIN}."
    else
      fatal "pinned cosign missing or failed its checksum -- cannot verify the images."
    fi
  fi

  # Verify EVERY image tar (cosign + tag + image-ID binding), then load them
  # orchestrator-last. Nothing unverified is ever loaded; a legacy .tar.gz or any
  # unsigned/unlisted file is fatal. A bad bundle fails here, not at first boot.
  # shellcheck source=/dev/null
  source "${BUNDLE_DIR}/cosign-verify-lib.sh"
  log "Verifying and loading Docker images..."
  airgap_verify_and_load_images "${BUNDLE_DIR}/images" "${BUNDLE_DIR}/cosign.pub" "$BAS_VERSION" \
    || fatal "image verification/loading failed -- refusing to continue."

  log "Staging BAS files..."
  rm -rf "$STAGING"
  mkdir -p "$STAGING/compose/images"
  cp -r "${BUNDLE_DIR}/compose/." "$STAGING/compose/"
  # Signed tars + bundles + key: setup.sh --offline re-verifies from here at first boot.
  cp "${BUNDLE_DIR}"/images/*.tar "${BUNDLE_DIR}"/images/*.tar.bundle "$STAGING/compose/images/"
  cp "${BUNDLE_DIR}/cosign.pub" "$STAGING/compose/cosign.pub"
  echo "${BAS_VERSION}" > "$STAGING/VERSION"

  rm -f "$AIRGAP_BUNDLE"
  log "Airgap import complete."
else
  # No embedded bundle: setup.sh NEVER pulls images. It installs only from signed
  # images already staged under ${STAGING}/compose/images (e.g. by the Packer
  # install-bas.sh build) and refuses to install without them.
  log "No airgap bundle — setup.sh will use the signed images staged in ${STAGING}/compose/images (it refuses without them; nothing is pulled)."
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
