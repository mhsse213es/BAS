#!/usr/bin/env bash
# Packer provisioner — Step 2: Stage BAS files and install first-boot service
set -euo pipefail

BAS_VERSION="${BAS_VERSION:-latest}"
BUNDLE="/var/tmp/bas-airgap.tar.gz"
STAGING_DIR="/opt/bas-platform-src"

# ── 1. Extract air-gap bundle ──────────────────────────────────────────────────
echo "[install-bas] Extracting bundle..."
if [[ ! -f "$BUNDLE" ]]; then
  echo "[install-bas] ERROR: $BUNDLE not found. Did the file provisioner succeed?"
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -xzf "$BUNDLE" -C "$WORK"
BUNDLE_DIR=$(find "$WORK" -maxdepth 1 -mindepth 1 -type d | head -1)

# ── 2. Load Docker images (baked into VM so first-boot is instant) ─────────────
echo "[install-bas] Loading Docker images..."
for img in "${BUNDLE_DIR}"/images/*.tar.gz; do
  echo "  Loading: $(basename "$img")"
  docker load < "$img"
done

# Ensure versioned image also has :latest tag for docker-compose.yml default
if docker image inspect "bas-orchestrator:${BAS_VERSION}" &>/dev/null && \
   ! docker image inspect "bas-orchestrator:latest" &>/dev/null; then
  docker tag "bas-orchestrator:${BAS_VERSION}" "bas-orchestrator:latest"
fi

echo "[install-bas] Docker images loaded:"
docker images | grep -E "(bas-orchestrator|postgres)" | awk '{printf "  %-40s %s\n", $1":"$2, $3}'

# ── 3. Stage compose bundle ────────────────────────────────────────────────────
echo "[install-bas] Staging BAS files to ${STAGING_DIR}..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/compose"
cp -r "${BUNDLE_DIR}/compose/." "$STAGING_DIR/compose/"
echo "${BAS_VERSION}" > "$STAGING_DIR/VERSION"

# ── 4. Install first-boot systemd service ─────────────────────────────────────
echo "[install-bas] Installing bas-firstboot service..."

# The firstboot wrapper script
cat > /usr/local/sbin/bas-firstboot <<'FBSCRIPT'
#!/usr/bin/env bash
# Runs setup.sh on first VM boot, then disables itself.
set -euo pipefail

STAGING_DIR="/opt/bas-platform-src"
SETUP_SCRIPT="${STAGING_DIR}/compose/setup.sh"
CONFIGURED_MARKER="/opt/bas-platform/.configured"

if [[ -f "$CONFIGURED_MARKER" ]]; then
  exit 0
fi

if [[ ! -f "$SETUP_SCRIPT" ]]; then
  echo "BAS first-boot: setup.sh not found at ${SETUP_SCRIPT}" >&2
  exit 1
fi

clear
echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║         BAS Platform — First Boot Configuration         ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  This wizard will configure your BAS Platform appliance."
echo "  It will only run once. Press ENTER to begin..."
read -r

# Run setup wizard in offline mode (Docker images are pre-loaded in this VM)
bash "$SETUP_SCRIPT" --offline
SETUP_RC=$?

if [[ $SETUP_RC -eq 0 ]]; then
  mkdir -p "$(dirname "$CONFIGURED_MARKER")"
  touch "$CONFIGURED_MARKER"
  systemctl disable bas-firstboot.service 2>/dev/null || true
  echo ""
  echo "  BAS Platform configured successfully."
fi
FBSCRIPT
chmod 0755 /usr/local/sbin/bas-firstboot

# The systemd unit — runs on tty1 before login prompt
cat > /etc/systemd/system/bas-firstboot.service <<'UNIT'
[Unit]
Description=BAS Platform First-Boot Configuration Wizard
Documentation=https://github.com/audspect/bas
After=multi-user.target
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

# ── 5. Clean up bundle ─────────────────────────────────────────────────────────
rm -f "$BUNDLE"
echo "[install-bas] Done. First-boot service installed."
