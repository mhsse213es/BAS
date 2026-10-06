#!/usr/bin/env bash
# Packer provisioner — Step 2: Stage BAS files and install first-boot service
set -euo pipefail

# BAS_ROOT is a path prefix used ONLY by the test suite to sandbox every path
# below (empty on a real VM).
R="${BAS_ROOT:-}"
BUNDLE="${R}/var/tmp/bas-airgap.tar.gz"
STAGING_DIR="${R}/opt/bas-platform-src"
APPLIANCE_DIR="${APPLIANCE_DIR:-${R}/var/tmp/bas-appliance}"
COSIGN_BIN="${R}/usr/local/bin/cosign"

err() { echo "ERROR: $*" >&2; }

# ── 0. Install pinned cosign (build-time download, sha256-pinned; fails the build) ─
bash "${APPLIANCE_DIR}/fetch-cosign.sh" "$COSIGN_BIN" "${APPLIANCE_DIR}/cosign.pin" \
  || { err "pinned cosign could not be installed -- failing the image build."; exit 1; }
PATH="$(dirname "$COSIGN_BIN"):$PATH"; export PATH
rm -rf "$APPLIANCE_DIR"

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

# The bundle's own VERSION is authoritative; compose/VERSION (which setup.sh pins
# .env to) must equal it, so compose runs the image we verify.
BAS_VERSION=$(cat "${BUNDLE_DIR}/VERSION" 2>/dev/null || echo "latest")
if [[ "$(tr -d '[:space:]' < "${BUNDLE_DIR}/compose/VERSION" 2>/dev/null)" != "$(echo "$BAS_VERSION" | tr -d '[:space:]')" ]]; then
  err "compose/VERSION does not match bundle VERSION (${BAS_VERSION}) -- refusing."
  exit 1
fi

# ── 2. Verify EVERY image (cosign + tag + image ID), then load orchestrator-last ─
# Nothing unverified is ever loaded; a legacy .tar.gz or any unsigned/unlisted
# file is fatal. A bad bundle fails the image build here, not at first boot.
# shellcheck source=/dev/null
source "${BUNDLE_DIR}/cosign-verify-lib.sh"
echo "[install-bas] Verifying and loading Docker images..."
airgap_verify_and_load_images "${BUNDLE_DIR}/images" "${BUNDLE_DIR}/cosign.pub" "$BAS_VERSION" \
  || { err "image verification/loading failed -- failing the image build."; exit 1; }
# No :latest tagging: compose is pinned to the verified bas-orchestrator:<version>
# via compose/VERSION.

echo "[install-bas] Docker images loaded:"
docker images | grep -E "(bas-orchestrator|postgres)" | awk '{printf "  %-40s %s\n", $1":"$2, $3}' || true

# ── 3. Stage compose bundle ────────────────────────────────────────────────────
echo "[install-bas] Staging BAS files to ${STAGING_DIR}..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/compose/images"
cp -r "${BUNDLE_DIR}/compose/." "$STAGING_DIR/compose/"
# Signed tars + bundles + key: setup.sh --offline re-verifies from here at first boot.
cp "${BUNDLE_DIR}"/images/*.tar "${BUNDLE_DIR}"/images/*.tar.bundle "$STAGING_DIR/compose/images/"
cp "${BUNDLE_DIR}/cosign.pub" "$STAGING_DIR/compose/cosign.pub"
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
BAS_REQUIRE_SIGNED_IMAGES=1 bash "$SETUP_SCRIPT" --offline
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
