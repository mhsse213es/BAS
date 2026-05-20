#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Packer
#
# Run this on an INTERNET-CONNECTED build machine.
# Produces a self-contained bundle that can be transferred to an air-gapped server.
#
# Usage:
#   bash packaging/airgap/pack.sh [version]
#
# Example:
#   bash packaging/airgap/pack.sh 1.2.0
#
# Output:
#   dist/bas-airgap-<version>.tar.gz      (transfer this to the air-gapped server)
#   dist/bas-airgap-<version>.tar.gz.sha256
#
# Run from the repository root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

VERSION="${1:-$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "dev")}"
readonly VERSION

DIST_DIR="${REPO_ROOT}/dist"
BUILD_NAME="bas-airgap-${VERSION}"
BUILD_DIR="${DIST_DIR}/${BUILD_NAME}"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Verify Docker is available ─────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  err "Docker is required to build the air-gap bundle."
  exit 1
fi
if ! docker info &>/dev/null; then
  err "Docker daemon is not running."
  exit 1
fi

# ── 1. Stage bundle directory ──────────────────────────────────────────────────
log "Staging air-gap bundle v${VERSION}..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/images" "${BUILD_DIR}/compose/systemd"

# ── 2. Pull Docker images ──────────────────────────────────────────────────────
ORCHESTRATOR_IMAGE="bas-orchestrator:${VERSION}"
POSTGRES_IMAGE="postgres:16-alpine"

log "Pulling ${POSTGRES_IMAGE}..."
docker pull "${POSTGRES_IMAGE}"

# orchestrator image must already be built locally (run packaging/build.sh first)
if ! docker image inspect "${ORCHESTRATOR_IMAGE}" &>/dev/null; then
  err "${ORCHESTRATOR_IMAGE} not found locally."
  echo "  Build it first: bash packaging/build.sh ${VERSION}"
  exit 1
fi
log "Found ${ORCHESTRATOR_IMAGE} locally."

# ── 3. Export images ───────────────────────────────────────────────────────────
log "Exporting Docker images (this may take a minute)..."

docker save "${ORCHESTRATOR_IMAGE}" | gzip > "${BUILD_DIR}/images/bas-orchestrator-${VERSION}.tar.gz"
log "  Saved: bas-orchestrator-${VERSION}.tar.gz ($(du -sh "${BUILD_DIR}/images/bas-orchestrator-${VERSION}.tar.gz" | cut -f1))"

docker save "${POSTGRES_IMAGE}" | gzip > "${BUILD_DIR}/images/postgres-16-alpine.tar.gz"
log "  Saved: postgres-16-alpine.tar.gz ($(du -sh "${BUILD_DIR}/images/postgres-16-alpine.tar.gz" | cut -f1))"

# ── 4. Copy compose bundle ─────────────────────────────────────────────────────
log "Copying compose bundle..."
cp "${REPO_ROOT}/packaging/compose/docker-compose.yml"          "${BUILD_DIR}/compose/"
cp "${REPO_ROOT}/packaging/compose/docker-compose.prod.yml"     "${BUILD_DIR}/compose/"
cp "${REPO_ROOT}/packaging/compose/.env.example"                "${BUILD_DIR}/compose/"
cp "${REPO_ROOT}/packaging/compose/setup.sh"                    "${BUILD_DIR}/compose/"
cp "${REPO_ROOT}/packaging/compose/uninstall.sh"                "${BUILD_DIR}/compose/"
cp "${REPO_ROOT}/packaging/compose/systemd/bas-compose.service" "${BUILD_DIR}/compose/systemd/"
chmod +x "${BUILD_DIR}/compose/setup.sh" "${BUILD_DIR}/compose/uninstall.sh"

# Copy application assets
cp -r "${REPO_ROOT}/scenarios/."                  "${BUILD_DIR}/compose/scenarios/"
cp -r "${REPO_ROOT}/orchestrator/wwwroot/."       "${BUILD_DIR}/compose/wwwroot/"

# ── 5. Copy import helper ──────────────────────────────────────────────────────
cp "${REPO_ROOT}/packaging/airgap/import.sh"  "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/airgap/verify.sh"  "${BUILD_DIR}/"
chmod +x "${BUILD_DIR}/import.sh" "${BUILD_DIR}/verify.sh"

# Write version file
echo "${VERSION}" > "${BUILD_DIR}/VERSION"

# ── 6. Generate sha256 manifest ───────────────────────────────────────────────
log "Generating file manifest..."
MANIFEST="${BUILD_DIR}/MANIFEST.sha256"
(
  cd "${BUILD_DIR}"
  find . -type f ! -name "MANIFEST.sha256" | sort | while read -r f; do
    sha256sum "$f"
  done
) > "${MANIFEST}"
log "  $(wc -l < "${MANIFEST}") files indexed."

# ── 7. Package tarball ─────────────────────────────────────────────────────────
TARBALL="${DIST_DIR}/${BUILD_NAME}.tar.gz"
log "Creating ${TARBALL}..."
tar -czf "${TARBALL}" -C "${DIST_DIR}" "${BUILD_NAME}"
rm -rf "${BUILD_DIR}"

CHECKSUM="${TARBALL}.sha256"
sha256sum "${TARBALL}" > "${CHECKSUM}" 2>/dev/null || \
  shasum -a 256 "${TARBALL}" > "${CHECKSUM}"

BUNDLE_SIZE=$(du -sh "${TARBALL}" | cut -f1)

# ── 8. Sign bundle if signing key is present ───────────────────────────────────
SIGN_SCRIPT="${REPO_ROOT}/packaging/signing/sign.sh"
SIGNING_KEY_EMAIL="releases@audspect.com"
if command -v gpg &>/dev/null && gpg --list-secret-keys "${SIGNING_KEY_EMAIL}" &>/dev/null 2>&1; then
  log "Signing bundle with GPG key ${SIGNING_KEY_EMAIL}..."
  bash "${SIGN_SCRIPT}" "${TARBALL}"
else
  warn "GPG signing key not found — bundle is unsigned."
  echo "  To sign: bash packaging/signing/keygen.sh && bash packaging/signing/sign.sh ${TARBALL}"
fi

log "Done."
echo ""
echo "  Bundle:    ${TARBALL}  (${BUNDLE_SIZE})"
echo "  Checksum:  ${CHECKSUM}"
echo ""
echo "  Transfer bundle + .sha256 + .asc (if signed) to the air-gapped server, then run:"
echo "    bash verify-sig.sh bas-airgap-${VERSION}.tar.gz   # if signed"
echo "    bash verify.sh bas-airgap-${VERSION}.tar.gz"
echo "    sudo bash import.sh bas-airgap-${VERSION}.tar.gz"
