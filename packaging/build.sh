#!/usr/bin/env bash
# BAS Platform — Build Script
# Compiles the orchestrator for linux/amd64 and packages a distributable
# Docker Compose bundle: bas-platform-compose-<version>.tar.gz
#
# Usage:
#   bash packaging/build.sh [version]
#
# Example:
#   bash packaging/build.sh 1.2.0
#
# Output:
#   dist/bas-platform-compose-<version>.tar.gz
#
# Run from the repository root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

VERSION="${1:-$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "dev")}"
readonly VERSION

DIST_DIR="${REPO_ROOT}/dist"
BUILD_NAME="bas-platform-compose-${VERSION}"
BUILD_DIR="${DIST_DIR}/${BUILD_NAME}"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

# ── 1. Build orchestrator binary ───────────────────────────────────────────────
log "Building bas-orchestrator ${VERSION} for linux/amd64..."
cd "${REPO_ROOT}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build \
    -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o "${DIST_DIR}/bas-orchestrator-linux-amd64" \
    ./orchestrator/cmd/server/

log "Binary: ${DIST_DIR}/bas-orchestrator-linux-amd64"

# ── 2. Prepare staging directory ───────────────────────────────────────────────
log "Staging distribution bundle..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/systemd"

# Compose files
cp "${REPO_ROOT}/packaging/compose/docker-compose.yml"      "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/docker-compose.prod.yml" "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/.env.example"            "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/setup.sh"                "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/uninstall.sh"            "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/systemd/bas-compose.service" "${BUILD_DIR}/systemd/"

chmod +x "${BUILD_DIR}/setup.sh" "${BUILD_DIR}/uninstall.sh"

# Application assets
log "Copying scenarios and wwwroot..."
cp -r "${REPO_ROOT}/scenarios/."   "${BUILD_DIR}/scenarios/"
cp -r "${REPO_ROOT}/orchestrator/wwwroot/." "${BUILD_DIR}/wwwroot/"

# Version file
echo "${VERSION}" > "${BUILD_DIR}/VERSION"

# ── 3. Rewrite BAS_VERSION in docker-compose.yml ──────────────────────────────
sed -i "s|bas-orchestrator:.*|bas-orchestrator:${VERSION}|g" \
  "${BUILD_DIR}/docker-compose.yml" 2>/dev/null || true

# Also update .env.example default
sed -i "s|^BAS_VERSION=.*|BAS_VERSION=${VERSION}|" "${BUILD_DIR}/.env.example"

# ── 4. Build Docker image and export (optional, requires Docker) ───────────────
if command -v docker &>/dev/null; then
  log "Building Docker image bas-orchestrator:${VERSION}..."
  docker build \
    --build-arg VERSION="${VERSION}" \
    -t "bas-orchestrator:${VERSION}" \
    -f "${REPO_ROOT}/orchestrator/Dockerfile" \
    "${REPO_ROOT}"

  log "Exporting Docker image to bundle..."
  mkdir -p "${BUILD_DIR}/images"
  docker save "bas-orchestrator:${VERSION}" \
    | gzip > "${BUILD_DIR}/images/bas-orchestrator-${VERSION}.tar.gz"
  docker save "postgres:16-alpine" \
    | gzip > "${BUILD_DIR}/images/postgres-16-alpine.tar.gz" 2>/dev/null || \
    warn "postgres:16-alpine not pulled locally — run 'docker pull postgres:16-alpine' to include it"
else
  warn "Docker not found — skipping image export. Bundle will pull images on install."
fi

# ── 5. Package tarball ─────────────────────────────────────────────────────────
TARBALL="${DIST_DIR}/${BUILD_NAME}.tar.gz"
log "Creating ${TARBALL}..."
tar -czf "${TARBALL}" -C "${DIST_DIR}" "${BUILD_NAME}"
rm -rf "${BUILD_DIR}"

CHECKSUM="${TARBALL}.sha256"
sha256sum "${TARBALL}" > "${CHECKSUM}" 2>/dev/null || \
  shasum -a 256 "${TARBALL}" > "${CHECKSUM}"

# ── 6. Sign bundle if signing key is available ────────────────────────────────
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
echo "  Package:   ${TARBALL}"
echo "  Checksum:  ${CHECKSUM}"
echo "  Version:   ${VERSION}"
echo ""
echo "  Install on target server:"
echo "    tar -xzf ${BUILD_NAME}.tar.gz"
echo "    cd ${BUILD_NAME}"
echo "    sudo bash setup.sh"
