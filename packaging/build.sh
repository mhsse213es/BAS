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

# ── Garble detection ──────────────────────────────────────────────────────────
# garble v0.12.1 — compatible with Go 1.23.  Install with:
#   go install mvdan.cc/garble@v0.12.1
if command -v garble &>/dev/null; then
  log "garble found — orchestrator will be obfuscated (-literals -tiny)"
  GOBUILD_ORCH="garble -literals -tiny build -ldflags=-s -w -X main.Version=${VERSION}"
else
  warn "garble not found — building orchestrator without obfuscation."
  echo "  Install: go install mvdan.cc/garble@v0.12.1"
  GOBUILD_ORCH="go build -trimpath -ldflags=-s -w -X main.Version=${VERSION}"
fi
# Agent uses plain stripped build: golang.org/x/sys assembly is incompatible with garble.
GOBUILD_AGENT="go build -trimpath -ldflags=-s -w"

# ── 1. Build orchestrator binary ───────────────────────────────────────────────
log "Building bas-orchestrator ${VERSION} for linux/amd64..."
cd "${REPO_ROOT}/orchestrator"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  ${GOBUILD_ORCH} \
  -o "${DIST_DIR}/bas-orchestrator-linux-amd64" \
  ./cmd/server/
cd "${REPO_ROOT}"

log "Binary: ${DIST_DIR}/bas-orchestrator-linux-amd64"

# ── 1b. Cross-compile agent binaries ──────────────────────────────────────────
AGENTS_DIR="${DIST_DIR}/agents"
mkdir -p "${AGENTS_DIR}"
log "Cross-compiling bas-agent for all platforms..."
cd "${REPO_ROOT}/agent"

declare -A AGENT_TARGETS=(
  ["linux-amd64"]="linux/amd64"
  ["linux-arm64"]="linux/arm64"
  ["darwin-amd64"]="darwin/amd64"
  ["darwin-arm64"]="darwin/arm64"
)

for LABEL in "${!AGENT_TARGETS[@]}"; do
  IFS='/' read -r GOOS GOARCH <<< "${AGENT_TARGETS[$LABEL]}"
  OUT="${AGENTS_DIR}/bas-agent-${LABEL}"
  log "  [agent] GOOS=${GOOS} GOARCH=${GOARCH} → ${OUT}"
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    ${GOBUILD_AGENT} -o "${OUT}" .
done

# Windows cross-compile (separate because of .exe extension)
log "  [agent] GOOS=windows GOARCH=amd64 → ${AGENTS_DIR}/bas-agent-windows-amd64.exe"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  ${GOBUILD_AGENT} -o "${AGENTS_DIR}/bas-agent-windows-amd64.exe" .

cd "${REPO_ROOT}"
log "Agent binaries written to ${AGENTS_DIR}/"

# ── 1c. Sign binaries if GPG key is available ─────────────────────────────────
SIGNING_KEY_EMAIL="releases@audspect.com"
SIGN_BINS="${REPO_ROOT}/packaging/signing/sign-binaries.sh"

# Also sign the orchestrator binary alongside the agents
cp "${DIST_DIR}/bas-orchestrator-linux-amd64" "${AGENTS_DIR}/bas-orchestrator-linux-amd64"

if command -v gpg &>/dev/null && gpg --list-secret-keys "${SIGNING_KEY_EMAIL}" &>/dev/null 2>&1; then
  log "Signing binaries..."
  bash "${SIGN_BINS}" "${AGENTS_DIR}"
  # Copy pubkey.asc into agents dir for bundle inclusion
  cp "${REPO_ROOT}/packaging/signing/pubkey.asc" "${AGENTS_DIR}/"
else
  warn "GPG signing key not found — binaries will not be signed."
  echo "  To sign: bash packaging/signing/keygen.sh then rebuild."
fi

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
log "Copying scenarios, wwwroot, and agent binaries..."
cp -r "${REPO_ROOT}/scenarios/."   "${BUILD_DIR}/scenarios/"
cp -r "${REPO_ROOT}/orchestrator/wwwroot/." "${BUILD_DIR}/wwwroot/"
mkdir -p "${BUILD_DIR}/agents"
cp "${AGENTS_DIR}"/* "${BUILD_DIR}/agents/" 2>/dev/null || true

# Copy signing verification tools alongside binaries
cp "${REPO_ROOT}/packaging/signing/verify-binary.sh" "${BUILD_DIR}/agents/"
chmod +x "${BUILD_DIR}/agents/verify-binary.sh"

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

  # Sign image with cosign if available
  COSIGN_SCRIPT="${REPO_ROOT}/packaging/signing/cosign.sh"
  COSIGN_PUB="${REPO_ROOT}/packaging/signing/cosign.pub"
  if command -v cosign &>/dev/null && [[ -f "${REPO_ROOT}/packaging/signing/cosign.key" ]]; then
    log "Signing Docker image with cosign..."
    bash "${COSIGN_SCRIPT}" --sign "bas-orchestrator:${VERSION}"
    # Copy public key into bundle so installer can verify
    [[ -f "$COSIGN_PUB" ]] && cp "$COSIGN_PUB" "${BUILD_DIR}/"
  else
    warn "cosign not available or cosign.key missing — Docker image will not be cosign-signed."
    echo "  To sign: bash packaging/signing/cosign.sh --keygen  then rebuild."
  fi

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
