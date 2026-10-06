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
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Garble detection ──────────────────────────────────────────────────────────
# garble v0.17.0 — pinned, not @latest: v0.18.0 (2026-09-19) bumped its
# go.mod requirement to go >= 1.27, which breaks under a go1.26 toolchain.
# Install with:
#   go install mvdan.cc/garble@v0.17.0
if command -v garble &>/dev/null; then
  log "garble found — orchestrator and agent will be obfuscated (-literals)"
  GOBUILD_ORCH="garble -literals -tiny build"
  # GOGARBLE scopes to our own module (audspect/agent, no github.com/
  # prefix -- different module path than the orchestrator's
  # github.com/audspect/bas). golang.org/x/sys, windigo, sspi, and
  # gorilla/websocket stay un-obfuscated, same reasoning as the
  # orchestrator's own scoping below.
  #
  # GOGARBLE is NOT embedded here (unlike GOBUILD_ORCH's literal garble
  # invocation above) -- an assignment-prefix word only works when bash
  # parses it literally on the command line; once it arrives via
  # unquoted parameter expansion (${GOBUILD_AGENT} at the call sites
  # below), bash treats the whole expanded string as the command name
  # instead of an env assignment, so it's set literally at each call
  # site instead (same place GOOS/GOARCH already are).
  GOBUILD_AGENT="garble -literals build"
else
  warn "garble not found — building orchestrator and agent without obfuscation."
  echo "  Install: go install mvdan.cc/garble@v0.17.0"
  GOBUILD_ORCH="go build -trimpath"
  GOBUILD_AGENT="go build -trimpath"
fi
# LDFLAGS_* are kept out of GOBUILD_ORCH/GOBUILD_AGENT and passed as their
# own already-quoted "-ldflags=..." token at each call site below. Bash
# word-splits on whitespace during unquoted parameter expansion
# (${GOBUILD_AGENT} ...), so a value containing an internal space (like
# "-s -w") embedded inside GOBUILD_AGENT itself would arrive as two
# separate words -- "-ldflags=-s" and a bare "-w" -- which go/garble
# reject or misparse (reproduced directly: "flag provided but not
# defined: -w" / "malformed import path"). Writing `-ldflags="${LDFLAGS_*}"`
# literally at the call site keeps bash's own quoting intact, so the
# expansion stays one word regardless of the value's internal spaces.
LDFLAGS_ORCH="-s -w -X main.Version=${VERSION}"
LDFLAGS_AGENT="-s -w"

# ── 1. Build orchestrator binary ───────────────────────────────────────────────
log "Building bas-orchestrator ${VERSION} for linux/amd64..."
cd "${REPO_ROOT}/orchestrator"
# GOGARBLE scopes obfuscation to our own module only. Obfuscating third-party
# deps (esp. github.com/go-pdf/fpdf) renames their reflection-driven struct
# fields and breaks PDF font loading ("font has not been set") — and protects no
# IP, since those libs are public OSS. (Ignored by the plain go-build fallback.)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOGARBLE='github.com/audspect/*' \
  ${GOBUILD_ORCH} \
  -ldflags="${LDFLAGS_ORCH}" \
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
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" GOGARBLE='audspect/*' \
    ${GOBUILD_AGENT} -ldflags="${LDFLAGS_AGENT}" -o "${OUT}" .
done

# Windows cross-compile (separate because of .exe extension)
log "  [agent] GOOS=windows GOARCH=amd64 → ${AGENTS_DIR}/bas-agent-windows-amd64.exe"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOGARBLE='audspect/*' \
  ${GOBUILD_AGENT} -ldflags="${LDFLAGS_AGENT}" -o "${AGENTS_DIR}/bas-agent-windows-amd64.exe" .

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

# ART external payloads (gsecdump, etc.) staged on the build host — baked into
# the bundle so the client gets them automatically (bind-mounted to /art-payloads).
# Only real executables/scripts are bundled (the staging folder may also hold tool
# source trees, zips, installers and PDBs — none of which an atomic invokes).
# Flattened with no-clobber so companion files co-locate and duplicate basenames
# resolve first-wins, matching the server's payload importer.
mkdir -p "${BUILD_DIR}/art-payloads"
PAYLOAD_N=0
if [ -d "${REPO_ROOT}/packaging/art-payloads" ]; then
  while IFS= read -r -d '' f; do
    if cp -n "$f" "${BUILD_DIR}/art-payloads/" 2>/dev/null; then
      PAYLOAD_N=$((PAYLOAD_N + 1))
    fi
  done < <(find "${REPO_ROOT}/packaging/art-payloads" -type f \( \
      -iname '*.exe' -o -iname '*.dll' -o -iname '*.ps1' -o -iname '*.psm1' \
      -o -iname '*.bat' -o -iname '*.cmd' -o -iname '*.vbs' -o -iname '*.js' \
      -o -iname '*.hta' -o -iname '*.sys' -o -iname '*.com' -o -iname '*.scr' \
      -o -iname '*.jar' -o -iname '*.py' -o -iname '*.sh' \) -print0)
  log "  ART payloads bundled (binaries only): ${PAYLOAD_N}"
fi
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

# ── 4. Build Docker image and export (requires Docker) ─────────────────────────
if ! command -v docker &>/dev/null; then
  err "Docker not found — this script produces a release bundle and cannot do so without Docker."
  exit 1
fi

# D2/cosign-enforcement: this script produces the distributable release
# bundle -- it has no dev-build concept to preserve, so cosign signing is
# unconditionally mandatory here (unlike windows-build.ps1, which keeps an
# explicit dev-vs-customer distinction via $WindowsSigningRequired). Checked
# before the (slow) docker build so a missing cosign/key fails fast.
COSIGN_SCRIPT="${REPO_ROOT}/packaging/signing/cosign.sh"
COSIGN_KEY="${REPO_ROOT}/packaging/signing/cosign.key"
COSIGN_PUB="${REPO_ROOT}/packaging/signing/cosign.pub"
if ! command -v cosign &>/dev/null; then
  err "cosign is not installed, and cosign signing is mandatory for this release build. Install: https://docs.sigstore.dev/cosign/system_config/installation/"
  exit 1
fi
if [[ ! -f "$COSIGN_KEY" ]]; then
  err "cosign.key not found at ${COSIGN_KEY}, and cosign signing is mandatory for this release build. Run: bash packaging/signing/cosign.sh --keygen"
  exit 1
fi

log "Building Docker image bas-orchestrator:${VERSION}..."
docker build \
  --build-arg VERSION="${VERSION}" \
  -t "bas-orchestrator:${VERSION}" \
  -f "${REPO_ROOT}/orchestrator/Dockerfile" \
  "${REPO_ROOT}"

log "Exporting Docker image to bundle..."
mkdir -p "${BUILD_DIR}/images"
ORCH_TAR="${BUILD_DIR}/images/bas-orchestrator-${VERSION}.tar"
docker save "bas-orchestrator:${VERSION}" -o "${ORCH_TAR}"

# cosign has no mode to sign/verify a Docker-daemon-only image reference --
# sign/verify/save/load all resolve against a container registry, which
# does not exist here (this image is built and saved but never pushed
# anywhere). Signing the tarball's own bytes with sign-blob/verify-blob
# needs no registry, and signs the EXACT bytes that ship in the bundle --
# not a pre-save intermediate that could diverge from what gets shipped.
log "Signing release artifact with cosign..."
if ! bash "${COSIGN_SCRIPT}" --sign "${ORCH_TAR}"; then
  err "cosign signing failed for ${ORCH_TAR} -- aborting release build."
  exit 1
fi
log "Verifying the signature we just produced..."
if ! bash "${COSIGN_SCRIPT}" --verify "${ORCH_TAR}"; then
  err "cosign verification FAILED immediately after signing ${ORCH_TAR} -- this should be structurally impossible; investigate before shipping."
  exit 1
fi
if [[ ! -f "$COSIGN_PUB" ]]; then
  err "cosign.pub not found at ${COSIGN_PUB} after a successful sign+verify -- cannot ship a release bundle the installer can't verify."
  exit 1
fi
cp "$COSIGN_PUB" "${BUILD_DIR}/"

# Postgres: saved UNCOMPRESSED and cosign-signed with the same helper and key as
# the orchestrator (signing is mandatory in this script, so it is mandatory here
# too). setup.sh/import flows refuse any image tar that lacks a valid signature,
# so a bundle without postgres is not installable: a missing local image is fatal.
PG_TAR="${BUILD_DIR}/images/postgres-16-alpine.tar"
if ! docker save "postgres:16-alpine" -o "${PG_TAR}"; then
  err "postgres:16-alpine not available locally -- run 'docker pull postgres:16-alpine' and re-run."
  exit 1
fi
log "Signing postgres image with cosign..."
if ! bash "${COSIGN_SCRIPT}" --sign "${PG_TAR}"; then
  err "cosign signing failed for ${PG_TAR} -- aborting release build."
  exit 1
fi
if ! bash "${COSIGN_SCRIPT}" --verify "${PG_TAR}"; then
  err "cosign verification FAILED immediately after signing ${PG_TAR} -- this should be structurally impossible; investigate before shipping."
  exit 1
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
