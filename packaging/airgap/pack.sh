#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Packer
#
# Run this on an INTERNET-CONNECTED build machine.
# Produces a self-contained bundle that can be transferred to an air-gapped
# server. Layout matches packaging/build.sh's flat bundle exactly (setup.sh
# is a direct sibling of images/, VERSION, cosign.pub, and the compose
# files) because packaging/compose/setup.sh resolves all of those paths
# relative to its own directory -- this layout is not a style choice, it
# is what makes setup.sh's existing checks resolve correctly.
#
# Usage:
#   bash packaging/airgap/pack.sh [version]
#
# Output:
#   dist/bas-airgap-<version>.tar.gz      (transfer this to the air-gapped server)
#   dist/bas-airgap-<version>.tar.gz.asc  (GPG detached signature -- mandatory)
#   dist/bas-airgap-<version>.tar.gz.sha256
#
# Run from the repository root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

# Overridable for testing only -- production runs always use the real
# packaging/signing/ scripts and dist/ directory.
SIGNING_DIR="${BAS_PACK_SIGNING_DIR:-${REPO_ROOT}/packaging/signing}"
DIST_DIR="${BAS_PACK_DIST_DIR:-${REPO_ROOT}/dist}"

VERSION="${1:-$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "dev")}"
readonly VERSION

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
if ! command -v go &>/dev/null; then
  err "Go is required to verify builtin scenario signatures (release gate)."
  exit 1
fi
if ! docker info &>/dev/null; then
  err "Docker daemon is not running."
  exit 1
fi

# ── 1. Stage bundle directory (flat -- matches packaging/build.sh) ─────────────
log "Staging air-gap bundle v${VERSION}..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/images" "${BUILD_DIR}/systemd"

# ── 2. Pull Docker images ──────────────────────────────────────────────────────
ORCHESTRATOR_IMAGE="bas-orchestrator:${VERSION}"
POSTGRES_IMAGE="postgres:16-alpine"

log "Pulling ${POSTGRES_IMAGE}..."
docker pull "${POSTGRES_IMAGE}"

if ! docker image inspect "${ORCHESTRATOR_IMAGE}" &>/dev/null; then
  err "${ORCHESTRATOR_IMAGE} not found locally."
  echo "  Build it first: bash packaging/build.sh ${VERSION}"
  exit 1
fi
log "Found ${ORCHESTRATOR_IMAGE} locally."

# ── 3. Export and cosign-sign the orchestrator image ───────────────────────────
# Signed the same way packaging/build.sh signs its own orchestrator tarball
# (sign-blob/verify-blob against the docker-save bytes, no registry needed)
# so packaging/compose/setup.sh's existing, unmodified cosign verification
# gate is satisfied by this pipeline too. Mandatory, not optional -- a pack
# build with no cosign key available fails here, it does not ship unsigned.
log "Exporting Docker images (this may take a minute)..."
ORCH_TAR="${BUILD_DIR}/images/bas-orchestrator-${VERSION}.tar.gz"
docker save "${ORCHESTRATOR_IMAGE}" | gzip > "${ORCH_TAR}"
log "  Saved: $(basename "${ORCH_TAR}") ($(du -sh "${ORCH_TAR}" | cut -f1))"

COSIGN_SCRIPT="${SIGNING_DIR}/cosign.sh"
log "Signing orchestrator image with cosign..."
if ! bash "${COSIGN_SCRIPT}" --sign "${ORCH_TAR}"; then
  err "cosign signing failed for ${ORCH_TAR} -- aborting bundle build."
  exit 1
fi
log "Verifying the cosign signature we just produced..."
if ! bash "${COSIGN_SCRIPT}" --verify "${ORCH_TAR}"; then
  err "cosign verification FAILED immediately after signing ${ORCH_TAR} -- aborting; investigate before shipping."
  exit 1
fi
COSIGN_PUB="${SIGNING_DIR}/cosign.pub"
if [[ ! -f "$COSIGN_PUB" ]]; then
  err "cosign.pub not found at ${COSIGN_PUB} after a successful sign+verify -- cannot ship a bundle the installer can't verify."
  exit 1
fi
cp "$COSIGN_PUB" "${BUILD_DIR}/"

docker save "${POSTGRES_IMAGE}" | gzip > "${BUILD_DIR}/images/postgres-16-alpine.tar.gz"
log "  Saved: postgres-16-alpine.tar.gz ($(du -sh "${BUILD_DIR}/images/postgres-16-alpine.tar.gz" | cut -f1))"

# ── 4. Copy compose bundle (flat, matches packaging/build.sh) ─────────────────
log "Copying compose bundle..."
cp "${REPO_ROOT}/packaging/compose/docker-compose.yml"          "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/docker-compose.prod.yml"     "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/.env.example"                "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/setup.sh"                    "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/uninstall.sh"                "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/compose/systemd/bas-compose.service" "${BUILD_DIR}/systemd/"
chmod +x "${BUILD_DIR}/setup.sh" "${BUILD_DIR}/uninstall.sh"

# Release gate: builtin scenario signatures must verify against the compiled key.
log "Verifying builtin scenario signatures..."
if ! (cd "${REPO_ROOT}/orchestrator" && env -u GOOS -u GOARCH go run scripts/signer.go verify-all "${REPO_ROOT}/scenarios"); then
  err "builtin scenario signatures are stale -- re-sign on the build host with orchestrator/private_key.pem (see docs/internal/build-guide.md)"
  exit 1
fi

cp -r "${REPO_ROOT}/scenarios/."                "${BUILD_DIR}/scenarios/"
cp -r "${REPO_ROOT}/orchestrator/wwwroot/."       "${BUILD_DIR}/wwwroot/"

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

# ── 5. Copy import helpers ──────────────────────────────────────────────────────
cp "${REPO_ROOT}/packaging/airgap/import.sh"         "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/airgap/verify.sh"          "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/airgap/verify-common.sh"   "${BUILD_DIR}/"
chmod +x "${BUILD_DIR}/import.sh" "${BUILD_DIR}/verify.sh"

echo "${VERSION}" > "${BUILD_DIR}/VERSION"

# ── 6. Generate sha256 manifest ───────────────────────────────────────────────
log "Generating file manifest..."
MANIFEST="${BUILD_DIR}/MANIFEST.sha256"
(
  cd "${BUILD_DIR}"
  find . -type f ! -name "MANIFEST.sha256" | sort | while read -r f; do
    sha256sum "$f" | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/'
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

# ── 8. Sign the bundle -- mandatory, not optional ───────────────────────────────
SIGN_SCRIPT="${SIGNING_DIR}/sign.sh"
if ! bash "${SIGN_SCRIPT}" "${TARBALL}"; then
  err "GPG signing failed -- aborting. An unsigned air-gap bundle must never be produced."
  rm -f "${TARBALL}" "${CHECKSUM}"
  exit 1
fi

log "Done."
echo ""
echo "  Bundle:    ${TARBALL}  (${BUNDLE_SIZE})"
echo "  Checksum:  ${CHECKSUM}"
echo ""
echo "  Transfer bundle + .sha256 + .asc to the air-gapped server, then run:"
echo "    bash verify.sh bas-airgap-${VERSION}.tar.gz"
echo "    sudo bash import.sh bas-airgap-${VERSION}.tar.gz"
