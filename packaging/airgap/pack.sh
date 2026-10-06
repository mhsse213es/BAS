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
# Requires cosign + packaging/signing/cosign.key (the orchestrator image is
# signed; import.sh refuses an unsigned one).
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

# ── cosign is mandatory (mirrors packaging/build.sh) ──────────────────────────
# The orchestrator image ships cosign-signed; the air-gapped importer refuses an
# unsigned one. Checked before the slow pull/save so a missing cosign/key fails fast.
COSIGN_SCRIPT="${REPO_ROOT}/packaging/signing/cosign.sh"
COSIGN_KEY="${REPO_ROOT}/packaging/signing/cosign.key"
COSIGN_PUB="${REPO_ROOT}/packaging/signing/cosign.pub"
if ! command -v cosign &>/dev/null; then
  err "cosign is not installed, and cosign signing is mandatory for this air-gap bundle. Install: https://docs.sigstore.dev/cosign/system_config/installation/"
  exit 1
fi
if [[ ! -f "$COSIGN_KEY" ]]; then
  err "cosign.key not found at ${COSIGN_KEY}, and cosign signing is mandatory for this air-gap bundle. Run: bash packaging/signing/cosign.sh --keygen"
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

# Orchestrator: UNCOMPRESSED tar so the signature covers the exact shipped bytes
# (same as packaging/build.sh). Signed with cosign sign-blob, verified at once.
ORCH_TAR="${BUILD_DIR}/images/bas-orchestrator-${VERSION}.tar"
docker save "${ORCHESTRATOR_IMAGE}" -o "${ORCH_TAR}"
log "  Saved: bas-orchestrator-${VERSION}.tar ($(du -sh "${ORCH_TAR}" | cut -f1))"

log "Signing orchestrator image with cosign..."
if ! bash "${COSIGN_SCRIPT}" --sign "${ORCH_TAR}"; then
  err "cosign signing failed for ${ORCH_TAR} -- aborting."
  exit 1
fi
log "Verifying the signature we just produced..."
if ! bash "${COSIGN_SCRIPT}" --verify "${ORCH_TAR}"; then
  err "cosign verification FAILED immediately after signing ${ORCH_TAR} -- this should be structurally impossible; investigate before shipping."
  exit 1
fi
if [[ ! -f "$COSIGN_PUB" ]]; then
  err "cosign.pub not found at ${COSIGN_PUB} -- cannot ship a bundle the importer can't verify."
  exit 1
fi
# Top level: used by import.sh / verify.sh. compose/: used by setup.sh --offline.
cp "$COSIGN_PUB" "${BUILD_DIR}/cosign.pub"

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

# ART external payloads staged on the build host — baked in so the client gets
# them automatically (compose bind-mounts ./art-payloads to /art-payloads).
# Only real executables/scripts are bundled (the staging folder may also hold tool
# source trees, zips, installers and PDBs — none of which an atomic invokes).
# Flattened with no-clobber so companion files co-locate and duplicate basenames
# resolve first-wins, matching the server's payload importer.
mkdir -p "${BUILD_DIR}/compose/art-payloads"
PAYLOAD_N=0
if [ -d "${REPO_ROOT}/packaging/art-payloads" ]; then
  while IFS= read -r -d '' f; do
    if cp -n "$f" "${BUILD_DIR}/compose/art-payloads/" 2>/dev/null; then
      PAYLOAD_N=$((PAYLOAD_N + 1))
    fi
  done < <(find "${REPO_ROOT}/packaging/art-payloads" -type f \( \
      -iname '*.exe' -o -iname '*.dll' -o -iname '*.ps1' -o -iname '*.psm1' \
      -o -iname '*.bat' -o -iname '*.cmd' -o -iname '*.vbs' -o -iname '*.js' \
      -o -iname '*.hta' -o -iname '*.sys' -o -iname '*.com' -o -iname '*.scr' \
      -o -iname '*.jar' -o -iname '*.py' -o -iname '*.sh' \) -print0)
  log "  ART payloads bundled (binaries only): ${PAYLOAD_N}"
fi

# ── 5. Copy import helper ──────────────────────────────────────────────────────
cp "${REPO_ROOT}/packaging/airgap/import.sh"  "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/airgap/verify.sh"  "${BUILD_DIR}/"
cp "${REPO_ROOT}/packaging/airgap/cosign-verify-lib.sh" "${BUILD_DIR}/"
chmod +x "${BUILD_DIR}/import.sh" "${BUILD_DIR}/verify.sh"

# setup.sh --offline (run by import.sh) verifies again from its own directory:
# it needs cosign.pub and the signed orchestrator artifact under compose/.
cp "${BUILD_DIR}/cosign.pub" "${BUILD_DIR}/compose/cosign.pub"

# Write version file
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
echo "  (cosign >= v3.1.0 must already be installed on the air-gapped server)"
echo "    bash verify-sig.sh bas-airgap-${VERSION}.tar.gz   # if signed"
echo "    bash verify.sh bas-airgap-${VERSION}.tar.gz"
echo "    sudo bash import.sh bas-airgap-${VERSION}.tar.gz"
