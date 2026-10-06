#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Importer
#
# Run on the AIR-GAPPED target server (no internet required).
# Loads Docker images, then launches the interactive setup wizard.
#
# Usage:
#   sudo bash import.sh <path/to/bas-airgap-<version>.tar.gz> [options]
#
# Options:
#   --cosign-pub <key.pub>   Out-of-band cosign public key (also --cosign-pub=<key.pub>).
#   --gpg-pub <key.asc>      Out-of-band GPG public key (also --gpg-pub=<key.asc>).
#   --non-interactive        Passed to setup.sh (accepted for compatibility).
#   --no-wizard              Passed to setup.sh.
#   --config <file>          Passed to setup.sh.
# Any other option is rejected (an unknown flag could silently drop a key).
#
# Out-of-band keys: the key is used EXCLUSIVELY instead of the bundle's own and
# also governs setup.sh. Precedence: flag, env (BAS_COSIGN_PUB / BAS_GPG_PUB),
# bundled. sudo strips the environment, so prefer the flag, or
# `sudo BAS_COSIGN_PUB=<path> bash import.sh ...`. Compare the printed key
# fingerprints with the ones Audspect publishes. A bundled key only proves
# integrity, not origin. To anchor trust out-of-band, check the bundle's GPG
# signature with your OWN gpg BEFORE extracting or running anything from it:
#   GNUPGHOME=$(mktemp -d) gpg --import <oob.asc> && \
#     gpg --status-fd 1 --verify bundle.tar.gz.asc bundle.tar.gz
# and compare the VALIDSIG fingerprint.
#
# EVERY image tar (orchestrator, postgres) is cosign-verified BEFORE any is
# loaded, bound to its expected tag and image ID, and loaded orchestrator-last;
# an unsigned, tampered, unlisted or legacy .tar.gz image is refused.
# PREREQUISITE: cosign >= v3.1.0 must be pre-installed on this air-gapped host
# (copy the release binary from https://github.com/sigstore/cosign/releases
# over offline: install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign).
set -euo pipefail
unset CDPATH

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Root check ─────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "This importer must be run as root."
  echo "  Run: sudo bash $0 <bundle>"
  exit 1
fi

TARBALL="${1:-}"
if [[ -z "$TARBALL" || "$TARBALL" == -* ]]; then
  err "Usage: sudo bash import.sh <bas-airgap-<version>.tar.gz> [--cosign-pub <key.pub>] [--gpg-pub <key.asc>] [--non-interactive]"
  exit 1
fi
if [[ ! -f "$TARBALL" ]]; then
  err "File not found: $TARBALL"
  exit 1
fi

# Options: keys are consumed here; ONLY the allowlisted flags pass to setup.sh
# (setup.sh itself accepts --offline [set by us], --no-wizard, --config <file>;
# --non-interactive is accepted and ignored, kept for older docs/scripts).
shift
SETUP_EXTRA_ARGS=()
COSIGN_PUB_FLAG=""
GPG_PUB_FLAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gpg-pub=*)    GPG_PUB_FLAG="${1#--gpg-pub=}"; shift ;;
    --gpg-pub)
      [[ $# -ge 2 ]] || { err "--gpg-pub requires a path"; exit 1; }
      GPG_PUB_FLAG="$2"; shift 2 ;;
    --cosign-pub=*) COSIGN_PUB_FLAG="${1#--cosign-pub=}"; shift ;;
    --cosign-pub)
      [[ $# -ge 2 ]] || { err "--cosign-pub requires a path"; exit 1; }
      COSIGN_PUB_FLAG="$2"; shift 2 ;;
    --non-interactive|--no-wizard) SETUP_EXTRA_ARGS+=("$1"); shift ;;
    --config)
      [[ $# -ge 2 ]] || { err "--config requires a file"; exit 1; }
      SETUP_EXTRA_ARGS+=("$1" "$2"); shift 2 ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Verify Docker ──────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  err "Docker is not installed on this server."
  echo "  Install Docker: https://docs.docker.com/engine/install/ubuntu/"
  exit 1
fi
if ! docker info &>/dev/null; then
  err "Docker daemon is not running. Start it: systemctl start docker"
  exit 1
fi

# ── cosign verification helpers (shared with verify.sh) ───────────────────────
AIRGAP_LIB="$(dirname -- "$0")/cosign-verify-lib.sh"
if [[ ! -f "$AIRGAP_LIB" ]]; then
  err "cosign-verify-lib.sh not found next to import.sh -- cannot verify the images, refusing to proceed."
  exit 1
fi
# shellcheck source=cosign-verify-lib.sh
source "$AIRGAP_LIB"

# An explicitly supplied GPG key (flag or env) with no .asc to check is an error,
# never a silent skip.
if [[ -n "${GPG_PUB_FLAG:-${BAS_GPG_PUB:-}}" && ! -f "${TARBALL}.asc" ]]; then
  err "An external GPG key was supplied but ${TARBALL}.asc does not exist -- cannot verify origin. Import aborted."
  exit 1
fi
airgap_external_pub "$COSIGN_PUB_FLAG" || { err "Import aborted."; exit 1; }

# ── Work on a private COPY of the bundle (no verify-then-swap race) ───────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
chmod 700 "$WORK_DIR"
COPY="${WORK_DIR}/$(basename -- "$TARBALL")"
cp -- "$TARBALL" "$COPY"
[[ -f "${TARBALL}.asc" ]] && cp -- "${TARBALL}.asc" "${COPY}.asc"
[[ -f "${TARBALL}.sha256" ]] && cp -- "${TARBALL}.sha256" "${COPY}.sha256"

# ── Signature verification (if .asc present) ──────────────────────────────────
SIGFILE="${COPY}.asc"
VERIFY_SIG_SCRIPT="$(dirname -- "$0")/../signing/verify-sig.sh"
# Also check same-dir placement (when distributed as part of a bundle-tools package)
[[ ! -f "$VERIFY_SIG_SCRIPT" ]] && VERIFY_SIG_SCRIPT="$(dirname -- "$0")/verify-sig.sh"

if [[ -f "$SIGFILE" ]]; then
  if [[ -f "$VERIFY_SIG_SCRIPT" ]]; then
    log "GPG signature found — verifying before import..."
    GPG_ARGS=()
    [[ -n "$GPG_PUB_FLAG" ]] && GPG_ARGS=(--gpg-pub "$GPG_PUB_FLAG")
    if ! bash "$VERIFY_SIG_SCRIPT" "$COPY" ${GPG_ARGS[@]+"${GPG_ARGS[@]}"}; then
      err "Signature verification failed. Import aborted."
      exit 1
    fi
  else
    err ".asc signature file found but verify-sig.sh is not available -- cannot verify it. Import aborted."
    echo "  Place verify-sig.sh (shipped in the bundle) next to import.sh." >&2
    exit 1
  fi
else
  warn "No GPG signature (.asc) found — proceeding without signature verification."
  warn "For production deployments, always verify signatures. See packaging/signing/."
fi

# ── Extract the verified copy ──────────────────────────────────────────────────
log "Extracting bundle..."
mkdir "${WORK_DIR}/x"
tar -xzf "$COPY" -C "${WORK_DIR}/x"

BUNDLE_DIR=$(find "${WORK_DIR}/x" -maxdepth 1 -mindepth 1 -type d | head -1)
if [[ -z "$BUNDLE_DIR" ]]; then
  err "Bundle appears empty or malformed. Run verify.sh first."
  exit 1
fi

VERSION=$(cat "${BUNDLE_DIR}/VERSION" 2>/dev/null || echo "unknown")
log "Bundle version: ${VERSION}"

# setup.sh pins .env to compose/VERSION: it must be the version we verify.
if [[ "$(cat "${BUNDLE_DIR}/compose/VERSION" 2>/dev/null | tr -d '[:space:]')" != "$(echo "$VERSION" | tr -d '[:space:]')" ]]; then
  err "compose/VERSION does not match the bundle VERSION (${VERSION}) -- compose would run a different image than the verified one. Import aborted."
  exit 1
fi

# ── Verify manifest (quick check) ─────────────────────────────────────────────
MANIFEST="${BUNDLE_DIR}/MANIFEST.sha256"
if [[ -f "$MANIFEST" ]]; then
  log "Verifying bundle integrity..."
  if ! mout=$(cd "$BUNDLE_DIR" && sha256sum --check --strict MANIFEST.sha256 2>&1); then
    grep -v ': OK$' <<<"$mout" | while IFS= read -r l; do err "$l"; done
    err "Bundle manifest verification failed. Abort."
    exit 1
  fi
  log "Manifest OK."
else
  warn "No MANIFEST.sha256 found — skipping integrity check."
fi

# setup.sh re-verifies with compose/cosign.pub; refuse an inconsistent bundle BEFORE
# anything is loaded (with an external key, compose/cosign.pub is overwritten later).
if [[ -z "$AIRGAP_EXT_PUB" ]] && ! cmp -s "${BUNDLE_DIR}/cosign.pub" "${BUNDLE_DIR}/compose/cosign.pub"; then
  err "compose/cosign.pub differs from the bundle's cosign.pub -- bundle is inconsistent. Import aborted."
  exit 1
fi

# ── Verify EVERY image signature + identity, THEN load (orchestrator last) ───
# Nothing reaches the Docker daemon unless every image tar verifies.
airgap_select_pub "${BUNDLE_DIR}/cosign.pub"
log "Verifying image signatures and loading images..."
if ! airgap_verify_and_load_images "${BUNDLE_DIR}/images" "$AIRGAP_PUB" "$VERSION"; then
  err "Image verification/loading failed. Import aborted."
  exit 1
fi

log "Docker images loaded:"
docker images | grep -E "(bas-orchestrator|bas-caldera|headless-shell|postgres)" | awk '{printf "  %-40s %s\n", $1":"$2, $3}'

# ── Tag orchestrator image as expected by docker-compose.yml ──────────────────
# docker-compose.yml uses bas-orchestrator:${BAS_VERSION:-latest}
# Always (re)point :latest at the VERIFIED versioned image, so a pre-existing
# or bundle-planted :latest can never be what compose runs.
log "  Tagging bas-orchestrator:${VERSION} as bas-orchestrator:latest..."
docker tag "bas-orchestrator:${VERSION}" "bas-orchestrator:latest"

# ── Run setup wizard ───────────────────────────────────────────────────────────
SETUP_SCRIPT="${BUNDLE_DIR}/compose/setup.sh"
if [[ ! -f "$SETUP_SCRIPT" ]]; then
  err "setup.sh not found inside bundle."
  exit 1
fi
chmod +x "$SETUP_SCRIPT"
# setup.sh --offline re-verifies the signed artifacts from <its dir>/images.
# Never trust a bundle-shipped compose/images or compose/cosign.pub.
rm -rf "${BUNDLE_DIR}/compose/images"
ln -s ../images "${BUNDLE_DIR}/compose/images"
if [[ -n "$AIRGAP_EXT_PUB" ]]; then
  # External key in use: it overrides whatever the bundle ships, for setup.sh too.
  cp "$AIRGAP_EXT_PUB" "${BUNDLE_DIR}/compose/cosign.pub"
  export BAS_COSIGN_PUB="$AIRGAP_EXT_PUB"
fi
# The out-of-band GPG key (if any) also governs setup.sh's agent-binary check.
if [[ -n "$GPG_PUB_FLAG" ]]; then
  BAS_GPG_PUB="$(cd -- "$(dirname -- "$GPG_PUB_FLAG")" && pwd)/$(basename -- "$GPG_PUB_FLAG")"
  export BAS_GPG_PUB
fi

log "Launching BAS setup wizard (offline mode)..."
echo ""

# Pass --offline so setup.sh skips docker pull
bash "$SETUP_SCRIPT" --offline ${SETUP_EXTRA_ARGS[@]+"${SETUP_EXTRA_ARGS[@]}"}
