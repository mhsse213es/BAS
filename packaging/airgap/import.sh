#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Importer
#
# Run on the AIR-GAPPED target server (no internet required).
# Loads Docker images, then launches the interactive setup wizard.
#
# Usage:
#   sudo bash import.sh <path/to/bas-airgap-<version>.tar.gz> [--cosign-pub <key.pub>]
#
# Out-of-band key: --cosign-pub <path> (or env BAS_COSIGN_PUB=<path>) verifies
# with a key you obtained separately instead of the bundle's cosign.pub; it also
# governs setup.sh. Precedence: flag, env, bundled. Compare the printed sha256
# fingerprint with the published Audspect fingerprint.
#
# The orchestrator image is cosign-verified (sign-blob bundle) BEFORE it is
# loaded; an unsigned, tampered or legacy .tar.gz orchestrator image is refused.
# PREREQUISITE: cosign >= v3.1.0 must be pre-installed on this air-gapped host
# (copy the release binary from https://github.com/sigstore/cosign/releases
# over offline: install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign).
#
# Optional flags (passed through to setup.sh):
#   --non-interactive   Run setup.sh with default values (no whiptail)
set -euo pipefail

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
if [[ -z "$TARBALL" ]]; then
  err "Usage: sudo bash import.sh <bas-airgap-<version>.tar.gz> [--non-interactive]"
  exit 1
fi
if [[ ! -f "$TARBALL" ]]; then
  err "File not found: $TARBALL"
  exit 1
fi

# Collect any extra flags to pass to setup.sh (e.g. --non-interactive).
# --cosign-pub <path> is consumed here (out-of-band key; see usage header).
shift
SETUP_EXTRA_ARGS=()
COSIGN_PUB_FLAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cosign-pub)
      [[ $# -ge 2 ]] || { err "--cosign-pub requires a path"; exit 1; }
      COSIGN_PUB_FLAG="$2"; shift 2 ;;
    *) SETUP_EXTRA_ARGS+=("$1"); shift ;;
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
AIRGAP_LIB="$(dirname "$0")/cosign-verify-lib.sh"
if [[ ! -f "$AIRGAP_LIB" ]]; then
  err "cosign-verify-lib.sh not found next to import.sh -- cannot verify the orchestrator image, refusing to proceed."
  exit 1
fi
# shellcheck source=cosign-verify-lib.sh
source "$AIRGAP_LIB"

airgap_external_pub "$COSIGN_PUB_FLAG" || { err "Import aborted."; exit 1; }

# ── Signature verification (if .asc present) ──────────────────────────────────
SIGFILE="${TARBALL}.asc"
VERIFY_SIG_SCRIPT="$(dirname "$0")/../signing/verify-sig.sh"
# Also check same-dir placement (when distributed as part of a bundle-tools package)
[[ ! -f "$VERIFY_SIG_SCRIPT" ]] && VERIFY_SIG_SCRIPT="$(dirname "$0")/verify-sig.sh"

if [[ -f "$SIGFILE" ]]; then
  if [[ -f "$VERIFY_SIG_SCRIPT" ]]; then
    log "GPG signature found — verifying before import..."
    if ! bash "$VERIFY_SIG_SCRIPT" "$TARBALL"; then
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

# ── Extract bundle ─────────────────────────────────────────────────────────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

log "Extracting bundle..."
tar -xzf "$TARBALL" -C "$WORK_DIR"

BUNDLE_DIR=$(find "$WORK_DIR" -maxdepth 1 -mindepth 1 -type d | head -1)
if [[ -z "$BUNDLE_DIR" ]]; then
  err "Bundle appears empty or malformed. Run verify.sh first."
  exit 1
fi

VERSION=$(cat "${BUNDLE_DIR}/VERSION" 2>/dev/null || echo "unknown")
log "Bundle version: ${VERSION}"

# ── Verify manifest (quick check) ─────────────────────────────────────────────
MANIFEST="${BUNDLE_DIR}/MANIFEST.sha256"
if [[ -f "$MANIFEST" ]]; then
  log "Verifying bundle integrity..."
  FAIL=0
  while IFS= read -r line; do
    hash=$(awk '{print $1}' <<<"$line")
    rel=$(awk '{print $2}' <<<"$line"); rel="${rel#\*}"; rel="${rel#./}"
    abs="${BUNDLE_DIR}/${rel}"
    [[ ! -f "$abs" ]] && { err "Missing: $rel"; FAIL=$((FAIL+1)); continue; }
    actual=$(sha256sum "$abs" | cut -d' ' -f1)
    [[ "$actual" != "$hash" ]] && { err "Corrupt: $rel"; FAIL=$((FAIL+1)); }
  done < "$MANIFEST"
  if [[ $FAIL -gt 0 ]]; then
    err "${FAIL} file(s) failed verification. Abort."
    exit 1
  fi
  log "Manifest OK."
else
  warn "No MANIFEST.sha256 found — skipping integrity check."
fi

# ── Verify orchestrator image signature, THEN load images ─────────────────────
# Nothing reaches the Docker daemon unless the orchestrator tar verifies.
ORCHESTRATOR_IMG="${BUNDLE_DIR}/images/bas-orchestrator-${VERSION}.tar"
LEGACY_ORCH_IMG="${BUNDLE_DIR}/images/bas-orchestrator-${VERSION}.tar.gz"
POSTGRES_IMG="${BUNDLE_DIR}/images/postgres-16-alpine.tar.gz"

if [[ ! -f "$ORCHESTRATOR_IMG" && -f "$LEGACY_ORCH_IMG" ]]; then
  airgap_verify_orchestrator "$LEGACY_ORCH_IMG" "${BUNDLE_DIR}/cosign.pub" || true
  err "Import aborted."
  exit 1
fi
if [[ ! -f "$ORCHESTRATOR_IMG" ]]; then
  err "Image not found: images/bas-orchestrator-${VERSION}.tar"
  exit 1
fi
airgap_select_pub "${BUNDLE_DIR}/cosign.pub"
log "Verifying orchestrator image signature..."
if ! airgap_verify_orchestrator "$ORCHESTRATOR_IMG" "$AIRGAP_PUB"; then
  err "Orchestrator image failed verification. Import aborted."
  exit 1
fi

log "Loading Docker images..."

if [[ -f "$POSTGRES_IMG" ]]; then
  log "  Loading postgres:16-alpine..."
  docker load < "$POSTGRES_IMG"
else
  err "Image not found: images/postgres-16-alpine.tar.gz"
  exit 1
fi

# Orchestrator loaded last so no later load can re-point its tag.
log "  Loading bas-orchestrator:${VERSION}..."
docker load < "$ORCHESTRATOR_IMG"

log "Docker images loaded:"
docker images | grep -E "(bas-orchestrator|postgres)" | awk '{printf "  %-40s %s\n", $1":"$2, $3}'

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
# setup.sh --offline re-verifies the signed artifact from <its dir>/images.
# Never trust a bundle-shipped compose/images or compose/cosign.pub.
rm -rf "${BUNDLE_DIR}/compose/images"
ln -s ../images "${BUNDLE_DIR}/compose/images"
if [[ -n "$AIRGAP_EXT_PUB" ]]; then
  # External key in use: it overrides whatever the bundle ships, for setup.sh too.
  cp "$AIRGAP_EXT_PUB" "${BUNDLE_DIR}/compose/cosign.pub"
  export BAS_COSIGN_PUB="$AIRGAP_EXT_PUB"
elif ! cmp -s "$AIRGAP_PUB" "${BUNDLE_DIR}/compose/cosign.pub"; then
  err "compose/cosign.pub differs from the key used for verification -- bundle is inconsistent. Import aborted."
  exit 1
fi

log "Launching BAS setup wizard (offline mode)..."
echo ""

# Pass --offline so setup.sh skips docker pull
bash "$SETUP_SCRIPT" --offline "${SETUP_EXTRA_ARGS[@]}"
