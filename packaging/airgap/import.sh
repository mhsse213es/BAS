#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Importer
#
# Run on the AIR-GAPPED target server (no internet required).
# Loads Docker images, then launches the interactive setup wizard.
#
# Usage:
#   sudo bash import.sh <path/to/bas-airgap-<version>.tar.gz>
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

# Collect any extra flags to pass to setup.sh (e.g. --non-interactive)
shift
SETUP_EXTRA_ARGS=("$@")

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
    warn ".asc signature file found but verify-sig.sh not available — skipping GPG check."
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
    [[ ! -f "$abs" ]] && { err "Missing: $rel"; ((FAIL++)); continue; }
    actual=$(sha256sum "$abs" | cut -d' ' -f1)
    [[ "$actual" != "$hash" ]] && { err "Corrupt: $rel"; ((FAIL++)); }
  done < "$MANIFEST"
  if [[ $FAIL -gt 0 ]]; then
    err "${FAIL} file(s) failed verification. Abort."
    exit 1
  fi
  log "Manifest OK."
else
  warn "No MANIFEST.sha256 found — skipping integrity check."
fi

# ── Load Docker images ─────────────────────────────────────────────────────────
log "Loading Docker images..."

ORCHESTRATOR_IMG="${BUNDLE_DIR}/images/bas-orchestrator-${VERSION}.tar.gz"
POSTGRES_IMG="${BUNDLE_DIR}/images/postgres-16-alpine.tar.gz"

if [[ -f "$ORCHESTRATOR_IMG" ]]; then
  log "  Loading bas-orchestrator:${VERSION}..."
  docker load < "$ORCHESTRATOR_IMG"
else
  err "Image not found: images/bas-orchestrator-${VERSION}.tar.gz"
  exit 1
fi

if [[ -f "$POSTGRES_IMG" ]]; then
  log "  Loading postgres:16-alpine..."
  docker load < "$POSTGRES_IMG"
else
  err "Image not found: images/postgres-16-alpine.tar.gz"
  exit 1
fi

log "Docker images loaded:"
docker images | grep -E "(bas-orchestrator|postgres)" | awk '{printf "  %-40s %s\n", $1":"$2, $3}'

# ── Tag orchestrator image as expected by docker-compose.yml ──────────────────
# docker-compose.yml uses bas-orchestrator:${BAS_VERSION:-latest}
# Ensure the versioned image is also tagged :latest for default installs
if ! docker image inspect "bas-orchestrator:latest" &>/dev/null; then
  log "  Tagging bas-orchestrator:${VERSION} as bas-orchestrator:latest..."
  docker tag "bas-orchestrator:${VERSION}" "bas-orchestrator:latest"
fi

# ── Run setup wizard ───────────────────────────────────────────────────────────
SETUP_SCRIPT="${BUNDLE_DIR}/compose/setup.sh"
if [[ ! -f "$SETUP_SCRIPT" ]]; then
  err "setup.sh not found inside bundle."
  exit 1
fi
chmod +x "$SETUP_SCRIPT"

log "Launching BAS setup wizard (offline mode)..."
echo ""

# Pass --offline so setup.sh skips docker pull
bash "$SETUP_SCRIPT" --offline "${SETUP_EXTRA_ARGS[@]}"
