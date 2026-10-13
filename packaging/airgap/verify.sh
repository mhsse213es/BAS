#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Verifier
#
# Verifies the integrity, authenticity, and host compatibility of a
# bas-airgap bundle before import. Run on the air-gapped target server
# before import.sh. Shares every check with import.sh via
# verify-common.sh -- this script and import.sh can never enforce
# different rules.
#
# Usage:
#   bash verify.sh <path/to/bas-airgap-<version>.tar.gz>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/verify-common.sh"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

TARBALL="${1:-}"
if [[ -z "$TARBALL" ]]; then
  err "Usage: bash verify.sh <bas-airgap-<version>.tar.gz>"
  exit 1
fi
if [[ ! -f "$TARBALL" ]]; then
  err "File not found: $TARBALL"
  exit 1
fi

echo ""
echo "  BAS Platform — Bundle Verification"
echo "  Bundle: $(basename "$TARBALL")"
echo ""

# ── 1. GPG signature (mandatory) ────────────────────────────────────────────────
PUBKEY="${BAS_VERIFY_PUBKEY:-${SCRIPT_DIR}/pubkey.asc}"
if ! verify_gpg_signature "$TARBALL" "${TARBALL}.asc" "$PUBKEY"; then
  err "GPG signature verification FAILED. Do NOT import this bundle."
  exit 1
fi
log "GPG signature valid."

# ── 2. Extract into a controlled staging directory ─────────────────────────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
chmod 700 "$WORK_DIR"

tar -xzf "$TARBALL" -C "$WORK_DIR"
BUNDLE_DIR=$(find "$WORK_DIR" -maxdepth 1 -mindepth 1 -type d | head -1)
if [[ -z "$BUNDLE_DIR" ]]; then
  err "Bundle appears empty or malformed."
  exit 1
fi

VERSION=$(cat "${BUNDLE_DIR}/VERSION" 2>/dev/null || echo "unknown")
echo "  Version:  ${VERSION}"

# ── 3. Manifest check against the extracted files ───────────────────────────────
if ! verify_manifest "$BUNDLE_DIR"; then
  err "Bundle integrity check FAILED. Do NOT import this bundle."
  exit 1
fi
log "Bundle manifest verified."

# ── 4. Compose version floor ─────────────────────────────────────────────────────
if ! check_compose_version_floor "2.8.0"; then
  err "Docker Compose on this host does not meet the required floor (2.8.0)."
  exit 1
fi
log "Docker Compose version OK."

# ── 5. Required files present (flat layout) ─────────────────────────────────────
REQUIRED=(
  "images/bas-orchestrator-${VERSION}.tar.gz"
  "images/postgres-16-alpine.tar.gz"
  "setup.sh"
  "docker-compose.yml"
  "docker-compose.prod.yml"
  "import.sh"
)

all_present=true
for f in "${REQUIRED[@]}"; do
  if [[ ! -f "${BUNDLE_DIR}/${f}" ]]; then
    err "Required file missing: ${f}"
    all_present=false
  fi
done

if ! $all_present; then
  err "Bundle is incomplete. Re-pack with packaging/airgap/pack.sh."
  exit 1
fi

echo ""
log "Bundle integrity OK — safe to import."
echo ""
echo "  Run:  sudo bash import.sh $(basename "$TARBALL")"
