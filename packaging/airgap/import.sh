#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Importer
#
# Run on the AIR-GAPPED target server (no internet required).
# Verifies the bundle (GPG signature, manifest, Compose version), THEN
# hands off to setup.sh, which loads every Docker image itself -- it is
# the sole place the orchestrator image is cosign-gated before any
# `docker load` touches it. This script never calls `docker load`. No
# step after verification can run if any check before it failed -- see
# verify-common.sh for the shared checks with verify.sh.
#
# Usage:
#   sudo bash import.sh <path/to/bas-airgap-<version>.tar.gz>
#
# Optional flags (passed through to setup.sh):
#   --no-wizard   Run setup.sh with default/config values (no whiptail)
#   --resume      Resume an install that was previously interrupted
#   --reinstall   Reinstall over a previously completed install
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/verify-common.sh"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# BAS_IMPORT_SKIP_ROOT_CHECK is a test-only escape hatch (same pattern as
# BAS_VERIFY_PUBKEY / BAS_PACK_SIGNING_DIR) -- never set outside a test harness.
if [[ $EUID -ne 0 ]] && [[ "${BAS_IMPORT_SKIP_ROOT_CHECK:-}" != "1" ]]; then
  err "This importer must be run as root."
  echo "  Run: sudo bash $0 <bundle>"
  exit 1
fi

TARBALL="${1:-}"
if [[ -z "$TARBALL" ]]; then
  err "Usage: sudo bash import.sh <bas-airgap-<version>.tar.gz> [--no-wizard]"
  exit 1
fi
if [[ ! -f "$TARBALL" ]]; then
  err "File not found: $TARBALL"
  exit 1
fi

shift
SETUP_EXTRA_ARGS=("$@")

if ! command -v docker &>/dev/null; then
  err "Docker is not installed on this server."
  exit 1
fi
if ! docker info &>/dev/null; then
  err "Docker daemon is not running. Start it: systemctl start docker"
  exit 1
fi

# ── 1. GPG signature (mandatory, before anything is extracted for use) ─────────
PUBKEY="${BAS_VERIFY_PUBKEY:-${SCRIPT_DIR}/pubkey.asc}"
if ! verify_gpg_signature "$TARBALL" "${TARBALL}.asc" "$PUBKEY"; then
  err "GPG signature verification FAILED. Import aborted. Zero images loaded, zero state changed."
  exit 1
fi
log "GPG signature verified."

# ── 2. Extract into a controlled staging directory ──────────────────────────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
chmod 700 "$WORK_DIR"

log "Extracting bundle..."
tar -xzf "$TARBALL" -C "$WORK_DIR"

BUNDLE_DIR=$(find "$WORK_DIR" -maxdepth 1 -mindepth 1 -type d | head -1)
if [[ -z "$BUNDLE_DIR" ]]; then
  err "Bundle appears empty or malformed. Run verify.sh first."
  exit 1
fi

VERSION=$(cat "${BUNDLE_DIR}/VERSION" 2>/dev/null || echo "unknown")
log "Bundle version: ${VERSION}"

# ── 3. Manifest check against the files as extracted right now ─────────────────
# This is the TOCTOU guard: everything from here on reads only from
# $BUNDLE_DIR (resolved once above), never by re-opening $TARBALL or any
# other mutable path.
if ! verify_manifest "$BUNDLE_DIR"; then
  err "Manifest verification FAILED. Import aborted. Zero images loaded, zero state changed."
  exit 1
fi
log "Manifest OK."

# ── 4. Compose version floor ─────────────────────────────────────────────────────
if ! check_compose_version_floor "2.8.0"; then
  err "Docker Compose does not meet the required floor (2.8.0). Import aborted. Zero images loaded, zero state changed."
  exit 1
fi
log "Docker Compose version OK."

# ── 5. Docker images are NOT loaded here ────────────────────────────────────────
# setup.sh's own _do_install_steps loop is the sole loader of every image in
# ${BUNDLE_DIR}/images/ -- it is the only place that gate-checks the
# orchestrator artifact against cosign.pub + the .bundle signature before
# calling `docker load` on it (see setup.sh's _verify_orchestrator_artifact).
# Loading images here first, ahead of that gate, would let a cosign failure
# discovered moments later be reported against an image already sitting in
# the local Docker store -- exactly the bytes-never-reach-the-daemon
# invariant that check exists to guarantee.

# ── 6. Run setup wizard (flat layout -- setup.sh is at the bundle root) ────────
SETUP_SCRIPT="${BUNDLE_DIR}/setup.sh"
if [[ ! -f "$SETUP_SCRIPT" ]]; then
  err "setup.sh not found inside bundle."
  exit 1
fi

log "Launching setup wizard..."
bash "$SETUP_SCRIPT" --offline "${SETUP_EXTRA_ARGS[@]}"
