#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Verifier
#
# Verifies the integrity of a bas-airgap bundle before import.
# Run on the air-gapped target server before import.sh.
#
# Usage:
#   bash verify.sh <path/to/bas-airgap-<version>.tar.gz> [--cosign-pub <key.pub>]
#
# --cosign-pub <path> / env BAS_COSIGN_PUB verify with an out-of-band key
# (precedence: flag, env, bundled cosign.pub); the key fingerprint is printed.
#
# Also verifies the orchestrator image's cosign signature. cosign >= v3.1.0
# must be installed; if it is not, verification FAILS (cannot verify signature).
set -euo pipefail

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

TARBALL="${1:-}"
COSIGN_PUB_FLAG=""
if [[ "${2:-}" == "--cosign-pub" ]]; then
  COSIGN_PUB_FLAG="${3:-}"
  [[ -n "$COSIGN_PUB_FLAG" ]] || { echo "--cosign-pub requires a path" >&2; exit 1; }
fi
if [[ -z "$TARBALL" ]]; then
  err "Usage: bash verify.sh <bas-airgap-<version>.tar.gz>"
  exit 1
fi
if [[ ! -f "$TARBALL" ]]; then
  err "File not found: $TARBALL"
  exit 1
fi

CHECKSUM_FILE="${TARBALL}.sha256"

# ── 1. Verify outer checksum ───────────────────────────────────────────────────
echo ""
echo "  BAS Platform — Bundle Verification"
echo "  Bundle: $(basename "$TARBALL")"
echo "  Size:   $(du -sh "$TARBALL" | cut -f1)"
echo ""

if [[ -f "$CHECKSUM_FILE" ]]; then
  echo -n "  Checking outer sha256... "
  if sha256sum --check --status "$CHECKSUM_FILE" 2>/dev/null || \
     shasum -a 256 --check --status "$CHECKSUM_FILE" 2>/dev/null; then
    log "outer sha256 OK"
  else
    err "Outer sha256 MISMATCH — bundle may be corrupt or tampered."
    exit 1
  fi
else
  warn "No .sha256 file found alongside bundle — skipping outer checksum."
fi

# ── 2. Extract and verify inner manifest ──────────────────────────────────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo -n "  Extracting bundle... "
tar -xzf "$TARBALL" -C "$WORK_DIR"
echo "done."

BUNDLE_DIR=$(find "$WORK_DIR" -maxdepth 1 -mindepth 1 -type d | head -1)
if [[ -z "$BUNDLE_DIR" ]]; then
  err "Bundle appears empty or malformed."
  exit 1
fi

MANIFEST="${BUNDLE_DIR}/MANIFEST.sha256"
if [[ ! -f "$MANIFEST" ]]; then
  err "MANIFEST.sha256 not found inside bundle."
  exit 1
fi

VERSION_FILE="${BUNDLE_DIR}/VERSION"
VERSION=$(cat "$BUNDLE_DIR/VERSION" 2>/dev/null || echo "unknown")
echo "  Version:  ${VERSION}"

echo -n "  Verifying file manifest... "
FAIL_COUNT=0
PASS_COUNT=0
while IFS= read -r line; do
  expected_hash="${line%% *}"
  rel_path="${line#*  }"   # sha256sum format: "<hash>  <path>"
  rel_path="${rel_path#./}"
  abs_path="${BUNDLE_DIR}/${rel_path}"

  if [[ ! -f "$abs_path" ]]; then
    err "Missing: ${rel_path}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    continue
  fi

  actual_hash=$(sha256sum "$abs_path" | cut -d' ' -f1)
  if [[ "$actual_hash" != "$expected_hash" ]]; then
    err "Corrupt: ${rel_path}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    PASS_COUNT=$((PASS_COUNT + 1))
  fi
done < "$MANIFEST"

if [[ $FAIL_COUNT -gt 0 ]]; then
  echo ""
  err "${FAIL_COUNT} file(s) failed verification. Do NOT import this bundle."
  exit 1
fi

if [[ $PASS_COUNT -eq 0 ]]; then
  err "Manifest is empty -- nothing verified. Do NOT import this bundle."
  exit 1
fi
log "${PASS_COUNT} files verified."

# ── 3. Check required files ────────────────────────────────────────────────────
REQUIRED=(
  "images/bas-orchestrator-${VERSION}.tar"
  "images/bas-orchestrator-${VERSION}.tar.bundle"
  "cosign.pub"
  "compose/cosign.pub"
  "cosign-verify-lib.sh"
  "images/postgres-16-alpine.tar.gz"
  "compose/setup.sh"
  "compose/docker-compose.yml"
  "compose/docker-compose.prod.yml"
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

# ── 4. Verify orchestrator image cosign signature ─────────────────────────────
# Trust model: the verifier (this lib, next to the script) and cosign.pub both
# come from the same bundle distribution, so this check proves integrity and
# consistency only. The outer GPG .asc (verify-sig.sh) is the trust anchor.
AIRGAP_LIB="$(dirname "$0")/cosign-verify-lib.sh"
if [[ ! -f "$AIRGAP_LIB" ]]; then
  err "cosign-verify-lib.sh not found next to verify.sh -- cannot verify signature."
  exit 1
fi
# shellcheck source=cosign-verify-lib.sh
source "$AIRGAP_LIB"
airgap_external_pub "$COSIGN_PUB_FLAG" || { err "Cannot verify signature -- do NOT import this bundle."; exit 1; }
airgap_select_pub "${BUNDLE_DIR}/cosign.pub"
if ! airgap_verify_orchestrator "${BUNDLE_DIR}/images/bas-orchestrator-${VERSION}.tar" "$AIRGAP_PUB"; then
  err "Cannot verify signature -- do NOT import this bundle."
  exit 1
fi

echo ""
log "Bundle integrity OK — safe to import."
echo ""
echo "  Run:  sudo bash import.sh $(basename "$TARBALL")"
