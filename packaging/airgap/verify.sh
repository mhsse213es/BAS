#!/usr/bin/env bash
# BAS Platform — Air-Gap Bundle Verifier
#
# Verifies the integrity of a bas-airgap bundle before import.
# Run on the air-gapped target server before import.sh.
#
# Usage:
#   bash verify.sh <path/to/bas-airgap-<version>.tar.gz> [--cosign-pub <key.pub>]
#
# --gpg-pub <key.asc> / env BAS_GPG_PUB: out-of-band GPG key for the bundle's
# .asc signature (checked via verify-sig.sh when an .asc is present).
# --cosign-pub <path> / env BAS_COSIGN_PUB verify with an out-of-band key
# (precedence: flag, env, bundled cosign.pub); the key fingerprint is printed.
#
# Also verifies the cosign signature of EVERY image tar (orchestrator, postgres). cosign >= v3.1.0
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
GPG_PUB_FLAG=""
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cosign-pub=*) COSIGN_PUB_FLAG="${1#--cosign-pub=}"; [[ -n "$COSIGN_PUB_FLAG" ]] || { echo "--cosign-pub requires a path" >&2; exit 1; }; shift ;;
    --gpg-pub=*)    GPG_PUB_FLAG="${1#--gpg-pub=}";       [[ -n "$GPG_PUB_FLAG" ]]    || { echo "--gpg-pub requires a path" >&2; exit 1; }; shift ;;
    --cosign-pub) COSIGN_PUB_FLAG="${2:-}"; [[ -n "$COSIGN_PUB_FLAG" ]] || { echo "--cosign-pub requires a path" >&2; exit 1; }; shift 2 ;;
    --gpg-pub)    GPG_PUB_FLAG="${2:-}";    [[ -n "$GPG_PUB_FLAG" ]]    || { echo "--gpg-pub requires a path" >&2; exit 1; }; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
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

# ── 1b. GPG signature (if .asc present) ────────────────────────────────────────
VERIFY_SIG_SCRIPT="$(dirname "$0")/verify-sig.sh"
[[ -f "$VERIFY_SIG_SCRIPT" ]] || VERIFY_SIG_SCRIPT="$(dirname "$0")/../signing/verify-sig.sh"
if [[ -f "${TARBALL}.asc" ]]; then
  if [[ ! -f "$VERIFY_SIG_SCRIPT" ]]; then
    err ".asc present but verify-sig.sh not found -- cannot verify origin."
    exit 1
  fi
  GPG_ARGS=()
  [[ -n "$GPG_PUB_FLAG" ]] && GPG_ARGS=(--gpg-pub "$GPG_PUB_FLAG")
  bash "$VERIFY_SIG_SCRIPT" "$TARBALL" ${GPG_ARGS[@]+"${GPG_ARGS[@]}"} || { err "GPG verification failed -- do NOT import this bundle."; exit 1; }
elif [[ -n "${GPG_PUB_FLAG:-${BAS_GPG_PUB:-}}" ]]; then
  err "An external GPG key was supplied but ${TARBALL}.asc does not exist -- cannot verify origin."
  exit 1
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
mrc=0
mout=$(cd "$BUNDLE_DIR" && sha256sum --check --strict MANIFEST.sha256 2>&1) || mrc=$?
PASS_COUNT=$(grep -c ': OK$' <<<"$mout" || true)
if [[ $mrc -ne 0 ]]; then
  grep -v ': OK$' <<<"$mout" | while IFS= read -r l; do err "$l"; done
  FAIL_COUNT=1
fi

if [[ $FAIL_COUNT -gt 0 ]]; then
  echo ""
  err "Bundle manifest verification failed (corrupt, missing or malformed entries). Do NOT import this bundle."
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
  "compose/VERSION"
  "cosign-verify-lib.sh"
  "images/postgres-16-alpine.tar"
  "images/postgres-16-alpine.tar.bundle"
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
# consistency only. The outer GPG .asc (verify-sig.sh) is the trust anchor, and
# only for origin when its key is out-of-band (--gpg-pub / BAS_GPG_PUB) or its
# fingerprint matches the published one.
AIRGAP_LIB="$(dirname "$0")/cosign-verify-lib.sh"
if [[ ! -f "$AIRGAP_LIB" ]]; then
  err "cosign-verify-lib.sh not found next to verify.sh -- cannot verify signature."
  exit 1
fi
# shellcheck source=cosign-verify-lib.sh
source "$AIRGAP_LIB"
airgap_external_pub "$COSIGN_PUB_FLAG" || { err "Cannot verify signature -- do NOT import this bundle."; exit 1; }
airgap_select_pub "${BUNDLE_DIR}/cosign.pub"
if ! airgap_verify_images "${BUNDLE_DIR}/images" "$AIRGAP_PUB" "$VERSION"; then
  err "Cannot verify signature -- do NOT import this bundle."
  exit 1
fi
if [[ "$(tr -d '[:space:]' < "${BUNDLE_DIR}/compose/VERSION" 2>/dev/null)" != "$(echo "$VERSION" | tr -d '[:space:]')" ]]; then
  err "compose/VERSION does not match the bundle VERSION (${VERSION}) -- do NOT import this bundle."
  exit 1
fi

echo ""
log "Bundle integrity OK — safe to import."
echo ""
echo "  Run:  sudo bash import.sh $(basename "$TARBALL")"
