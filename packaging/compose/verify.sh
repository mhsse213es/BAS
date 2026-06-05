#!/usr/bin/env bash
# BAS Platform — Bundle Integrity Verifier (in-place)
#
# Verifies the integrity of an UNZIPPED bas-install bundle before setup.
# Run from inside the unzipped bundle directory on the target server.
#
# Usage:
#   cd bas-install-<version>
#   bash verify.sh
#
# Exit codes: 0 = all files verified, 1 = mismatch/missing file or no manifest.
set -euo pipefail

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# Resolve the bundle directory as the location of this script, so it works
# regardless of the caller's current working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MANIFEST="MANIFEST.sha256"
# Strip a possible UTF-8 BOM from the VERSION file (Windows-written).
VERSION=$(tr -d '\357\273\277' < VERSION 2>/dev/null || echo "unknown")

echo ""
echo "  BAS Platform — Bundle Integrity Check"
echo "  Bundle:  $(basename "$SCRIPT_DIR")"
echo "  Version: ${VERSION}"
echo ""

if [[ ! -f "$MANIFEST" ]]; then
  err "MANIFEST.sha256 not found — cannot verify integrity."
  err "Re-build the bundle with packaging/windows-build.ps1."
  exit 1
fi

# Pick an available SHA-256 tool.
if command -v sha256sum &>/dev/null; then
  HASH_CMD() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum &>/dev/null; then
  HASH_CMD() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  err "Neither sha256sum nor shasum found — cannot verify."
  exit 1
fi

echo -n "  Verifying files against manifest... "
FAIL_COUNT=0
PASS_COUNT=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  expected_hash="${line%% *}"
  rel_path="${line#* }"
  rel_path="${rel_path#./}"
  # Strip any leading whitespace left from the two-space separator.
  rel_path="${rel_path#"${rel_path%%[![:space:]]*}"}"

  if [[ ! -f "$rel_path" ]]; then
    echo ""; err "Missing: ${rel_path}"
    FAIL_COUNT=$((FAIL_COUNT + 1)); continue
  fi

  actual_hash="$(HASH_CMD "$rel_path")"
  if [[ "$actual_hash" != "$expected_hash" ]]; then
    echo ""; err "Corrupt: ${rel_path}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    PASS_COUNT=$((PASS_COUNT + 1))
  fi
done < "$MANIFEST"

if [[ $FAIL_COUNT -gt 0 ]]; then
  echo ""
  err "${FAIL_COUNT} file(s) failed verification. Do NOT install this bundle."
  exit 1
fi

echo "done."
log "${PASS_COUNT} files verified — bundle integrity OK."
echo ""
echo "  Safe to install. Run:"
echo "    sudo bash setup.sh --offline"
echo ""
