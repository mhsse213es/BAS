#!/usr/bin/env bash
# Downloads the pinned cosign release (packaging/appliance/cosign.pin) to <out>
# and verifies its SHA-256 against the pinned value. Any failure exits non-zero
# and removes the file, so the appliance build fails closed.
#
# Usage: fetch-cosign.sh <out-file> [pin-file]
#        fetch-cosign.sh --verify <file> [pin-file]   (checksum check only)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=fetch
if [[ "${1:-}" == "--verify" ]]; then MODE=verify; shift; fi
OUT="${1:?usage: fetch-cosign.sh [--verify] <file> [pin-file]}"
PIN="${2:-${HERE}/cosign.pin}"

[[ -f "$PIN" ]] || { echo "ERROR: pin file not found: $PIN" >&2; exit 1; }
COSIGN_VERSION="" COSIGN_SHA256_LINUX_AMD64=""
# shellcheck source=cosign.pin
source "$PIN"
[[ "$COSIGN_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: COSIGN_VERSION must be an exact vX.Y.Z (got '${COSIGN_VERSION}')" >&2; exit 1; }
[[ "$COSIGN_SHA256_LINUX_AMD64" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: COSIGN_SHA256_LINUX_AMD64 is not a 64-hex SHA-256" >&2; exit 1; }
IFS=. read -r _maj _min _ <<< "${COSIGN_VERSION#v}"
(( _maj > 3 || (_maj == 3 && _min >= 1) )) || { echo "ERROR: pinned cosign ${COSIGN_VERSION} is older than v3.1.0" >&2; exit 1; }

if [[ "$MODE" == fetch ]]; then
  URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
  echo "[cosign-pin] Downloading ${URL}"
  if ! curl -fsSL --retry 3 -o "$OUT" "$URL"; then
    rm -f "$OUT"; echo "ERROR: cosign download failed" >&2; exit 1
  fi
fi
actual="$(sha256sum "$OUT" | cut -d' ' -f1)"
if [[ "$actual" != "$COSIGN_SHA256_LINUX_AMD64" ]]; then
  rm -f "$OUT"
  echo "ERROR: cosign ${COSIGN_VERSION} checksum mismatch (expected ${COSIGN_SHA256_LINUX_AMD64}, got ${actual})" >&2
  exit 1
fi
chmod 0755 "$OUT"
echo "[cosign-pin] cosign ${COSIGN_VERSION} verified (sha256 ${actual})"
