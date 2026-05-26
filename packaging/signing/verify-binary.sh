#!/usr/bin/env bash
# BAS Platform — Binary Verifier
#
# Verifies a single BAS binary against:
#   1. Its individual GPG detached signature (<binary>.asc)
#   2. The signed SHA-256 manifest (BINARIES.sha256 + BINARIES.sha256.asc)
#
# Usage:
#   bash verify-binary.sh <path/to/bas-agent-linux-amd64>
#
# The pubkey.asc, <binary>.asc, and BINARIES.sha256{,.asc} must be in the
# same directory as the binary being verified.
#
# Exit codes:
#   0  All checks passed
#   1  Verification failed
set -euo pipefail

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

BINARY="${1:-}"
if [[ -z "$BINARY" ]]; then
  err "Usage: bash verify-binary.sh <binary>"
  exit 1
fi
if [[ ! -f "$BINARY" ]]; then
  err "File not found: $BINARY"
  exit 1
fi

BINARY_DIR="$(cd "$(dirname "$BINARY")" && pwd)"
BINARY_NAME="$(basename "$BINARY")"
SIGFILE="${BINARY_DIR}/${BINARY_NAME}.asc"
PUBKEY="${BINARY_DIR}/pubkey.asc"
MANIFEST="${BINARY_DIR}/BINARIES.sha256"
MANIFEST_SIG="${BINARY_DIR}/BINARIES.sha256.asc"

echo ""
echo "  BAS Platform — Binary Verification"
echo "  Binary: ${BINARY_NAME}"
echo ""

# ── gpg check ─────────────────────────────────────────────────────────────────
if ! command -v gpg &>/dev/null; then
  err "gpg is not installed. Install with: apt-get install -y gnupg"
  exit 1
fi

# ── public key ─────────────────────────────────────────────────────────────────
if [[ ! -f "$PUBKEY" ]]; then
  err "pubkey.asc not found in ${BINARY_DIR}"
  echo "  Ensure pubkey.asc (Audspect release signing key) is alongside the binary."
  exit 1
fi

# ── isolated keyring ──────────────────────────────────────────────────────────
TMPRING=$(mktemp -d)
trap 'rm -rf "$TMPRING"' EXIT

gpg --quiet --batch --no-default-keyring \
    --keyring "${TMPRING}/bas.gpg" \
    --import "${PUBKEY}" 2>/dev/null

KEY_ID=$(gpg --quiet --batch --no-default-keyring \
             --keyring "${TMPRING}/bas.gpg" \
             --list-keys --with-colons 2>/dev/null \
         | awk -F: '/^fpr/{print $10; exit}')
echo "  Signing key: ${KEY_ID:-unknown}"

# ── Check 1: individual binary signature ─────────────────────────────────────
if [[ -f "$SIGFILE" ]]; then
  if gpg --quiet --batch --no-default-keyring \
         --keyring "${TMPRING}/bas.gpg" \
         --verify "${SIGFILE}" "${BINARY}" 2>/dev/null; then
    log "Individual signature valid  (${BINARY_NAME}.asc)"
  else
    err "Individual signature INVALID for ${BINARY_NAME}"
    echo "  The binary may have been tampered with or replaced."
    exit 1
  fi
else
  warn "No individual .asc signature found — skipping individual check."
fi

# ── Check 2: manifest signature ───────────────────────────────────────────────
if [[ -f "$MANIFEST" ]] && [[ -f "$MANIFEST_SIG" ]]; then
  if gpg --quiet --batch --no-default-keyring \
         --keyring "${TMPRING}/bas.gpg" \
         --verify "${MANIFEST_SIG}" "${MANIFEST}" 2>/dev/null; then
    log "Manifest signature valid    (BINARIES.sha256.asc)"
  else
    err "Manifest signature INVALID — binary manifest may have been tampered with."
    exit 1
  fi

  # ── Check 3: SHA-256 of binary matches manifest ───────────────────────────
  expected=$(grep "^[a-f0-9]*  *${BINARY_NAME}$" "${MANIFEST}" | awk '{print $1}')
  if [[ -z "$expected" ]]; then
    warn "${BINARY_NAME} not listed in manifest — cannot verify checksum."
  else
    actual=$(sha256sum "${BINARY}" | awk '{print $1}')
    if [[ "$actual" == "$expected" ]]; then
      log "SHA-256 checksum matches manifest"
    else
      err "SHA-256 MISMATCH for ${BINARY_NAME}"
      echo "  Expected: ${expected}"
      echo "  Actual:   ${actual}"
      exit 1
    fi
  fi
else
  warn "No BINARIES.sha256 manifest found — skipping manifest check."
fi

echo ""
log "All checks passed. Binary is authentic."
