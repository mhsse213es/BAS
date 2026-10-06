#!/usr/bin/env bash
# BAS Platform — Signature Verifier
#
# Verifies the GPG signature of a release bundle.
# Run on the target server before import.sh or setup.sh.
#
# Usage:
#   bash verify-sig.sh <path/to/bundle.tar.gz> [--gpg-pub <key.asc>]
#
# Expects <bundle>.tar.gz.asc alongside the tarball.
# Key selection (precedence): --gpg-pub flag, BAS_GPG_PUB env, then the
# pubkey.asc next to this script. TRUST MODEL: a bundled pubkey.asc only proves
# integrity, not origin -- whoever replaces the bundle can replace that key too.
# For origin, pass an out-of-band key (--gpg-pub) or compare the printed
# fingerprint with the one Audspect publishes. An external key is used
# exclusively; a missing/unreadable path aborts.
#
# Exit codes:
#   0  Signature valid
#   1  Signature invalid, missing, or gpg unavailable
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

TARBALL="${1:-}"
GPG_PUB_FLAG=""
if [[ "${2:-}" == "--gpg-pub" ]]; then
  GPG_PUB_FLAG="${3:-}"
  [[ -n "$GPG_PUB_FLAG" ]] || { echo "--gpg-pub requires a path" >&2; exit 1; }
fi
if [[ -z "$TARBALL" ]]; then
  err "Usage: bash verify-sig.sh <bundle.tar.gz>"
  exit 1
fi
if [[ ! -f "$TARBALL" ]]; then
  err "File not found: $TARBALL"
  exit 1
fi

SIGFILE="${TARBALL}.asc"
PUBKEY="${SCRIPT_DIR}/pubkey.asc"
KEY_KIND=BUNDLED
EXT_PUB="${GPG_PUB_FLAG:-${BAS_GPG_PUB:-}}"
if [[ -n "$EXT_PUB" ]]; then
  if [[ ! -f "$EXT_PUB" || ! -r "$EXT_PUB" ]]; then
    err "External GPG public key not found or unreadable: ${EXT_PUB}"
    exit 1
  fi
  PUBKEY="$EXT_PUB"
  KEY_KIND=EXTERNAL
fi

echo ""
echo "  BAS Platform — Signature Verification"
echo "  Bundle:    $(basename "${TARBALL}")"
echo ""

# ── gpg check ─────────────────────────────────────────────────────────────────
if ! command -v gpg &>/dev/null; then
  err "gpg is not installed. Install with: apt-get install -y gnupg"
  exit 1
fi

# ── signature file ─────────────────────────────────────────────────────────────
if [[ ! -f "$SIGFILE" ]]; then
  err "Signature file not found: ${SIGFILE}"
  echo "  The .asc file must be in the same directory as the bundle."
  exit 1
fi

# ── public key ─────────────────────────────────────────────────────────────────
if [[ ! -f "$PUBKEY" ]]; then
  err "Public key not found: ${PUBKEY}"
  echo "  Ensure pubkey.asc is in the same directory as verify-sig.sh."
  exit 1
fi

# ── import key into isolated temporary keyring ────────────────────────────────
TMPRING=$(mktemp -d)
trap 'rm -rf "$TMPRING"' EXIT

gpg --quiet --batch --no-default-keyring \
    --keyring "${TMPRING}/bas.gpg" \
    --import "${PUBKEY}" 2>/dev/null

KEY_ID=$(gpg --quiet --batch --no-default-keyring \
             --keyring "${TMPRING}/bas.gpg" \
             --list-keys --with-colons 2>/dev/null \
  | awk -F: '/^fpr/{print $10; exit}')

echo ""
echo "  ============================================================"
echo "   Verifying with ${KEY_KIND} GPG key, fingerprint: ${KEY_ID:-unknown}"
echo "   (compare with the fingerprint Audspect publishes)"
echo "  ============================================================"
if [[ "$KEY_KIND" == BUNDLED ]]; then
  warn "A bundled key proves integrity, not origin, unless its fingerprint matches the published one (or use --gpg-pub / BAS_GPG_PUB)."
fi
echo ""

# ── verify detached signature ──────────────────────────────────────────────────
if gpg --quiet --batch --no-default-keyring \
       --keyring "${TMPRING}/bas.gpg" \
       --verify "${SIGFILE}" "${TARBALL}" 2>/dev/null; then
  log "Signature VALID — bundle is authentic."
  echo ""
else
  err "Signature INVALID."
  echo ""
  echo "  Do NOT install this bundle. It may have been tampered with."
  echo "  Contact Audspect support if you received this bundle from an official source."
  exit 1
fi

# ── sha256 checksum (bonus check if present) ──────────────────────────────────
CHECKSUM="${TARBALL}.sha256"
if [[ -f "$CHECKSUM" ]]; then
  if sha256sum --check --status "${CHECKSUM}" 2>/dev/null || \
     shasum -a 256 --check --status "${CHECKSUM}" 2>/dev/null; then
    log "sha256 checksum OK."
  else
    err "sha256 checksum MISMATCH."
    exit 1
  fi
else
  warn "No .sha256 file found — skipping checksum verification."
fi

echo ""
log "All checks passed. Safe to proceed with installation."
