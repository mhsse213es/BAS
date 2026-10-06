#!/usr/bin/env bash
# BAS Platform — Signature Verifier
#
# Verifies the GPG signature of a release bundle.
# Run on the target server before import.sh or setup.sh.
#
# Usage:
#   bash verify-sig.sh <path/to/bundle.tar.gz> [--gpg-pub <key.asc> | --gpg-pub=<key.asc>]
#
# Expects <bundle>.tar.gz.asc alongside the tarball.
# Key selection (precedence): --gpg-pub flag, BAS_GPG_PUB env, then the
# pubkey.asc next to this script. TRUST MODEL: a bundled pubkey.asc only proves
# integrity, not origin -- whoever replaces the bundle can replace that key too.
# For origin, pass an out-of-band key (--gpg-pub) or compare the printed
# fingerprint with the one Audspect publishes. An external key is used
# exclusively; a missing/unreadable path aborts. NOTE: with sudo the environment
# is stripped, so prefer the flag (or: sudo BAS_GPG_PUB=<path> bash ...).
#
# Hardening: the key file is imported into a throwaway GNUPGHOME; it must hold
# exactly ONE primary key; and the signature's VALIDSIG primary fingerprint must
# equal that key's fingerprint (so the fingerprint shown is the signer's).
#
# Exit codes:
#   0  Signature valid
#   1  Signature invalid, missing, or gpg unavailable
set -euo pipefail
unset CDPATH

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

TARBALL=""
GPG_PUB_FLAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gpg-pub=*) GPG_PUB_FLAG="${1#--gpg-pub=}"; shift ;;
    --gpg-pub)
      [[ $# -ge 2 ]] || { err "--gpg-pub requires a path"; exit 1; }
      GPG_PUB_FLAG="$2"; shift 2 ;;
    -*) err "Unknown option: $1"; exit 1 ;;
    *)
      [[ -z "$TARBALL" ]] || { err "Unexpected extra argument: $1"; exit 1; }
      TARBALL="$1"; shift ;;
  esac
done
if [[ -z "$TARBALL" ]]; then
  err "Usage: bash verify-sig.sh <bundle.tar.gz> [--gpg-pub <key.asc>]"
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
echo "  Bundle:    $(basename -- "${TARBALL}")"
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

# ── throwaway keyring: nothing from the host's keyring can vouch for a signature ──
GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
G=(gpg --batch --quiet --no-autostart)

if ! "${G[@]}" --import "$PUBKEY" 2>/dev/null; then
  err "Could not import the public key from ${PUBKEY}."
  exit 1
fi
LISTING="$("${G[@]}" --with-colons --list-keys 2>/dev/null)"
PUB_COUNT=$(grep -c '^pub:' <<<"$LISTING" || true)
if [[ "$PUB_COUNT" -ne 1 ]]; then
  err "Key file ${PUBKEY} contains ${PUB_COUNT} primary keys; exactly one is required (a multi-key file could let a different key vouch for the bundle). Refusing."
  exit 1
fi
KEY_FPR=$(awk -F: '/^fpr/{print $10; exit}' <<<"$LISTING")
if [[ -z "$KEY_FPR" ]]; then
  err "Could not read the key fingerprint from ${PUBKEY}."
  exit 1
fi

echo ""
echo "  ============================================================"
echo "   Verifying with ${KEY_KIND} GPG key, fingerprint: ${KEY_FPR}"
echo "   (compare with the fingerprint Audspect publishes)"
echo "  ============================================================"
if [[ "$KEY_KIND" == BUNDLED ]]; then
  warn "A bundled key proves integrity, not origin, unless its fingerprint matches the published one (or use --gpg-pub / BAS_GPG_PUB)."
fi
echo ""

# ── verify detached signature; the SIGNER must be the single imported key ──────
rc=0
STATUS="$("${G[@]}" --status-fd 1 --verify "${SIGFILE}" "${TARBALL}" 2>/dev/null)" || rc=$?
VALID_LINES="$(grep '^\[GNUPG:\] VALIDSIG ' <<<"$STATUS" || true)"
SIGNER_OK=false
if [[ $rc -eq 0 && -n "$VALID_LINES" ]]; then
  SIGNER_OK=true
  while IFS= read -r l; do
    # [GNUPG:] VALIDSIG <fpr> <date> <ts> <expire> <ver> <res> <pk> <hash> <class> <primary-fpr>
    primary="$(awk '{print toupper($12)}' <<<"$l")"
    [[ "$primary" == "$(tr '[:lower:]' '[:upper:]' <<<"$KEY_FPR")" ]] || SIGNER_OK=false
  done <<<"$VALID_LINES"
fi
if $SIGNER_OK; then
  log "Signature VALID — signed by key ${KEY_FPR} (VALIDSIG primary fingerprint matches)."
  echo ""
else
  err "Signature INVALID, or not made by the key ${KEY_FPR}."
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
