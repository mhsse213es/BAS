#!/usr/bin/env bash
# BAS Platform — Binary Signer
#
# Signs all built binaries with a GPG detached signature and generates a
# SHA-256 manifest (BINARIES.sha256) that is itself GPG-signed.
#
# Usage:
#   bash packaging/signing/sign-binaries.sh <binaries-dir>
#
# Example:
#   bash packaging/signing/sign-binaries.sh dist/agents
#
# Output (in <binaries-dir>/):
#   BINARIES.sha256       SHA-256 of every binary
#   BINARIES.sha256.asc   GPG signature of the manifest
#   <binary>.asc          GPG detached sig per binary (for individual verification)
#
# Prerequisites:
#   - GPG signing key generated with keygen.sh (releases@audspect.com)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_EMAIL="releases@audspect.com"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

BINARIES_DIR="${1:-}"
if [[ -z "$BINARIES_DIR" ]]; then
  err "Usage: bash sign-binaries.sh <binaries-dir>"
  exit 1
fi
if [[ ! -d "$BINARIES_DIR" ]]; then
  err "Directory not found: $BINARIES_DIR"
  exit 1
fi

# ── GPG availability ───────────────────────────────────────────────────────────
if ! command -v gpg &>/dev/null; then
  err "gpg is not installed."
  exit 1
fi
if ! gpg --list-secret-keys "${KEY_EMAIL}" &>/dev/null; then
  err "No signing key found for ${KEY_EMAIL}."
  echo "  Generate one first: bash packaging/signing/keygen.sh"
  exit 1
fi

PUBKEY="${SCRIPT_DIR}/pubkey.asc"
if [[ ! -f "$PUBKEY" ]]; then
  err "pubkey.asc not found at ${PUBKEY}. Run keygen.sh first."
  exit 1
fi

# ── Sign each binary individually ─────────────────────────────────────────────
log "Signing binaries in ${BINARIES_DIR}..."
signed=0

while IFS= read -r -d '' binary; do
  name="$(basename "$binary")"
  # Skip existing .asc files and the manifest
  [[ "$name" == *.asc ]]          && continue
  [[ "$name" == "BINARIES.sha256" ]] && continue

  sigfile="${binary}.asc"
  # Remove stale sig
  rm -f "$sigfile"

  gpg --quiet --batch --armor \
      --detach-sign \
      --local-user "${KEY_EMAIL}" \
      --output "$sigfile" \
      "$binary"

  log "  signed: ${name}"
  signed=$((signed + 1))
done < <(find "$BINARIES_DIR" -maxdepth 1 -type f -print0 | sort -z)

if [[ $signed -eq 0 ]]; then
  warn "No binaries found in ${BINARIES_DIR} to sign."
  exit 0
fi

# ── Generate SHA-256 manifest ─────────────────────────────────────────────────
MANIFEST="${BINARIES_DIR}/BINARIES.sha256"
log "Generating manifest: ${MANIFEST}"
(
  cd "$BINARIES_DIR"
  # Only hash the binaries themselves, not .asc or the manifest
  find . -maxdepth 1 -type f ! -name "*.asc" ! -name "BINARIES.sha256" \
    | sort \
    | xargs sha256sum 2>/dev/null | sed 's|\./||'
) > "$MANIFEST"

log "  $(wc -l < "$MANIFEST") entries in manifest"

# ── Sign the manifest ─────────────────────────────────────────────────────────
MANIFEST_SIG="${MANIFEST}.asc"
rm -f "$MANIFEST_SIG"
gpg --quiet --batch --armor \
    --detach-sign \
    --local-user "${KEY_EMAIL}" \
    --output "$MANIFEST_SIG" \
    "$MANIFEST"

log "Manifest signed: $(basename "$MANIFEST_SIG")"

# ── Self-verify ───────────────────────────────────────────────────────────────
TMPRING=$(mktemp -d)
trap 'rm -rf "$TMPRING"' EXIT

gpg --quiet --batch --no-default-keyring \
    --keyring "${TMPRING}/bas.gpg" \
    --import "${PUBKEY}" 2>/dev/null

if gpg --quiet --batch --no-default-keyring \
       --keyring "${TMPRING}/bas.gpg" \
       --verify "${MANIFEST_SIG}" "${MANIFEST}" 2>/dev/null; then
  log "Self-verify OK."
else
  err "Self-verify FAILED — pubkey.asc may be outdated. Re-run keygen.sh."
  exit 1
fi

echo ""
log "Binary signing complete."
echo "  Binaries signed:  ${signed}"
echo "  Manifest:         ${MANIFEST}"
echo "  Manifest sig:     ${MANIFEST_SIG}"
echo ""
echo "  Include BINARIES.sha256, BINARIES.sha256.asc, and pubkey.asc in the bundle."
echo "  Clients verify with: bash verify-binary.sh <binary>"
