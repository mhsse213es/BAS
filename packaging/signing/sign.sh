#!/usr/bin/env bash
# BAS Platform — Bundle Signer
#
# Signs a release tarball (compose or airgap) with a GPG detached signature.
# Optionally also signs the Docker image with cosign if available.
#
# Usage:
#   bash packaging/signing/sign.sh <path/to/bundle.tar.gz> [--cosign <image:tag>]
#
# Prerequisites:
#   - GPG signing key generated with keygen.sh
#   - cosign installed (only if --cosign flag used)
#
# Output:
#   <bundle>.tar.gz.asc     GPG detached armored signature
#   <bundle>.tar.gz.sha256  sha256 checksum (created if absent)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

KEY_EMAIL="releases@audspect.com"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

TARBALL=""
COSIGN_IMAGE=""

# ── Parse args ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cosign) shift; COSIGN_IMAGE="${1:-}"; shift ;;
    -*) err "Unknown flag: $1"; exit 1 ;;
    *)  TARBALL="$1"; shift ;;
  esac
done

if [[ -z "$TARBALL" ]]; then
  err "Usage: bash sign.sh <bundle.tar.gz> [--cosign <image:tag>]"
  exit 1
fi
if [[ ! -f "$TARBALL" ]]; then
  err "File not found: $TARBALL"
  exit 1
fi

# ── GPG availability ───────────────────────────────────────────────────────────
if ! command -v gpg &>/dev/null; then
  err "gpg is not installed. Install with: apt-get install -y gnupg"
  exit 1
fi
if ! gpg --list-secret-keys "${KEY_EMAIL}" &>/dev/null; then
  err "No signing key found for ${KEY_EMAIL}."
  echo "  Generate one first: bash packaging/signing/keygen.sh"
  exit 1
fi

# ── 1. sha256 checksum (idempotent) ───────────────────────────────────────────
CHECKSUM="${TARBALL}.sha256"
if [[ ! -f "$CHECKSUM" ]]; then
  log "Generating sha256 checksum..."
  sha256sum "${TARBALL}" > "${CHECKSUM}" 2>/dev/null || \
    shasum -a 256 "${TARBALL}" > "${CHECKSUM}"
fi
log "sha256: $(cat "${CHECKSUM}" | cut -d' ' -f1)"

# ── 2. GPG detached signature ──────────────────────────────────────────────────
SIGFILE="${TARBALL}.asc"
log "Signing with GPG key ${KEY_EMAIL}..."
gpg --armor \
    --detach-sign \
    --local-user "${KEY_EMAIL}" \
    --output "${SIGFILE}" \
    "${TARBALL}"

log "Signature written: ${SIGFILE}"

# Quick self-verify
PUBKEY="${REPO_ROOT}/packaging/signing/pubkey.asc"
if [[ -f "$PUBKEY" ]]; then
  TMPRING=$(mktemp -d)
  trap 'rm -rf "$TMPRING"' EXIT
  gpg --quiet --batch --no-default-keyring \
      --keyring "${TMPRING}/verify.gpg" \
      --import "${PUBKEY}" 2>/dev/null
  if gpg --quiet --batch --no-default-keyring \
         --keyring "${TMPRING}/verify.gpg" \
         --verify "${SIGFILE}" "${TARBALL}" 2>/dev/null; then
    log "Self-verify OK."
  else
    warn "Self-verify failed — pubkey.asc may be outdated. Re-run keygen.sh to refresh."
  fi
fi

# ── 3. cosign image signing (optional) ────────────────────────────────────────
if [[ -n "$COSIGN_IMAGE" ]]; then
  bash "${REPO_ROOT}/packaging/signing/cosign.sh" --sign "${COSIGN_IMAGE}"
fi

echo ""
log "Signing complete."
echo ""
echo "  Distribute these three files together:"
echo "    $(basename "${TARBALL}")"
echo "    $(basename "${TARBALL}").sha256"
echo "    $(basename "${TARBALL}").asc"
echo ""
echo "  Customers verify with:"
echo "    bash verify-sig.sh $(basename "${TARBALL}")"
