#!/usr/bin/env bash
# BAS Platform — Container Image Signing (cosign)
#
# Signs or verifies the BAS orchestrator Docker image using cosign with a
# local key pair (suitable for air-gapped / on-prem deployments).
# Keyless Sigstore signing is NOT used since it requires internet access.
#
# Usage:
#   bash packaging/signing/cosign.sh --keygen               # one-time key setup
#   bash packaging/signing/cosign.sh --sign   <image:tag>   # sign image
#   bash packaging/signing/cosign.sh --verify <image:tag>   # verify image
#
# Key files (DO NOT commit the private key):
#   packaging/signing/cosign.key      (private — keep secret, never commit)
#   packaging/signing/cosign.pub      (public  — commit to repo)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

COSIGN_KEY="${SCRIPT_DIR}/cosign.key"
COSIGN_PUB="${SCRIPT_DIR}/cosign.pub"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── cosign availability ────────────────────────────────────────────────────────
require_cosign() {
  if ! command -v cosign &>/dev/null; then
    err "cosign is not installed."
    echo "  Install: https://docs.sigstore.dev/cosign/system_config/installation/"
    echo "  Quick:   curl -sL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign"
    exit 1
  fi
}

# ── subcommands ────────────────────────────────────────────────────────────────
cmd_keygen() {
  require_cosign
  if [[ -f "$COSIGN_KEY" ]]; then
    warn "cosign.key already exists at ${COSIGN_KEY}."
    read -r -p "  Overwrite? [y/N] " yn
    [[ "${yn,,}" != "y" ]] && exit 0
  fi
  log "Generating cosign key pair (no passphrase for automated signing)..."
  COSIGN_PASSWORD="" cosign generate-key-pair \
    --output-key-prefix "${SCRIPT_DIR}/cosign"
  log "Private key: ${COSIGN_KEY}  ← NEVER commit this"
  log "Public key:  ${COSIGN_PUB}  ← commit to repo"
  warn "Back up cosign.key to a secure vault. Losing it means you cannot sign new releases."
  echo ""
  echo "  Add to .gitignore:  packaging/signing/cosign.key"
  echo "  Commit public key:  git add packaging/signing/cosign.pub"
}

cmd_sign() {
  local image="${1:-}"
  if [[ -z "$image" ]]; then
    err "Usage: bash cosign.sh --sign <image:tag>"
    exit 1
  fi
  require_cosign
  if [[ ! -f "$COSIGN_KEY" ]]; then
    err "cosign.key not found. Run: bash cosign.sh --keygen"
    exit 1
  fi
  log "Signing image: ${image}"
  COSIGN_PASSWORD="" cosign sign \
    --key "${COSIGN_KEY}" \
    --yes \
    "${image}"
  log "Image signed: ${image}"
  echo "  Verify with: bash cosign.sh --verify ${image}"
}

cmd_verify() {
  local image="${1:-}"
  if [[ -z "$image" ]]; then
    err "Usage: bash cosign.sh --verify <image:tag>"
    exit 1
  fi
  require_cosign
  if [[ ! -f "$COSIGN_PUB" ]]; then
    err "cosign.pub not found. Cannot verify without the public key."
    exit 1
  fi
  log "Verifying image: ${image}"
  if cosign verify \
       --key "${COSIGN_PUB}" \
       --insecure-ignore-tlog \
       "${image}" 2>/dev/null | grep -q '"verified":true' 2>/dev/null || \
     COSIGN_PASSWORD="" cosign verify \
       --key "${COSIGN_PUB}" \
       --insecure-ignore-tlog \
       "${image}" &>/dev/null; then
    log "Image signature VALID: ${image}"
  else
    err "Image signature INVALID or not found for: ${image}"
    exit 1
  fi
}

# ── main ───────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --keygen) cmd_keygen ;;
  --sign)   shift; cmd_sign "$@" ;;
  --verify) shift; cmd_verify "$@" ;;
  *)
    echo "Usage:"
    echo "  bash cosign.sh --keygen               # one-time key setup"
    echo "  bash cosign.sh --sign   <image:tag>   # sign image"
    echo "  bash cosign.sh --verify <image:tag>   # verify image"
    exit 1
    ;;
esac
