#!/usr/bin/env bash
# BAS Platform — Release Artifact Signing (cosign sign-blob)
#
# Signs or verifies the BAS orchestrator release tarball (the `docker save`
# output, after every patch that will change its bytes) using cosign's
# sign-blob/verify-blob against a local key pair. This operates on the
# tarball's raw bytes, not on an OCI image reference -- cosign's image
# (sign/verify/save/load) subcommands all resolve against a container
# REGISTRY, which does not exist in this on-prem/air-gapped deployment
# model: the orchestrator image is built and `docker save`d but never
# pushed anywhere. sign-blob/verify-blob need no registry.
#
# --tlog-upload=false --use-signing-config=false are both required: without
# them, cosign silently uploads the signature to the public Sigstore
# transparency log (rekor.sigstore.dev) over the internet even when signing
# with a purely local key pair, which this on-prem/air-gapped model cannot
# depend on. Confirmed by real signing: omitting these flags produced a
# bundle containing a real rekor.sigstore.dev tlog entry; with them, the
# bundle contains only the local signature, no network contact needed to
# sign OR verify (--insecure-ignore-tlog on verify-blob skips checking for
# a tlog entry that was never created).
#
# Usage:
#   bash packaging/signing/cosign.sh --keygen                 # one-time key setup
#   bash packaging/signing/cosign.sh --sign   <artifact-file> # writes <artifact-file>.bundle
#   bash packaging/signing/cosign.sh --verify <artifact-file> # reads <artifact-file>.bundle
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
  local artifact="${1:-}"
  if [[ -z "$artifact" ]]; then
    err "Usage: bash cosign.sh --sign <artifact-file>"
    exit 1
  fi
  require_cosign
  if [[ ! -f "$COSIGN_KEY" ]]; then
    err "cosign.key not found. Run: bash cosign.sh --keygen"
    exit 1
  fi
  if [[ ! -f "$artifact" ]]; then
    err "Artifact not found: ${artifact}"
    exit 1
  fi
  log "Signing artifact: ${artifact}"
  COSIGN_PASSWORD="" cosign sign-blob \
    --key "${COSIGN_KEY}" \
    --yes \
    --tlog-upload=false \
    --use-signing-config=false \
    --bundle "${artifact}.bundle" \
    "${artifact}"
  log "Artifact signed: ${artifact}"
  echo "  Bundle: ${artifact}.bundle"
  echo "  Verify with: bash cosign.sh --verify ${artifact}"
}

cmd_verify() {
  local artifact="${1:-}"
  if [[ -z "$artifact" ]]; then
    err "Usage: bash cosign.sh --verify <artifact-file>"
    exit 1
  fi
  require_cosign
  if [[ ! -f "$COSIGN_PUB" ]]; then
    err "cosign.pub not found. Cannot verify without the public key."
    exit 1
  fi
  if [[ ! -f "${artifact}.bundle" ]]; then
    err "Signature bundle not found: ${artifact}.bundle"
    exit 1
  fi
  log "Verifying artifact: ${artifact}"
  if cosign verify-blob \
       --key "${COSIGN_PUB}" \
       --bundle "${artifact}.bundle" \
       --insecure-ignore-tlog \
       "${artifact}" 2>/dev/null; then
    log "Artifact signature VALID: ${artifact}"
  else
    err "Artifact signature INVALID or not found for: ${artifact}"
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
    echo "  bash cosign.sh --keygen                 # one-time key setup"
    echo "  bash cosign.sh --sign   <artifact-file> # sign artifact"
    echo "  bash cosign.sh --verify <artifact-file> # verify artifact"
    exit 1
    ;;
esac
