#!/usr/bin/env bash
# BAS Platform — GPG Signing Key Generator
#
# Run ONCE on the designated build/signing machine to create the Audspect
# release signing key pair.  The private key stays on the signing machine;
# only pubkey.asc is committed to the repo.
#
# Usage:
#   bash packaging/signing/keygen.sh
#
# After running, commit the updated pubkey.asc to the repository.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

KEY_NAME="Audspect BAS Platform"
KEY_EMAIL="releases@audspect.com"
KEY_COMMENT="BAS Release Signing Key"

# Check if key already exists
if gpg --list-secret-keys "${KEY_EMAIL}" &>/dev/null; then
  warn "A signing key for ${KEY_EMAIL} already exists."
  read -r -p "  Export existing public key? [Y/n] " yn
  [[ "${yn,,}" == "n" ]] && exit 0
else
  log "Generating GPG signing key for ${KEY_NAME} <${KEY_EMAIL}>..."
  echo "  This may take a moment (entropy collection)."
  echo ""

  gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: ${KEY_NAME}
Name-Comment: ${KEY_COMMENT}
Name-Email: ${KEY_EMAIL}
Expire-Date: 3y
%no-protection
%commit
EOF

  log "Key generated."
fi

# Export public key
PUBKEY="${REPO_ROOT}/packaging/signing/pubkey.asc"
gpg --armor --export "${KEY_EMAIL}" > "${PUBKEY}"
log "Public key exported to: ${PUBKEY}"

# Show fingerprint
echo ""
echo "  Key fingerprint:"
gpg --fingerprint "${KEY_EMAIL}" | grep -A1 "pub" | tail -1 | tr -d ' '
echo ""
warn "IMPORTANT — Back up your private key securely:"
echo "  gpg --armor --export-secret-keys ${KEY_EMAIL} > bas-signing-key-PRIVATE.asc"
echo "  Store this in a secure vault (Vault, HSM, encrypted USB). NEVER commit it."
echo ""
log "Next step: git add packaging/signing/pubkey.asc && git commit -m 'chore: add release signing public key'"
