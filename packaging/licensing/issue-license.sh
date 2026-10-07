#!/usr/bin/env bash
# BAS Platform — standalone license issuer.
#
# Generates a signed customer license file WITHOUT touching the build or
# packaging pipeline. packaging/windows-build.ps1's "Generate license" step
# does the exact same thing, but only as part of a full package rebuild
# (Docker image, agent binaries, signing, zip). A license is a plain file
# verified against the one Audspect-wide public key already embedded in
# every build (orchestrator/internal/license/license_key.go) -- a license
# change never needs a new package. Use this script for that case: a
# renewal, a feature change, or issuing a first license for a customer
# who already has a package installed.
#
# Usage:
#   bash packaging/licensing/issue-license.sh -customer "HDFC Bank" -id hdfc-001 [-days 365] [-features full] [-out PATH]
#
# All flags pass straight through to packaging/licensing/licensegen/main.go
# (run `go run packaging/licensing/licensegen/main.go -h` for the full list).
# Output: <id>.lic in the repo root, with delivery instructions printed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PRIV_KEY="${SCRIPT_DIR}/keys/private.pem"

RED='\033[0;31m'; NC='\033[0m'
err() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

[[ -f "$PRIV_KEY" ]] || err "Private key not found at $PRIV_KEY -- run: bash packaging/licensing/keygen.sh"
command -v go >/dev/null 2>&1 || err "Go not found -- required to run licensegen."

cd "$REPO_ROOT"
exec go run packaging/licensing/licensegen/main.go -key "$PRIV_KEY" "$@"
