#!/usr/bin/env bash
# BAS Platform — Packer Build Wrapper
#
# Orchestrates the full VM image build:
#   1. Validates prerequisites (packer, qemu-kvm, airgap bundle)
#   2. Generates a random build-time SSH password and injects it into user-data
#   3. Runs packer to produce the QCOW2 image
#   4. Calls convert.sh to produce VHDX and OVA
#   5. Optionally signs all output files
#
# Usage:
#   bash packaging/packer/build-packer.sh [version]
#
# Example:
#   bash packaging/packer/build-packer.sh 1.2.0
#
# Run from the repository root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
PACKER_DIR="${REPO_ROOT}/packaging/packer"

VERSION="${1:-$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "dev")}"
readonly VERSION

DIST_DIR="${REPO_ROOT}/dist"
AIRGAP_BUNDLE="${DIST_DIR}/bas-airgap-${VERSION}.tar.gz"

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── 1. Prerequisite checks ─────────────────────────────────────────────────────
log "Checking prerequisites..."

if ! command -v packer &>/dev/null; then
  err "packer not found."
  echo "  Install: https://developer.hashicorp.com/packer/install"
  exit 1
fi
log "  packer $(packer version | head -1)"

if ! command -v qemu-system-x86_64 &>/dev/null; then
  err "qemu-system-x86_64 not found."
  echo "  Install: apt-get install -y qemu-system-x86"
  exit 1
fi

if ! grep -qs vmx /proc/cpuinfo && ! grep -qs svm /proc/cpuinfo; then
  warn "KVM hardware acceleration not detected — build will be slow."
fi

if [[ ! -f "$AIRGAP_BUNDLE" ]]; then
  err "Air-gap bundle not found: ${AIRGAP_BUNDLE}"
  echo "  Build it first:"
  echo "    bash packaging/build.sh ${VERSION}"
  echo "    bash packaging/airgap/pack.sh ${VERSION}"
  exit 1
fi
log "  Air-gap bundle: $(du -sh "${AIRGAP_BUNDLE}" | cut -f1)  ${AIRGAP_BUNDLE}"

# ── 2. Generate build-time SSH password ───────────────────────────────────────
log "Generating temporary build SSH password..."
PACKER_SSH_PASS=$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9' | head -c 20)

# Hash for cloud-init user-data
if command -v openssl &>/dev/null; then
  SALT=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)
  PASS_HASH=$(openssl passwd -6 -salt "$SALT" "$PACKER_SSH_PASS")
else
  err "openssl required to hash the build password."
  exit 1
fi

# ── 3. Generate http/user-data from template ──────────────────────────────────
log "Generating http/user-data..."
sed "s|%%PACKER_SSH_PASS_HASH%%|${PASS_HASH}|g" \
  "${PACKER_DIR}/http/user-data.tmpl" \
  > "${PACKER_DIR}/http/user-data"

# Ensure user-data is cleaned up even on failure
trap 'rm -f "${PACKER_DIR}/http/user-data"' EXIT

# ── 4. Initialize Packer plugins ──────────────────────────────────────────────
log "Initializing Packer plugins..."
(cd "$PACKER_DIR" && packer init ubuntu.pkr.hcl)

# ── 5. Run Packer build ───────────────────────────────────────────────────────
mkdir -p "${DIST_DIR}/packer-output"
log "Starting Packer build for BAS Platform ${VERSION}..."
echo "  This will take 20–60 minutes depending on hardware and network speed."
echo ""

(
  cd "$PACKER_DIR"
  packer build \
    -var-file="variables.pkrvars.hcl" \
    -var "bas_version=${VERSION}" \
    -var "airgap_bundle=${AIRGAP_BUNDLE}" \
    -var "packer_ssh_pass=${PACKER_SSH_PASS}" \
    -var "output_dir=${DIST_DIR}/packer-output" \
    ubuntu.pkr.hcl
)

log "Packer build complete."

# ── 6. Convert to VHDX + OVA ─────────────────────────────────────────────────
log "Converting to VHDX and OVA..."
bash "${PACKER_DIR}/convert.sh" "${VERSION}"

# ── 7. Sign output files ──────────────────────────────────────────────────────
SIGN_SCRIPT="${REPO_ROOT}/packaging/signing/sign.sh"
SIGNING_KEY_EMAIL="releases@audspect.com"
if command -v gpg &>/dev/null && gpg --list-secret-keys "${SIGNING_KEY_EMAIL}" &>/dev/null 2>&1; then
  log "Signing VM images..."
  for f in \
    "${DIST_DIR}/bas-platform-${VERSION}.qcow2" \
    "${DIST_DIR}/bas-platform-${VERSION}.vhdx" \
    "${DIST_DIR}/bas-platform-${VERSION}.ova"; do
    [[ -f "$f" ]] && bash "${SIGN_SCRIPT}" "$f"
  done
else
  warn "GPG signing key not found — VM images are unsigned."
fi

log "Build complete."
echo ""
echo "  Outputs in ${DIST_DIR}/:"
echo ""
for ext in qcow2 vhdx ova; do
  f="${DIST_DIR}/bas-platform-${VERSION}.${ext}"
  [[ -f "$f" ]] && printf "  %-6s  %s  (%s)\n" "${ext}" "$(basename "$f")" "$(du -sh "$f" | cut -f1)"
done
echo ""
echo "  VM appliance instructions:"
echo "    1. Import the .ova (VMware) or .vhdx (Hyper-V) or .qcow2 (KVM)"
echo "    2. Allocate at least 2 vCPUs and 4 GB RAM"
echo "    3. Power on — the first-boot wizard will launch on the console"
