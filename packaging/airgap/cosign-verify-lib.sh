#!/usr/bin/env bash
# BAS Platform -- shared cosign verification helpers for the air-gap flow.
# Sourced by import.sh and verify.sh (shipped next to them in the bundle).
# Mirrors _check_cosign / _verify_orchestrator_artifact in
# packaging/compose/install.sh and packaging/compose/setup.sh: the orchestrator
# tarball is verified with `cosign verify-blob --key cosign.pub --bundle
# <tar>.bundle --insecure-ignore-tlog <tar>` and any failure is fatal.
#
# Caller must define err(); log()/warn() are optional (defaults provided).
# Functions return nonzero on failure and print the reason via err().

declare -F log  >/dev/null || log()  { echo "[+] $*"; }
declare -F warn >/dev/null || warn() { echo "[!] $*"; }

# Minimum cosign confirmed to verify the sigstore bundle format sign-blob now
# produces (v2.x and v3.0.x reject a valid offline signature).
_cosign_version_ok() {
  local ver="$1" major minor
  IFS='.' read -r major minor _ <<< "${ver#v}"
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
  (( major > 3 || (major == 3 && minor >= 1) ))
}

# airgap_check_cosign <cosign.pub path>
airgap_check_cosign() {
  local pub="$1"
  if ! command -v cosign &>/dev/null; then
    err "cosign is not installed -- cannot verify the orchestrator image signature, refusing to proceed."
    echo "  cosign >= v3.1.0 must be installed on this air-gapped host BEFORE importing." >&2
    echo "  Offline install: download the release binary (cosign-linux-amd64) from" >&2
    echo "    https://github.com/sigstore/cosign/releases on a connected machine," >&2
    echo "    copy it over, then: install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign" >&2
    return 1
  fi
  local ver
  ver=$(cosign version 2>/dev/null | sed -n 's/^GitVersion:[[:space:]]*\(.*\)$/\1/p' | tr -d '[:space:]')
  if [[ -z "$ver" ]] || ! _cosign_version_ok "$ver"; then
    err "cosign version ${ver:-unknown} is too old (need >= v3.1.0 to verify this bundle's signature format)."
    echo "  Install a newer release binary from https://github.com/sigstore/cosign/releases (copy it over offline)." >&2
    return 1
  fi
  if [[ ! -f "$pub" ]]; then
    err "cosign public key not found at ${pub} (corrupt or incomplete bundle) -- refusing to proceed."
    return 1
  fi
  return 0
}

# airgap_verify_orchestrator <tar> <cosign.pub path>
# Refuses a compressed (.tar.gz) orchestrator image outright: it cannot carry
# a signature this flow knows how to check.
airgap_verify_orchestrator() {
  local tar="$1" pub="$2"
  if [[ "$tar" == *.tar.gz ]]; then
    err "$(basename "$tar") is a legacy unsigned orchestrator image -- refusing. Re-pack with the current packaging/airgap/pack.sh."
    return 1
  fi
  if [[ ! -f "$tar" ]]; then
    err "Orchestrator image not found: $(basename "$tar")"
    return 1
  fi
  airgap_check_cosign "$pub" || return 1
  if [[ ! -f "${tar}.bundle" ]]; then
    err "Signature bundle not found: $(basename "$tar").bundle -- refusing to load an unsigned orchestrator image."
    return 1
  fi
  local out
  if ! out=$(cosign verify-blob --key "$pub" --bundle "${tar}.bundle" --insecure-ignore-tlog "$tar" 2>&1); then
    err "cosign verification FAILED for $(basename "$tar") -- refusing to load a tampered or unsigned orchestrator image."
    echo "$out" >&2
    return 1
  fi
  log "cosign: verified $(basename "$tar")"
  return 0
}

# ── Out-of-band public key selection ──────────────────────────────────────────
# Precedence: --cosign-pub flag, then BAS_COSIGN_PUB env, then the bundled
# cosign.pub. An external key is NEVER silently replaced by the bundled one.

_airgap_fp() { sha256sum "$1" | cut -d' ' -f1; }

# airgap_external_pub <flag-value-or-empty>
# Sets AIRGAP_EXT_PUB (absolute path, or empty). Returns 1 if a key was
# requested but is missing/unreadable.
airgap_external_pub() {
  local p="${1:-${BAS_COSIGN_PUB:-}}"
  AIRGAP_EXT_PUB=""
  [[ -z "$p" ]] && return 0
  if [[ ! -f "$p" || ! -r "$p" ]]; then
    err "External cosign public key not found or unreadable: ${p}"
    return 1
  fi
  AIRGAP_EXT_PUB="$(cd "$(dirname "$p")" && pwd)/$(basename "$p")"
}

# airgap_select_pub <bundled cosign.pub path>
# Sets AIRGAP_PUB to the key verification MUST use and prints its fingerprint.
airgap_select_pub() {
  local bundled="$1" fp
  if [[ -n "${AIRGAP_EXT_PUB:-}" ]]; then
    AIRGAP_PUB="$AIRGAP_EXT_PUB"
    fp=$(_airgap_fp "$AIRGAP_PUB")
    echo "" >&2
    echo "  ============================================================" >&2
    echo "   Verifying with EXTERNAL key, sha256: ${fp}" >&2
    echo "   (${AIRGAP_PUB}) -- compare with the published Audspect fingerprint" >&2
    echo "  ============================================================" >&2
    echo "" >&2
    if [[ -f "$bundled" ]] && ! cmp -s "$bundled" "$AIRGAP_PUB"; then
      warn "The bundle's own cosign.pub DIFFERS from the external key (sha256: $(_airgap_fp "$bundled")). The external key is used."
    fi
  else
    AIRGAP_PUB="$bundled"
    if [[ -f "$bundled" ]]; then
      log "Verifying with BUNDLED key, sha256: $(_airgap_fp "$bundled") (supply --cosign-pub or BAS_COSIGN_PUB to use an out-of-band key)"
    fi
  fi
}
