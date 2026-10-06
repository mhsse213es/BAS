#!/usr/bin/env bash
# BAS Platform -- shared cosign verification helpers for the air-gap flow.
# Sourced by import.sh, verify.sh and the ISO/Packer provisioning scripts
# (shipped next to them in the bundle).
# Mirrors _check_cosign / _verify_orchestrator_artifact in
# packaging/compose/install.sh and packaging/compose/setup.sh: every image tar
# is verified with `cosign verify-blob --key cosign.pub --bundle <tar>.bundle
# --insecure-ignore-tlog <tar>` and any failure is fatal.
#
# Caller must define err(); log()/warn() are optional (defaults provided).
# Functions return nonzero on failure and print the reason via err().

unset CDPATH
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
    err "cosign is not installed -- cannot verify the image signatures, refusing to proceed."
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
# (name kept; verifies ANY image tar's cosign signature.) Refuses a compressed
# (.tar.gz) image outright: it cannot carry a signature this flow checks.
airgap_verify_orchestrator() {
  local tar="$1" pub="$2"
  if [[ "$tar" == *.tar.gz ]]; then
    err "$(basename -- "$tar") is a legacy unsigned image -- refusing. Re-pack with the current packaging/airgap/pack.sh."
    return 1
  fi
  if [[ ! -f "$tar" ]]; then
    err "Image not found: $(basename -- "$tar")"
    return 1
  fi
  airgap_check_cosign "$pub" || return 1
  if [[ ! -f "${tar}.bundle" ]]; then
    err "Signature bundle not found: $(basename -- "$tar").bundle -- refusing to load an unsigned image."
    return 1
  fi
  local out
  if ! out=$(cosign verify-blob --key "$pub" --bundle "${tar}.bundle" --insecure-ignore-tlog "$tar" 2>&1); then
    err "cosign verification FAILED for $(basename -- "$tar") -- refusing to load a tampered or unsigned image."
    echo "$out" >&2
    return 1
  fi
  log "cosign: verified $(basename -- "$tar")"
  return 0
}

# ── Key fingerprint ───────────────────────────────────────────────────────────
# sha256 of the DER SubjectPublicKeyInfo (stable across PEM re-wrapping; openssl
# is already required by setup.sh). Falls back to the plain file sha256, labelled
# as such, if openssl cannot parse the key.
_airgap_fp() {
  local f="$1"
  if command -v openssl &>/dev/null && openssl pkey -pubin -in "$f" -noout 2>/dev/null; then
    openssl pkey -pubin -in "$f" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1
  else
    echo "$(sha256sum "$f" | cut -d' ' -f1) (file sha256; not a parsable public key)"
  fi
}

# ── Image identity: bind a verified tar to the tag + ID compose runs ──────────

# airgap_expected_tag <tar basename> <bundle version>
# The ONLY images this flow ships, and the one tag each must carry.
# Must equal packaging/images.pin (CHROME_VERSION) and docker-compose.yml.
AIRGAP_CHROME_TAG="chromedp/headless-shell:151.0.7922.109"
airgap_expected_tag() {
  case "$1" in
    "bas-orchestrator-$2.tar") echo "bas-orchestrator:$2" ;;
    postgres-16-alpine.tar)    echo "postgres:16-alpine" ;;
    headless-shell.tar)        echo "$AIRGAP_CHROME_TAG" ;;
    "bas-caldera-$2.tar")      echo "bas-caldera:$2" ;;
    *) return 1 ;;
  esac
}

airgap_tar_image_id() {
  local tar="$1" want="$2" m cfg tags idx d ids
  m=$(tar -xOf "$tar" --occurrence=1 manifest.json 2>/dev/null) || return 1
  [[ $(grep -o '"Config"' <<<"$m" | wc -l) -eq 1 ]] || return 1
  tags=$(sed -n 's/.*"RepoTags":\[\([^]]*\)\].*/\1/p' <<<"$m")
  [[ "$tags" == "\"${want}\"" ]] || return 1
  cfg=$(sed -n 's/.*"Config":"\([^"]*\)".*/\1/p' <<<"$m")
  cfg="${cfg##*/}"; cfg="${cfg%.json}"
  [[ "$cfg" =~ ^[0-9a-f]{64}$ ]] || return 1
  # Candidate 1 (classic overlay2 store): the Config digest. Candidate 2
  # (containerd store, the default on new Docker Engines): `docker image inspect`
  # reports the top-level manifest/index digest from index.json. Both come from
  # the cosign-verified tar, so neither can be chosen by an attacker. Older
  # `docker save` tars have no index.json: Config only.
  ids="sha256:${cfg}"
  idx=$(tar -xOf "$tar" --occurrence=1 index.json 2>/dev/null || true)
  if [[ -n "$idx" ]]; then
    for d in $(grep -o '"digest"[[:space:]]*:[[:space:]]*"sha256:[0-9a-f]\{64\}"' <<<"$idx" | grep -o 'sha256:[0-9a-f]*'); do
      ids="${ids} ${d}"
    done
  fi
  echo "$ids"
}

# <tag>'s ID in the local daemon must equal one of the space-separated candidate
# IDs recorded from the verified tar (see above); anything else is a mismatch.
airgap_docker_tag_is() {
  local got want
  got=$(docker image inspect -f '{{.Id}}' "$1" 2>/dev/null) || return 1
  for want in $2; do
    [[ "$got" == "$want" ]] && return 0
  done
  return 1
}

# airgap_verify_images <images dir> <cosign.pub> <version>
# Nothing touches docker: every file in images/ must be a known <name>.tar with
# a valid cosign .bundle and a manifest carrying exactly its expected tag;
# anything else (unsigned/unlisted file, legacy .tar.gz) is fatal, and all four runtime tars
# (orchestrator, postgres, caldera, chrome) must be present. Fills AIRGAP_TARS/TAGS/IDS
# (supporting images) and AIRGAP_ORCH/ORCH_TAG/ORCH_ID.
airgap_verify_images() {
  local dir="$1" pub="$2" ver="$3" f base tag id
  AIRGAP_TARS=(); AIRGAP_TAGS=(); AIRGAP_IDS=()
  AIRGAP_ORCH=""; AIRGAP_ORCH_TAG=""; AIRGAP_ORCH_ID=""
  for f in "$dir"/*; do
    [[ -e "$f" ]] || continue
    base="${f##*/}"
    case "$base" in
      *.tar.bundle) continue ;;
      *.tar) ;;
      *) err "Unexpected file in images/: ${base} -- refusing (only signed .tar images are allowed)."; return 1 ;;
    esac
    tag=$(airgap_expected_tag "$base" "$ver") || { err "Unlisted image tar in images/: ${base} -- refusing."; return 1; }
    airgap_verify_orchestrator "$f" "$pub" || return 1
    id=$(airgap_tar_image_id "$f" "$tag") || { err "${base}: manifest.json does not carry exactly the tag ${tag} -- refusing."; return 1; }
    if [[ "$base" == bas-orchestrator-* ]]; then
      AIRGAP_ORCH="$f"; AIRGAP_ORCH_TAG="$tag"; AIRGAP_ORCH_ID="$id"
    else
      AIRGAP_TARS+=("$f"); AIRGAP_TAGS+=("$tag"); AIRGAP_IDS+=("$id")
    fi
  done
  [[ -n "$AIRGAP_ORCH" ]] || { err "Orchestrator image bas-orchestrator-${ver}.tar missing from images/."; return 1; }
  # ALL runtime images are required: compose starts postgres, caldera, chrome and
  # the orchestrator with no profile, so a missing one aborts `docker compose up`.
  local req
  for req in postgres-16-alpine.tar headless-shell.tar "bas-caldera-${ver}.tar"; do
    [[ -f "$dir/$req" ]] || { err "Required runtime image ${req} missing from images/ -- refusing."; return 1; }
  done
  return 0
}

# airgap_verify_and_load_images <images dir> <cosign.pub> <version>
# Phase 1 = airgap_verify_images (all verified before any load). Phase 2: load
# postgres first and the orchestrator last; after every load the tag must
# resolve to exactly the image ID recorded in phase 1.
airgap_verify_and_load_images() {
  local i
  airgap_verify_images "$@" || return 1
  for i in "${!AIRGAP_TARS[@]}"; do
    log "  Loading ${AIRGAP_TAGS[$i]}..."
    docker load < "${AIRGAP_TARS[$i]}" || { err "docker load failed for ${AIRGAP_TAGS[$i]}"; return 1; }
    airgap_docker_tag_is "${AIRGAP_TAGS[$i]}" "${AIRGAP_IDS[$i]}" || { err "${AIRGAP_TAGS[$i]} is not the verified image after load -- aborting."; return 1; }
  done
  log "  Loading ${AIRGAP_ORCH_TAG}..."
  docker load < "$AIRGAP_ORCH" || { err "docker load failed for ${AIRGAP_ORCH_TAG}"; return 1; }
  airgap_docker_tag_is "$AIRGAP_ORCH_TAG" "$AIRGAP_ORCH_ID" || { err "${AIRGAP_ORCH_TAG} is not the verified image after load -- aborting."; return 1; }
  return 0
}

# ── Out-of-band public key selection ──────────────────────────────────────────
# Precedence: --cosign-pub flag, then BAS_COSIGN_PUB env, then the bundled
# cosign.pub. An external key is NEVER silently replaced by the bundled one.

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
  AIRGAP_EXT_PUB="$(cd -- "$(dirname -- "$p")" && pwd)/$(basename -- "$p")"
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
