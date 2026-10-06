#!/usr/bin/env bash
# BAS Platform — Interactive Setup Wizard
# Supports Ubuntu 20.04 / 22.04 / 24.04 and Rocky Linux 9
set -euo pipefail

# ── Audspect public key — DO NOT MODIFY ───────────────────────────────────────
readonly _LIC_PUBKEY='-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1Tkfvrt9afADqXrViDca
CMqjC9YC7FPQ/cEG5Uyw/mHa17/oeVAselWrfyw3sd8c/aS8dCUzE+DhMGRmnPm7
Kf9eCT4pGxVbkKq6h1/ospdsFUgWmrfHECmPgVLK6fppLPnpOEoC8g6ZDm0N5+Wi
v7r1Ke7ZAfKIxjkOHY2J4/sbexV5yNshO7y54nuhV2HO5aO8bIcbleqEejYB5p+o
waz/nlY+CQEQvkhvAb3ycBmcdUn1JJx3/uFNRANzWMjXvUm6svc89PqmeztFQyh1
D3JN8H8DP3tpu6sYJB546Bp/ibha3q2daQdaZBzPMG3stqx8vuRBDk6oP3Git1Oc
sLwFvk21TPctYgG2ZIIe79X6OZURBM3pmh2MMv3EGGosZQjwjKK2XJHBXTQRKbOu
DALVvcNDHOHJuJ79uN4ZQgRKcTh9+rbc+U8ItiqxMPaz6PgnWXp232MknfNd0o5c
+FgMfeAWEUyZwu2iO172ghWYkM5JzFCijJz9u5yTxL/25qferhhD9XcerdPJT1uS
viWhPS0KAZel/o+9jJg2H4P7H1NrZc4diIMhPMhmm6jxC9S3TyCQjf2rvl8oNeD6
ZKTftlLSAELFxhi81iDw7789G53Ur0+PQTcf9wCVFAPFk7DjCykHNcMf3c05vTdn
/CNAusfhqKmVI/VkLgROhr0CAwEAAQ==
-----END PUBLIC KEY-----'

# ── Constants ──────────────────────────────────────────────────────────────────
readonly TITLE="BAS Platform Setup"
readonly DEFAULT_INSTALL_DIR="/opt/bas-platform"
readonly DEFAULT_PORT="9000"
readonly MIN_RAM_MB=3800
readonly MIN_DISK_MB=5120
readonly SERVICE_NAME="bas-compose"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Version is read from the bundle's VERSION file (written by the packager) so the
# .env image tag ALWAYS matches the images shipped in THIS bundle — never a
# hardcoded guess that drifts from the -Version used at build time. Strip a
# possible UTF-8 BOM / CR / surrounding whitespace. Fallback only applies when
# setup.sh is run outside a bundle (no VERSION file).
_bas_version="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || true)"
_bas_version="${_bas_version#$'\xEF\xBB\xBF'}"
_bas_version="${_bas_version//$'\r'/}"
_bas_version="${_bas_version//[[:space:]]/}"
readonly BAS_VERSION="${_bas_version:-latest}"

# Set by --offline flag; skips docker pull (images already loaded)
OFFLINE=false

# Set during prereq checks — installer auto-installs these if missing
NEED_DOCKER=false
NEED_COMPOSE=false

# Set by --config <file>; skips wizard and reads all values from file
CONFIG_FILE=""

# Set internally when Python wizard spawns setup.sh as subprocess
# Disables all whiptail; outputs plain log lines captured by Python SSE streamer
NO_WIZARD=false

# ── Colours (only when stdout is a terminal) ───────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# Ensure whiptail has a valid terminal type (sudo strips TERM in some envs)
export TERM="${TERM:-xterm}"

# ── Config file loader ────────────────────────────────────────────────────────
# Reads key=value pairs from setup.conf without sourcing (no arbitrary code exec).
# Sets: INSTALL_DIR, DASHBOARD_PORT, DB_PASSWORD, ADMIN_EMAIL, ADMIN_PASSWORD, LIC_PATH
# Generates: JWT_SECRET, AGENT_SECRET, CALDERA_API_KEY, CALDERA_API_KEY_BLUE
load_config() {
  local cfg="$1"
  [[ -f "$cfg" ]] || { err "Config file not found: $cfg"; exit 1; }

  local key val
  while IFS='=' read -r key val; do
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${key// }" ]] && continue
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    val="${val#\'}" ; val="${val%\'}"
    val="${val#\"}" ; val="${val%\"}"
    case "$key" in
      INSTALL_DIR)    INSTALL_DIR="$val"    ;;
      DASHBOARD_PORT) DASHBOARD_PORT="$val" ;;
      DB_PASSWORD)    DB_PASSWORD="$val"    ;;
      ADMIN_EMAIL)    ADMIN_EMAIL="$val"    ;;
      ADMIN_PASSWORD) ADMIN_PASSWORD="$val" ;;
      LIC_PATH)       LIC_PATH="$val"       ;;
    esac
  done < "$cfg"

  # Expand leading ~ to $HOME (tilde is not expanded when read from a file)
  LIC_PATH="${LIC_PATH/#\~/$HOME}"

  [[ -z "${INSTALL_DIR:-}"    ]] && INSTALL_DIR="$DEFAULT_INSTALL_DIR"
  [[ -z "${DASHBOARD_PORT:-}" ]] && DASHBOARD_PORT="$DEFAULT_PORT"

  local missing=false
  [[ -z "${LIC_PATH:-}"       ]] && { err "setup.conf: LIC_PATH is required.";       missing=true; }
  [[ -z "${DB_PASSWORD:-}"    ]] && { err "setup.conf: DB_PASSWORD is required.";    missing=true; }
  [[ -z "${ADMIN_EMAIL:-}"    ]] && { err "setup.conf: ADMIN_EMAIL is required.";    missing=true; }
  [[ -z "${ADMIN_PASSWORD:-}" ]] && { err "setup.conf: ADMIN_PASSWORD is required."; missing=true; }
  $missing && exit 1

  [[ ${#DB_PASSWORD}    -lt 8  ]] && { err "DB_PASSWORD must be at least 8 characters.";     exit 1; }
  [[ ${#ADMIN_PASSWORD} -lt 10 ]] && { err "ADMIN_PASSWORD must be at least 10 characters."; exit 1; }

  JWT_SECRET=$(openssl rand -hex 32)
  AGENT_SECRET=$(openssl rand -hex 24)
  CALDERA_API_KEY=$(openssl rand -hex 20)
  CALDERA_API_KEY_BLUE=$(openssl rand -hex 20)

  log "Config loaded: install=${INSTALL_DIR} port=${DASHBOARD_PORT}"
}

# Capture whiptail output via temp file — portable under sudo (fd-swap breaks in some envs)
_wt() {
  local _retvar="$1"; shift
  local _tmp _rc
  _tmp=$(mktemp)
  _rc=0
  whiptail "$@" 2>"$_tmp" || _rc=$?   # || prevents set -e from firing on Cancel/ESC
  printf -v "$_retvar" '%s' "$(cat "$_tmp")"
  rm -f "$_tmp"
  return "$_rc"
}

# ── Root check ─────────────────────────────────────────────────────────────────
require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "This installer must be run as root."
    echo "  Run: sudo bash $0"
    exit 1
  fi
}

# ── whiptail availability ──────────────────────────────────────────────────────
ensure_whiptail() {
  if command -v whiptail &>/dev/null; then return; fi
  warn "whiptail not found — installing..."
  if command -v apt-get &>/dev/null; then
    apt-get install -y -qq whiptail
  elif command -v dnf &>/dev/null; then
    dnf install -y -q newt
  else
    err "Cannot install whiptail. Install it manually and re-run."
    exit 1
  fi
}

# ── Prerequisite checks ────────────────────────────────────────────────────────
check_os() {
  local os_id os_version
  os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"' 2>/dev/null || echo "unknown")
  os_version=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release | tr -d '"' 2>/dev/null || echo "0")

  case "$os_id" in
    ubuntu)
      if [[ "${os_version%%.*}" -lt 20 ]]; then
        echo "FAIL:OS — Ubuntu ${os_version} not supported (need 20.04+)"
        return
      fi
      echo "PASS:OS — Ubuntu ${os_version} LTS"
      ;;
    rocky|rhel|centos)
      if [[ "${os_version%%.*}" -lt 9 ]]; then
        echo "FAIL:OS — Rocky/RHEL ${os_version} not supported (need 9+)"
        return
      fi
      echo "PASS:OS — Rocky Linux / RHEL ${os_version}"
      ;;
    *)
      echo "WARN:OS — ${os_id} ${os_version} (untested — may work)"
      ;;
  esac
}

check_ram() {
  local ram_mb
  ram_mb=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
  if [[ $ram_mb -lt $MIN_RAM_MB ]]; then
    echo "FAIL:RAM — ${ram_mb}MB available (need ${MIN_RAM_MB}MB)"
  else
    echo "PASS:RAM — ${ram_mb}MB available"
  fi
}

check_disk() {
  local install_dir="${1:-$DEFAULT_INSTALL_DIR}"
  local parent
  parent=$(dirname "$install_dir")
  [[ -d "$install_dir" ]] && parent="$install_dir"
  local free_mb
  free_mb=$(df -m "$parent" | awk 'NR==2 {print $4}')
  if [[ $free_mb -lt $MIN_DISK_MB ]]; then
    echo "FAIL:Disk — ${free_mb}MB free at ${parent} (need ${MIN_DISK_MB}MB)"
  else
    echo "PASS:Disk — ${free_mb}MB free at ${parent}"
  fi
}

check_docker() {
  if ! command -v docker &>/dev/null; then
    NEED_DOCKER=true
    echo "INST:Docker — not installed (will be auto-installed)"
    return
  fi
  if ! docker info &>/dev/null; then
    echo "FAIL:Docker — daemon not running (run: systemctl start docker)"
    return
  fi
  echo "PASS:Docker — $(docker --version | grep -oP 'Docker version \K[^,]+')"
}

check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    echo "PASS:Compose — $(docker compose version --short 2>/dev/null || echo 'v2')"
  elif command -v docker-compose &>/dev/null; then
    echo "WARN:Compose — docker-compose v1 found (v2 plugin recommended)"
  else
    NEED_COMPOSE=true
    echo "INST:Compose — not installed (will be auto-installed with Docker)"
  fi
}

# The orchestrator release artifact ships cosign-signed (packaging/build.sh,
# packaging/windows-build.ps1, via sign-blob/verify-blob against the
# docker-save tarball -- cosign's image subcommands all need a registry,
# which doesn't exist here); this installer must be able to verify that
# signature before the tarball is ever loaded. No auto-install path like
# Docker's -- cosign is specific enough that silently installing it on an
# operator's box is not appropriate here.
# Minimum confirmed-working cosign version for the sigstore bundle format
# sign-blob/verify-blob now always produce. Real cross-version testing
# during review found v2.2.4/v2.4.3/v2.5.3/v2.6.1/v3.0.2 all reject a
# genuinely valid, offline signature ("trusted root is required when
# using new bundle format" or a decode error); v3.1.3 verifies correctly.
# Without this check, an operator with an older cosign sees "refusing to
# install a tampered or unsigned orchestrator artifact" for a perfectly
# valid artifact -- a version problem misreported as a tamper finding.
_cosign_version_ok() {
  local ver="$1" major minor
  IFS='.' read -r major minor _ <<< "${ver#v}"
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
  (( major > 3 || (major == 3 && minor >= 1) ))
}

check_cosign() {
  if ! command -v cosign &>/dev/null; then
    echo "FAIL:Cosign — not installed (required to verify the orchestrator artifact before install; see https://docs.sigstore.dev/cosign/system_config/installation/)"
    return
  fi
  local ver
  ver=$(cosign version 2>/dev/null | sed -n 's/^GitVersion:[[:space:]]*\(.*\)$/\1/p' | tr -d '[:space:]')
  if [[ -z "$ver" ]] || ! _cosign_version_ok "$ver"; then
    echo "FAIL:Cosign — version ${ver:-unknown} is too old (need >= v3.1.0 to verify the sigstore bundle format this bundle's signature uses)"
    return
  fi
  if [[ ! -f "${BAS_COSIGN_PUB:-${SCRIPT_DIR}/cosign.pub}" ]]; then
    echo "FAIL:Cosign — public key not found in bundle at ${SCRIPT_DIR}/cosign.pub (corrupt or incomplete release bundle)"
    return
  fi
  echo "PASS:Cosign — ${ver}"
}


# Key fingerprint: sha256 of the DER SubjectPublicKeyInfo (stable across PEM
# re-wrapping; openssl is already required by this installer). Falls back to the
# plain file sha256, labelled as such, if openssl cannot parse the key.
_key_fp() {
  local f="$1"
  if command -v openssl &>/dev/null && openssl pkey -pubin -in "$f" -noout 2>/dev/null; then
    openssl pkey -pubin -in "$f" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1
  else
    echo "$(sha256sum "$f" | cut -d' ' -f1) (file sha256; not a parsable public key)"
  fi
}

_tar_image_id() {
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
_docker_tag_is() {
  local got want
  got=$(docker image inspect -f '{{.Id}}' "$1" 2>/dev/null) || return 1
  for want in $2; do
    [[ "$got" == "$want" ]] && return 0
  done
  return 1
}

# Verifies the orchestrator tarball against the bundle's cosign.pub BEFORE
# any docker load call touches it -- the tarball's bytes never reach the
# Docker daemon at all if verification fails. Caller must treat a nonzero
# return as fatal (abort the whole install), not skip-and-continue.
_verify_orchestrator_artifact() {
  local tar="$1"
  local pub="${BAS_COSIGN_PUB:-${SCRIPT_DIR}/cosign.pub}" kind=BUNDLED ctx
  [[ -n "${BAS_COSIGN_PUB:-}" ]] && kind=EXTERNAL
  if [[ ! -f "$pub" ]]; then
    err "cosign.pub not found (${kind} key ${pub}) -- cannot verify $(basename "$tar"), refusing to proceed"
    return 1
  fi
  if ! command -v cosign &>/dev/null; then
    err "cosign is not installed -- cannot verify $(basename "$tar"), refusing to proceed"
    return 1
  fi
  if [[ ! -f "${tar}.bundle" ]]; then
    err "Signature bundle not found: $(basename "$tar").bundle -- refusing to install an unsigned orchestrator artifact"
    return 1
  fi
  ctx="${kind} key ${pub}, fingerprint $(_key_fp "$pub")"
  log "cosign: verifying $(basename "$tar") with ${ctx}"
  local verify_output
  if ! verify_output=$(cosign verify-blob --key "$pub" --bundle "${tar}.bundle" --insecure-ignore-tlog "$tar" 2>&1); then
    err "cosign verification FAILED for $(basename "$tar") using ${ctx} -- refusing to install a tampered or unsigned orchestrator artifact"
    echo "$verify_output" >&2
    return 1
  fi
  log "cosign: verified $(basename "$tar")"
  return 0
}

check_port() {
  local port="$1"
  if ss -tlnH "sport = :${port}" 2>/dev/null | grep -q ":${port}"; then
    echo "FAIL:Port ${port} — already in use"
  else
    echo "PASS:Port ${port} — available"
  fi
}

# ── Binary manifest verification ──────────────────────────────────────────────
# GPG key selection (precedence): --gpg-pub flag, BAS_GPG_PUB env, then the
# bundle's agents/pubkey.asc. An external key is used EXCLUSIVELY (the bundled
# one is never consulted) and a missing/unreadable path is fatal. A bundled key
# only proves integrity, not origin.
GPG_PUB_FLAG=""

# _gpg_verify_single_key <sig> <file> <pubkey> <kind>
# Same hardening as packaging/signing/verify-sig.sh (duplicated here because
# verify-sig.sh is not guaranteed to sit next to setup.sh in a release bundle):
# throwaway keyring, exactly ONE primary key in the key file, and the signature's
# VALIDSIG primary fingerprint must equal that key's fingerprint, which is printed.
_gpg_verify_single_key() {
  local sig="$1" file="$2" pub="$3" kind="$4" home listing n fpr status rc=0 l primary ok
  home=$(mktemp -d); chmod 700 "$home"
  # shellcheck disable=SC2064
  trap "rm -rf '$home'" RETURN
  local G=(gpg --homedir "$home" --batch --quiet --no-autostart)
  "${G[@]}" --import "$pub" 2>/dev/null || { err "Could not import the GPG public key from ${pub}."; return 1; }
  listing=$("${G[@]}" --with-colons --list-keys 2>/dev/null)
  n=$(grep -c '^pub:' <<<"$listing" || true)
  if [[ "$n" -ne 1 ]]; then
    err "GPG key file ${pub} contains ${n} primary keys; exactly one is required. Refusing."
    return 1
  fi
  fpr=$(awk -F: '/^fpr/{print $10; exit}' <<<"$listing")
  [[ -n "$fpr" ]] || { err "Could not read the GPG key fingerprint from ${pub}."; return 1; }
  echo "" >&2
  echo "  ============================================================" >&2
  echo "   Verifying with ${kind} GPG key, fingerprint: ${fpr}" >&2
  echo "   (compare with the fingerprint Audspect publishes)" >&2
  echo "  ============================================================" >&2
  if [[ "$kind" == BUNDLED ]]; then
    warn "A bundled key proves integrity, not origin, unless its fingerprint matches the published one (or use --gpg-pub / BAS_GPG_PUB)."
  fi
  status=$("${G[@]}" --status-fd 1 --verify "$sig" "$file" 2>/dev/null) || rc=$?
  l=$(grep '^\[GNUPG:\] VALIDSIG ' <<<"$status" || true)
  ok=false
  if [[ $rc -eq 0 && -n "$l" ]]; then
    ok=true
    while IFS= read -r line; do
      primary=$(awk '{print toupper($12)}' <<<"$line")
      [[ "$primary" == "$(tr '[:lower:]' '[:upper:]' <<<"$fpr")" ]] || ok=false
    done <<<"$l"
  fi
  $ok
}

# Silent only when the bundle has no BINARIES.sha256 at all (unsigned dev/test
# bundle) and no external key was requested. A manifest with no .asc stays a
# warning (deliberate, pre-existing) unless an external key was requested. A
# present .asc that cannot be verified -- INCLUDING gpg not being installed -- is
# fatal. After the signature verifies, every binary is checked against the
# manifest and any mismatch/missing file is fatal.
verify_bundle_signatures() {
  local agents_dir="${SCRIPT_DIR}/agents"
  local manifest="${agents_dir}/BINARIES.sha256"
  local manifest_sig="${agents_dir}/BINARIES.sha256.asc"
  local pubkey="${agents_dir}/pubkey.asc" kind=BUNDLED
  local ext="${GPG_PUB_FLAG:-${BAS_GPG_PUB:-}}"

  if [[ -n "$ext" ]]; then
    if [[ ! -f "$ext" || ! -r "$ext" ]]; then
      err "External GPG public key not found or unreadable: ${ext}"
      exit 1
    fi
    pubkey="$ext"; kind=EXTERNAL
  fi

  if [[ ! -f "$manifest" ]]; then
    [[ -z "$ext" ]] && return 0
    err "An external GPG key was supplied but ${manifest} does not exist -- cannot verify the agent binaries."
    exit 1
  fi
  if [[ ! -f "$manifest_sig" ]]; then
    if [[ -n "$ext" ]]; then
      err "An external GPG key was supplied but ${manifest_sig} does not exist -- cannot verify the agent binaries."
      exit 1
    fi
    warn "Binary manifest present but unsigned — skipping verification."
    return 0
  fi
  [[ -f "$pubkey" ]] || { err "pubkey.asc missing alongside BINARIES.sha256 — cannot verify."; exit 1; }

  if ! command -v gpg &>/dev/null; then
    err "gpg is not installed, but ${manifest_sig} is present -- refusing to continue without verifying the agent binaries. Install gnupg (apt-get install -y gnupg)."
    exit 1
  fi

  if ! _gpg_verify_single_key "$manifest_sig" "$manifest" "$pubkey" "$kind"; then
    err "SECURITY: Binary manifest signature verification FAILED."
    echo ""
    echo "  The agent binaries in this bundle may have been tampered with."
    echo "  Do NOT continue installation."
    echo "  Contact Audspect support if you received this bundle from an official source."
    exit 1
  fi
  log "Binary manifest signature verified (${kind} GPG key)."

  # The signed manifest is only meaningful if the binaries still match it.
  if [[ ! -s "$manifest" ]]; then
    err "Binary manifest ${manifest} is empty -- nothing to verify against. Refusing."
    exit 1
  fi
  if ! (cd "$agents_dir" && sha256sum --check --strict --quiet BINARIES.sha256 >/dev/null 2>&1); then
    err "SECURITY: an agent binary does not match the signed BINARIES.sha256 (modified or missing). Do NOT continue installation."
    exit 1
  fi
  log "Agent binaries match the signed manifest."
}

# ── Docker CE installation (Ubuntu/Debian) ─────────────────────────────────────
install_docker() {
  log "Installing Docker CE..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  log "Docker CE installed: $(docker --version)"
}

# ── License validation ─────────────────────────────────────────────────────────
# Returns "OK:customer|expires" or "FAIL:reason". Never throws.
_check_license() {
  local lic="$1"

  [[ -f "$lic" ]] || { echo "FAIL:File not found: ${lic}"; return 0; }

  command -v python3 &>/dev/null || { echo "FAIL:python3 required (apt install python3)"; return 0; }
  command -v openssl &>/dev/null || { echo "FAIL:openssl required (apt install openssl)"; return 0; }

  # Parse all required fields in one python call
  local parsed
  parsed=$(python3 - <<PYEOF 2>/dev/null
import json, sys
try:
    d = json.load(open('${lic}'))
    for f in ('customer','customer_id','issued_at','expires_at','features','signature'):
        if f not in d:
            print('FAIL:Missing field: ' + f)
            sys.exit()
    print('|'.join([
        d['customer'], d['customer_id'], d['issued_at'],
        d['expires_at'], ','.join(d['features']), d['signature']
    ]))
except Exception as e:
    print('FAIL:' + str(e))
PYEOF
)

  [[ "$parsed" == FAIL:* ]] && { echo "$parsed"; return 0; }
  [[ -z "$parsed" ]]        && { echo "FAIL:Could not parse license file"; return 0; }

  local customer customer_id issued_at expires_at features signature
  IFS='|' read -r customer customer_id issued_at expires_at features signature <<< "$parsed"

  # Canonical payload — must match licensegen/main.go exactly
  local payload="${customer_id}|${issued_at}|${expires_at}|${features}"

  # Verify RSA-SHA256 signature with the embedded Audspect public key
  local tmpkey tmpsig tmpdata
  tmpkey=$(mktemp); tmpsig=$(mktemp); tmpdata=$(mktemp)

  printf '%s' "$_LIC_PUBKEY" > "$tmpkey"
  printf '%s' "$signature"   | base64 -d > "$tmpsig" 2>/dev/null || {
    rm -f "$tmpkey" "$tmpsig" "$tmpdata"
    echo "FAIL:Cannot decode signature — file is corrupt or not an Audspect license"
    return 0
  }
  printf '%s' "$payload" > "$tmpdata"

  local sig_ok=false
  openssl dgst -sha256 -verify "$tmpkey" -signature "$tmpsig" "$tmpdata" &>/dev/null \
    && sig_ok=true
  rm -f "$tmpkey" "$tmpsig" "$tmpdata"

  $sig_ok || {
    echo "FAIL:Signature invalid — license was not issued by Audspect or has been tampered"
    return 0
  }

  # Check expiry (24-hour grace matches the orchestrator)
  local today_epoch expiry_epoch
  today_epoch=$(date -u +%s)
  expiry_epoch=$(date -d "${expires_at} + 1 day" -u +%s 2>/dev/null) || {
    echo "FAIL:Cannot parse expiry date '${expires_at}'"
    return 0
  }

  [[ $today_epoch -gt $expiry_epoch ]] && {
    echo "FAIL:License expired on ${expires_at} — contact support@audspect.com to renew"
    return 0
  }

  echo "OK:${customer}|${expires_at}"
}

# ── Wizard pages ───────────────────────────────────────────────────────────────
page_welcome() {
  whiptail --title "$TITLE" --msgbox \
"Welcome to the BAS Platform installer.

This wizard will guide you through installing the
Breach and Attack Simulation platform on this server.

What will be installed:
  • BAS Orchestrator (Go service)
  • PostgreSQL 16 database
  • Systemd service (auto-start on boot)

Press OK to begin." 18 64
}

page_prereqs() {
  local results=()
  local has_fail=false

  # Run checks
  while IFS= read -r line; do results+=("$line"); done < <(
    check_os
    check_ram
    check_disk "$DEFAULT_INSTALL_DIR"
    check_docker
    check_compose
    check_cosign
    check_port "9000"
    check_port "5432"
  )

  # Build display text
  local display=""
  for r in "${results[@]}"; do
    local status="${r%%:*}"
    local message="${r#*:}"
    case "$status" in
      PASS) display+="  ✓  ${message}\n" ;;
      WARN) display+="  ⚠  ${message}\n" ;;
      INST) display+="  ↓  ${message}\n" ;;
      FAIL) display+="  ✗  ${message}\n"; has_fail=true ;;
    esac
  done

  if $has_fail; then
    whiptail --title "$TITLE — Prerequisites" --msgbox \
"Prerequisite check — ISSUES FOUND:

${display}
Please resolve the items marked ✗ before continuing.
Re-run this installer after fixing them." 22 70
    exit 1
  else
    local note=""
    ($NEED_DOCKER || $NEED_COMPOSE) && \
      note="\n  Items marked ↓ will be installed automatically.\n"
    whiptail --title "$TITLE — Prerequisites" --msgbox \
"Prerequisite check — READY TO INSTALL:

${display}${note}
Press OK to continue." 22 70
  fi
}


# ── Installation ───────────────────────────────────────────────────────────────
# _step PCT "message" — outputs whiptail gauge format or plain log depending on mode
_step() {
  local pct="$1" msg="$2"
  if $NO_WIZARD; then
    log "$msg"
  else
    echo "$pct"
    echo "# $msg"
  fi
}

do_install() {
  if $NO_WIZARD; then
    _do_install_steps
  else
    (
      _do_install_steps
    ) | whiptail --title "$TITLE — Installing" \
                 --gauge "Installing BAS Platform, please wait..." 10 70 0
  fi
}

# Image tag each shipped tar must carry (name is pinned to the bundle version).
# Every bundle type (release ZIP, build.sh bundle, air-gap bundle) ships these
# signed; anything else in images/ is refused.
_expected_image_tag() {
  case "$1" in
    "bas-orchestrator-${BAS_VERSION}.tar") echo "bas-orchestrator:${BAS_VERSION}" ;;
    postgres-16-alpine.tar)                echo "postgres:16-alpine" ;;
    headless-shell.tar)                    echo "chromedp/headless-shell:151.0.7922.109" ;;
    "bas-caldera-${BAS_VERSION}.tar")      echo "bas-caldera:${BAS_VERSION}" ;;
    *) return 1 ;;
  esac
}

# Verify EVERYTHING in images/ before anything is loaded or written. Signed
# images are REQUIRED (no opt-out): every tar must be a known <name>.tar with a
# valid cosign .bundle, and its manifest.json must carry exactly the expected tag.
# Fills IMG_TARS/IMG_TAGS/IMG_IDS (non-orchestrator, load order) and
# ORCH_IMG/ORCH_ID. A tar with no signature, an unlisted file or a legacy .tar.gz
# is fatal.
_verify_all_images() {
  IMG_TARS=(); IMG_TAGS=(); IMG_IDS=(); ORCH_IMG=""; ORCH_ID=""
  local img base tag id
  for img in "${SCRIPT_DIR}"/images/*; do
    [[ -f "$img" ]] || continue
    base="$(basename "$img")"
    case "$base" in
      *.bundle) continue ;;
      *.tar) ;;
      *) err "Unexpected file in images/: ${base} -- refusing (only signed .tar images are allowed)."; exit 1 ;;
    esac
    tag=$(_expected_image_tag "$base") || { err "Unlisted image tar in images/: ${base} -- refusing."; exit 1; }
    _verify_orchestrator_artifact "$img" || { err "Image ${base} failed verification -- installation aborted."; exit 1; }
    id=$(_tar_image_id "$img" "$tag") || { err "${base}: manifest.json does not carry exactly the tag ${tag} -- refusing (the verified image must be the one compose runs)."; exit 1; }
    if [[ "$base" == bas-orchestrator-* ]]; then
      ORCH_IMG="$img"; ORCH_ID="$id"
    else
      IMG_TARS+=("$img"); IMG_TAGS+=("$tag"); IMG_IDS+=("$id")
    fi
  done
  if [[ -z "$ORCH_IMG" ]]; then
    err "No orchestrator artifact (bas-orchestrator-${BAS_VERSION}.tar) found in ${SCRIPT_DIR}/images -- refusing to install without it."
    exit 1
  fi
  # ALL runtime images are required (compose starts them with no profile).
  local req
  for req in postgres-16-alpine.tar headless-shell.tar "bas-caldera-${BAS_VERSION}.tar"; do
    [[ -f "${SCRIPT_DIR}/images/${req}" ]] || { err "Required runtime image ${req} missing from ${SCRIPT_DIR}/images -- refusing."; exit 1; }
  done
}

_do_install_steps() {
  if [[ "$OFFLINE" == "true" ]]; then
    _verify_all_images
  fi

  _step 5 "Installing Docker CE (may take 1-2 minutes)..."
  if $NEED_DOCKER; then
    install_docker || { err "Docker install failed."; exit 1; }
  fi

  _step 15 "Creating install directory..."
  mkdir -p "${INSTALL_DIR}/scenarios" "${INSTALL_DIR}/wwwroot" "${INSTALL_DIR}/data" "${INSTALL_DIR}/art-payloads"

  _step 20 "Installing license..."
  cp "${LIC_PATH}" "${INSTALL_DIR}/bas.lic"
  chmod 644 "${INSTALL_DIR}/bas.lic"
  chown root:root "${INSTALL_DIR}/bas.lic"

  _step 25 "Copying application files..."
  if [[ -d "${SCRIPT_DIR}/scenarios" ]]; then
    cp -r "${SCRIPT_DIR}/scenarios/." "${INSTALL_DIR}/scenarios/"
  fi
  # The orchestrator runs as the distroless 'nonroot' user (uid/gid 65532) and
  # writes into this bind-mounted dir: scenarios/custom (clone + save) and
  # scenarios/intel (threat-intel connector). Pre-create those subdirs and hand
  # the whole scenarios tree to 65532 so MkdirAll/WriteFile from the container
  # don't fail with EACCES ("create custom dir: permission denied"). Builtin
  # YAMLs stay readable; only ownership changes.
  mkdir -p "${INSTALL_DIR}/scenarios/custom" "${INSTALL_DIR}/scenarios/intel"
  chown -R 65532:65532 "${INSTALL_DIR}/scenarios"
  if [[ -d "${SCRIPT_DIR}/wwwroot" ]]; then
    cp -r "${SCRIPT_DIR}/wwwroot/." "${INSTALL_DIR}/wwwroot/"
  fi
  # ART external payloads bundled at build time — copied so the orchestrator's
  # /art-payloads mount is populated. Empty is fine (payload atomics skip cleanly).
  if [[ -d "${SCRIPT_DIR}/art-payloads" ]]; then
    cp -r "${SCRIPT_DIR}/art-payloads/." "${INSTALL_DIR}/art-payloads/"
    chmod 644 "${INSTALL_DIR}/art-payloads/"* 2>/dev/null || true
  fi

  _step 30 "Copying configuration templates..."
  cp "${SCRIPT_DIR}/docker-compose.yml"      "${INSTALL_DIR}/"
  cp "${SCRIPT_DIR}/docker-compose.prod.yml" "${INSTALL_DIR}/"

  _step 38 "Writing .env configuration..."
  cat > "${INSTALL_DIR}/.env" <<EOF
# BAS Platform — generated by setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
BAS_VERSION=${BAS_VERSION}
REGISTRY=
POSTGRES_DB=bas_platform
POSTGRES_USER=bas_user
POSTGRES_PASSWORD=${DB_PASSWORD}
JWT_SECRET=${JWT_SECRET}
AGENT_SECRET=${AGENT_SECRET}
DASHBOARD_PORT=${DASHBOARD_PORT}
BAS_LICENSE_PATH=/etc/bas/bas.lic
CALDERA_API_KEY=${CALDERA_API_KEY}
CALDERA_API_KEY_BLUE=${CALDERA_API_KEY_BLUE}
BAS_ADMIN_EMAIL=${ADMIN_EMAIL}
BAS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
  chmod 640 "${INSTALL_DIR}/.env"
  chown root:root "${INSTALL_DIR}/.env"

  _step 50 "Loading Docker images..."
  if [[ "$OFFLINE" == "true" ]]; then
    # Everything was verified up front (_verify_all_images). Load the other
    # images first, the orchestrator LAST, and after each load require the tag
    # to resolve to exactly the image ID recorded from the verified tar's
    # manifest, so no tag planted elsewhere can be what compose runs.
    local i
    for i in "${!IMG_TARS[@]}"; do
      _step 55 "Loading $(basename "${IMG_TARS[$i]}")..."
      docker load < "${IMG_TARS[$i]}" || { err "docker load failed for $(basename "${IMG_TARS[$i]}")"; exit 1; }
      _docker_tag_is "${IMG_TAGS[$i]}" "${IMG_IDS[$i]}" || { err "${IMG_TAGS[$i]} is not the verified image after load -- aborting."; exit 1; }
    done
    _step 55 "Loading $(basename "$ORCH_IMG")..."
    docker load < "$ORCH_IMG"
    _docker_tag_is "bas-orchestrator:${BAS_VERSION}" "$ORCH_ID" || { err "bas-orchestrator:${BAS_VERSION} is not the verified image after load -- aborting before starting services."; exit 1; }
  else
    cd "${INSTALL_DIR}"
    docker compose -f docker-compose.yml pull --quiet || true
  fi

  _step 80 "Installing systemd service..."
  sed "s|/opt/bas-platform|${INSTALL_DIR}|g" \
    "${SCRIPT_DIR}/systemd/bas-compose.service" \
    > /etc/systemd/system/bas-compose.service
  systemctl daemon-reload
  systemctl enable bas-compose.service

  _step 87 "Starting BAS Platform..."
  cd "${INSTALL_DIR}"
  systemctl start bas-compose.service
  sleep 3

  _step 93 "Waiting for orchestrator to become healthy..."
  local retries=0
  until curl -sf "http://localhost:${DASHBOARD_PORT}/health" &>/dev/null || [[ $retries -ge 24 ]]; do
    sleep 5
    ((retries++))
  done

  _step 98 "Finalising..."
  _step 100 "Installation complete."
}

show_credentials() {
  local detected_ip
  detected_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")
  echo ""
  echo "============================================================"
  echo "  BAS Platform v${BAS_VERSION} installed successfully!"
  echo "============================================================"
  echo ""
  echo "  Dashboard URL : http://${detected_ip}:${DASHBOARD_PORT}"
  echo "  Caldera UI    : http://${detected_ip}:8888"
  echo "  Login         : admin / (password you set)"
  echo "  Install path  : ${INSTALL_DIR}"
  echo ""
  echo "  Agent downloads:"
  echo "    Linux amd64 : http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/linux-amd64"
  echo "    Linux arm64 : http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/linux-arm64"
  echo "    Windows     : http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/windows-amd64"
  echo ""
  echo "  Useful commands:"
  echo "    Logs   : docker compose -C ${INSTALL_DIR} logs -f"
  echo "    Status : systemctl status bas-compose"
  echo "    Stop   : systemctl stop bas-compose"
  echo "============================================================"
}

# ── Web-based setup wizard ────────────────────────────────────────────────────
# Writes a Python3 stdlib HTTP server to /tmp, starts it on :9001.
# The browser form POSTs config values; the server writes setup.conf and
# spawns this same setup.sh with --config + --no-wizard.
# All output from the install subprocess is streamed back to the browser via SSE.
# Python exits automatically ~3 s after the subprocess completes.
start_web_wizard() {
  command -v python3 &>/dev/null || { err "python3 is required for the setup wizard."; exit 1; }

  local server_ip
  server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

  local pyfile
  pyfile=$(mktemp /tmp/bas-wizard-XXXXXX.py)
  chmod 600 "$pyfile"

  # Write the Python server — single-quoted heredoc prevents bash expansion
  cat > "$pyfile" << 'PYEOF'
#!/usr/bin/env python3
"""BAS Platform setup wizard -- Python3 stdlib only, fully offline."""
import http.server, socketserver, subprocess, threading, json, os, sys, time, socket

SCRIPT_DIR = sys.argv[1]
SETUP_SH   = sys.argv[2]
PORT       = 9001

_log     = []
_done    = False
_rc      = 0
_lock    = threading.Lock()
_started = False

def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip

PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BAS Platform Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b1420;color:#c9d1d9;font-family:ui-monospace,SFMono-Regular,"SF Mono",Consolas,"Liberation Mono",Menlo,monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem 1rem}
.card{background:#152338;border:1px solid #22324a;border-radius:8px;width:100%;max-width:580px;padding:2rem}
.header{margin-bottom:1.5rem}
.header h1{color:#e6edf3;font-size:1.1rem;font-weight:600;margin-bottom:.3rem}
.header p{color:#9aa9bc;font-size:.78rem}
.section-title{color:#9aa9bc;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;margin:1.25rem 0 .5rem}
.row{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}
label{display:block;color:#9aa9bc;font-size:.75rem;margin-bottom:.3rem}
input{width:100%;background:#0d1b2e;border:1px solid #22324a;border-radius:4px;color:#e6edf3;padding:.45rem .65rem;font-size:.82rem;font-family:inherit;outline:none;transition:border-color .15s}
input:focus{border-color:#2f81f7;background:#0f1f35}
input::placeholder{color:#3d4f63}
input:disabled{opacity:.5}
.field{margin-bottom:.75rem}
.btn{display:block;width:100%;margin-top:1.5rem;padding:.65rem;background:#2f81f7;border:none;border-radius:6px;color:#fff;font-family:inherit;font-size:.85rem;font-weight:600;cursor:pointer;transition:background .15s}
.btn:hover:not(:disabled){background:#388bfd}
.btn:disabled{background:#1b2a41;color:#4d5f72;cursor:not-allowed}
.log-wrap{display:none;margin-top:1.25rem;border:1px solid #22324a;border-radius:4px;overflow:hidden}
.log-wrap.show{display:block}
.log-head{background:#0d1b2e;padding:.4rem .7rem;font-size:.7rem;color:#9aa9bc;border-bottom:1px solid #22324a}
.log-body{background:#080f1a;padding:.6rem .7rem;height:240px;overflow-y:auto;font-size:.72rem;line-height:1.6}
.ll{white-space:pre-wrap;word-break:break-all}
.ll.ok{color:#3fb950}.ll.warn{color:#d29922}.ll.bad{color:#f85149}
.banner{display:none;margin-top:1rem;border-radius:6px;padding:.9rem 1rem;font-size:.8rem}
.banner.show{display:block}
.banner.success{background:#0f2718;border:1px solid #238636;color:#3fb950}
.banner.success h2{font-size:.9rem;margin-bottom:.4rem}
.banner.success a{color:#2f81f7;text-decoration:none}
.banner.success p{color:#9aa9bc;margin-top:.3rem;font-size:.75rem}
.banner.fail{background:#200e0e;border:1px solid #da3633;color:#f85149}
.sep{border:none;border-top:1px solid #1b2a41;margin:1.25rem 0}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <h1>BAS Platform &mdash; Setup Wizard</h1>
    <p>All configuration stays on this server. No internet required.</p>
  </div>
  <form id="frm">
    <p class="section-title">License</p>
    <div class="field">
      <label>License file path</label>
      <input name="LIC_PATH" placeholder="/root/hdfc-prod-001.lic" required>
    </div>
    <hr class="sep">
    <p class="section-title">Installation</p>
    <div class="row">
      <div class="field">
        <label>Install directory</label>
        <input name="INSTALL_DIR" value="/opt/bas-platform" required>
      </div>
      <div class="field">
        <label>Dashboard port</label>
        <input name="DASHBOARD_PORT" value="9000" required>
      </div>
    </div>
    <hr class="sep">
    <p class="section-title">Database</p>
    <div class="row">
      <div class="field">
        <label>Password <span style="color:#4d5f72">(min 8)</span></label>
        <input type="password" id="dbp" name="DB_PASSWORD" required>
      </div>
      <div class="field">
        <label>Confirm password</label>
        <input type="password" id="dbp2" required>
      </div>
    </div>
    <hr class="sep">
    <p class="section-title">Admin Account</p>
    <div class="row">
      <div class="field">
        <label>Admin Email <span style="color:#da3633">*</span></label>
        <input type="email" id="ade" name="ADMIN_EMAIL" placeholder="bas-admin@corp.internal" required>
      </div>
      <div class="field"></div>
    </div>
    <div class="row">
      <div class="field">
        <label>Password <span style="color:#4d5f72">(min 10)</span></label>
        <input type="password" id="adp" name="ADMIN_PASSWORD" required>
      </div>
      <div class="field">
        <label>Confirm password</label>
        <input type="password" id="adp2" required>
      </div>
    </div>
    <button type="submit" class="btn" id="btn">Install BAS Platform</button>
  </form>
  <div class="log-wrap" id="logwrap">
    <div class="log-head">Installation log</div>
    <div class="log-body" id="log"></div>
  </div>
  <div class="banner" id="ok"></div>
  <div class="banner fail" id="fail"></div>
</div>
<script>
const frm=document.getElementById("frm"),btn=document.getElementById("btn"),
      logEl=document.getElementById("log"),logWrap=document.getElementById("logwrap"),
      okBanner=document.getElementById("ok"),failBanner=document.getElementById("fail");
function addLine(txt){
  const d=document.createElement("div");
  const cls=txt.startsWith("[+]")?"ok":txt.startsWith("[!")?"warn":
            (txt.includes("[x]")||txt.toLowerCase().includes("error"))?"bad":"";
  d.className="ll"+(cls?" "+cls:"");
  d.textContent=txt;
  logEl.appendChild(d);
  logEl.scrollTop=logEl.scrollHeight;
}
frm.addEventListener("submit",async function(e){
  e.preventDefault();
  const dbp=document.getElementById("dbp").value;
  const dbp2=document.getElementById("dbp2").value;
  const adp=document.getElementById("adp").value;
  const adp2=document.getElementById("adp2").value;
  const ade=document.getElementById("ade").value;
  if(!ade||!ade.includes("@")){alert("A valid admin email address is required.");return;}
  if(dbp!==dbp2){alert("Database passwords do not match.");return;}
  if(adp!==adp2){alert("Admin passwords do not match.");return;}
  if(dbp.length<8){alert("Database password must be at least 8 characters.");return;}
  if(adp.length<10){alert("Admin password must be at least 10 characters.");return;}
  const data={};
  new FormData(frm).forEach(function(v,k){data[k]=v;});
  btn.disabled=true;
  btn.textContent="Installing...";
  frm.querySelectorAll("input").forEach(function(i){i.disabled=true;});
  logWrap.classList.add("show");
  try{
    const res=await fetch("/install",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify(data)
    });
    if(!res.ok){throw new Error("HTTP "+res.status);}
  }catch(err){
    failBanner.textContent="Failed to start installation: "+err.message;
    failBanner.classList.add("show");
    btn.disabled=false;
    btn.textContent="Retry";
    return;
  }
  const src=new EventSource("/events");
  src.onmessage=function(ev){
    const d=ev.data;
    if(d.startsWith("__DONE__")){
      src.close();
      const rc=parseInt(d.slice(8),10);
      btn.textContent="Done";
      if(rc===0){
        const ip=location.hostname;
        const port=data.DASHBOARD_PORT||"9000";
        okBanner.className="banner success show";
        okBanner.innerHTML="<h2>Installation complete!</h2>"+
          "<p>Dashboard: <a href=\"http://"+ip+":"+port+"\" target=\"_blank\">"+
          "http://"+ip+":"+port+"</a></p>"+
          "<p>Caldera: http://"+ip+":8888</p>"+
          "<p>Login: admin / (password you set)</p>";
      }else{
        failBanner.textContent="Installation failed (exit code "+rc+"). Check the log above.";
        failBanner.classList.add("show");
      }
    }else{
      try{addLine(JSON.parse(d));}catch(_){addLine(d);}
    }
  };
  src.onerror=function(){src.close();};
});
</script>
</body>
</html>'''

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        if self.path == "/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            idx = 0
            try:
                while True:
                    with _lock:
                        chunk = _log[idx:]
                        done  = _done
                        rc    = _rc
                    for line in chunk:
                        msg = json.dumps(line)
                        self.wfile.write(("data:" + msg + "\n\n").encode("utf-8"))
                        idx += 1
                    if chunk:
                        self.wfile.flush()
                    if done and idx >= len(_log):
                        self.wfile.write(("data:__DONE__" + str(rc) + "\n\n").encode("utf-8"))
                        self.wfile.flush()
                        break
                    time.sleep(0.1)
            except Exception:
                pass
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global _started
        if self.path == "/install" and not _started:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
            cfg = os.path.join(SCRIPT_DIR, "setup.conf")
            with open(cfg, "w") as fh:
                for k, v in data.items():
                    fh.write(k + "=" + v + "\n")
            os.chmod(cfg, 0o600)
            _started = True
            threading.Thread(target=_run_install, args=(cfg,), daemon=True).start()
            resp = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(400)
            self.end_headers()

def _run_install(cfg):
    global _done, _rc
    proc = subprocess.Popen(
        ["bash", SETUP_SH, "--config", cfg, "--offline", "--no-wizard"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    for line in proc.stdout:
        with _lock:
            _log.append(line.rstrip())
    proc.wait()
    with _lock:
        _rc   = proc.returncode
        _done = True
    threading.Timer(3, srv.shutdown).start()

ip  = _local_ip()
srv = ThreadedHTTPServer(("", PORT), Handler)
print("[+] BAS Setup Wizard: http://" + ip + ":" + str(PORT), flush=True)
print("[+] Open this URL in a browser on any machine on this network.", flush=True)
srv.serve_forever()
PYEOF

  log "Starting setup wizard on port 9001..."
  log ""
  log "  Open this URL in your browser:"
  log "  http://${server_ip}:9001"
  log ""
  log "  Fill in the form and click 'Install BAS Platform'."
  log "  This terminal will exit when installation is complete."
  log "  (Ctrl+C to cancel)"
  log ""

  python3 "$pyfile" "$SCRIPT_DIR" "${BASH_SOURCE[0]}"
  local wiz_rc=$?
  rm -f "$pyfile"
  [[ $wiz_rc -ne 0 ]] && { err "Setup wizard exited unexpectedly."; exit 1; }
}

page_finish() {
  local detected_ip
  detected_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")

  local svc_status
  svc_status=$(systemctl is-active bas-compose.service 2>/dev/null || echo "unknown")

  whiptail --title "$TITLE — Complete" --msgbox \
"BAS Platform v${BAS_VERSION} installed successfully!

  Service status:   ${svc_status}
  Dashboard URL:    http://${detected_ip}:${DASHBOARD_PORT}
  Caldera UI:       http://${detected_ip}:8888
  Install path:     ${INSTALL_DIR}
  Login:            admin / (password set during setup)

Agent download (run on each target host):
  Linux amd64:  http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/linux-amd64
  Linux arm64:  http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/linux-arm64
  Windows:      http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/windows-amd64

Useful commands:
  Logs:      docker compose -C ${INSTALL_DIR} logs -f
  Status:    systemctl status bas-compose
  Stop:      systemctl stop bas-compose
  Uninstall: sudo bash ${INSTALL_DIR}/uninstall.sh

Press OK to exit the installer." 28 74
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
  # ── Parse flags ──────────────────────────────────────────────────────────────
  local _args=("$@")
  local i=0
  while [[ $i -lt ${#_args[@]} ]]; do
    case "${_args[$i]}" in
      --offline)   OFFLINE=true ;;
      --no-wizard) NO_WIZARD=true ;;
      --gpg-pub=*) GPG_PUB_FLAG="${_args[$i]#--gpg-pub=}" ;;
      --gpg-pub)
        i=$(( i + 1 ))
        GPG_PUB_FLAG="${_args[$i]:-}"
        ;;
      --config)
        i=$(( i + 1 ))
        CONFIG_FILE="${_args[$i]:-}"
        ;;
    esac
    i=$(( i + 1 ))
  done

  # ── No-wizard mode: called internally by Python wizard subprocess ─────────────
  # Pure stdout, no whiptail; all output captured by Python SSE streamer.
  if $NO_WIZARD; then
    [[ -z "$CONFIG_FILE" ]] && { err "--config <file> is required with --no-wizard"; exit 1; }
    require_root
    verify_bundle_signatures
    load_config "$CONFIG_FILE"

    log "Validating license..."
    local lic_result
    lic_result=$(_check_license "$LIC_PATH")
    if [[ "$lic_result" == OK:* ]]; then
      local lic_info="${lic_result#OK:}"
      log "License OK -- ${lic_info%%|*} (expires ${lic_info##*|})"
    else
      err "License invalid: ${lic_result#FAIL:}"
      exit 1
    fi

    log "Checking prerequisites..."
    while IFS= read -r result; do
      local status="${result%%:*}" message="${result#*:}"
      case "$status" in
        PASS) log "  OK  ${message}" ;;
        WARN) warn "  WN  ${message}" ;;
        INST) log "  >>  ${message} (will install)" ;;
        FAIL) err "  !! ${message}"; exit 1 ;;
      esac
    done < <(
      check_os
      check_ram
      check_disk "$INSTALL_DIR"
      check_docker
      check_compose
      check_cosign
      check_port "$DASHBOARD_PORT"
      check_port "5432"
    )

    if $NEED_DOCKER; then
      log "Installing Docker CE..."
      install_docker || { err "Docker CE installation failed."; exit 1; }
    fi

    do_install
    show_credentials
    return 0
  fi

  # ── Normal interactive modes ──────────────────────────────────────────────────
  require_root
  ensure_whiptail
  verify_bundle_signatures

  # Config file mode: setup.conf was pre-seeded or --config passed
  if [[ -n "$CONFIG_FILE" ]] || [[ -f "${SCRIPT_DIR}/setup.conf" ]]; then
    [[ -z "$CONFIG_FILE" ]] && CONFIG_FILE="${SCRIPT_DIR}/setup.conf"
    load_config "$CONFIG_FILE"

    log "Validating license..."
    local lic_result lic_info
    lic_result=$(_check_license "$LIC_PATH")
    if [[ "$lic_result" != OK:* ]]; then
      { whiptail --title "$TITLE -- License Error" --msgbox \
"License check FAILED:

  ${lic_result#FAIL:}

Edit setup.conf, update LIC_PATH, and re-run." 14 64; } 2>/dev/null || \
        err "License invalid: ${lic_result#FAIL:}"
      exit 1
    fi
    lic_info="${lic_result#OK:}"
    log "License OK -- ${lic_info%%|*} (expires ${lic_info##*|})"

    page_welcome
    page_prereqs
    do_install
    page_finish
    log "Setup complete. Dashboard: http://$(hostname -I | awk '{print $1}'):${DASHBOARD_PORT}"
    return 0
  fi

  # Web wizard mode: no setup.conf found
  start_web_wizard
}

main "$@"
