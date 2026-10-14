#!/usr/bin/env bash
# packaging/airgap/verify-common.sh
#
# Shared verification functions for the air-gap bundle pipeline. Sourced by
# both verify.sh (operator pre-flight check) and import.sh (the actual
# import path) so the two can never enforce different rules. No function
# here has a side effect outside the paths it is explicitly given -- no
# docker load, no write under an install directory.

# verify_gpg_signature TARBALL SIGFILE PUBKEY
# Verifies TARBALL's detached GPG signature (SIGFILE) against PUBKEY, using
# an isolated temporary keyring so this never touches the caller's real
# GPG keyring. Prints the fingerprint it is about to trust before
# verifying, so an operator following the documented key-provisioning
# process (spec Section 2.5) can compare it against the independently
# communicated value.
verify_gpg_signature() {
  local tarball="$1" sigfile="$2" pubkey="$3"

  if ! command -v gpg &>/dev/null; then
    echo "verify_gpg_signature: gpg is not installed" >&2
    return 1
  fi
  if [[ ! -f "$sigfile" ]]; then
    echo "verify_gpg_signature: signature file not found: $sigfile" >&2
    return 1
  fi
  if [[ ! -f "$pubkey" ]]; then
    echo "verify_gpg_signature: public key not found: $pubkey" >&2
    return 1
  fi

  local tmpring
  tmpring=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmpring'" RETURN

  gpg --quiet --batch --no-default-keyring \
      --keyring "${tmpring}/verify.gpg" \
      --import "$pubkey" 2>/dev/null

  local fpr
  fpr=$(gpg --quiet --batch --no-default-keyring \
            --keyring "${tmpring}/verify.gpg" \
            --list-keys --with-colons 2>/dev/null \
    | awk -F: '/^fpr/{print $10; exit}')
  echo "verify_gpg_signature: trusting key fingerprint ${fpr:-unknown} -- compare this against the independently published value before proceeding" >&2

  if ! gpg --quiet --batch --no-default-keyring \
           --keyring "${tmpring}/verify.gpg" \
           --verify "$sigfile" "$tarball" 2>/dev/null; then
    echo "verify_gpg_signature: signature INVALID for $tarball" >&2
    return 1
  fi
  return 0
}

# verify_manifest BUNDLE_DIR
# Checksums every file listed in BUNDLE_DIR/MANIFEST.sha256 against the
# files as they exist right now. Deliberately independent of signature
# verification: a valid signature over the original tarball says nothing
# about files that were swapped after extraction, which is exactly the
# TOCTOU window this function closes.
verify_manifest() {
  local bundle_dir="$1"
  local manifest="${bundle_dir}/MANIFEST.sha256"

  if [[ ! -f "$manifest" ]]; then
    echo "verify_manifest: MANIFEST.sha256 not found in $bundle_dir" >&2
    return 1
  fi

  local fail_count=0
  while read -r expected_hash rel_path; do
    [[ -z "$expected_hash" ]] && continue
    rel_path="${rel_path#\*}"
    rel_path="${rel_path#./}"
    local abs_path="${bundle_dir}/${rel_path}"

    if [[ ! -f "$abs_path" ]]; then
      echo "verify_manifest: missing file: $rel_path" >&2
      ((fail_count++))
      continue
    fi
    local actual_hash
    actual_hash=$(sha256sum "$abs_path" | cut -d' ' -f1)
    if [[ "$actual_hash" != "$expected_hash" ]]; then
      echo "verify_manifest: checksum mismatch: $rel_path" >&2
      ((fail_count++))
    fi
  done < "$manifest"

  [[ $fail_count -eq 0 ]]
}

# check_compose_version_floor MIN_VERSION
# Runs `docker compose version --short`, parses the result as X.Y.Z, and
# returns success only if it parses AND is >= MIN_VERSION. A missing
# plugin, a failing command, or an unparseable string are all failures --
# never silently treated as "new enough" or "doesn't matter".
check_compose_version_floor() {
  local min_version="$1"
  local raw

  if ! raw=$(docker compose version --short 2>/dev/null); then
    echo "check_compose_version_floor: 'docker compose version' failed or Compose plugin is not installed" >&2
    return 1
  fi
  raw="${raw//[[:space:]]/}"

  if [[ ! "$raw" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    echo "check_compose_version_floor: could not parse Compose version string: '$raw'" >&2
    return 1
  fi
  local got_major="${BASH_REMATCH[1]}" got_minor="${BASH_REMATCH[2]}" got_patch="${BASH_REMATCH[3]}"

  local min_major min_minor min_patch
  IFS='.' read -r min_major min_minor min_patch <<< "$min_version"

  if (( got_major > min_major )); then return 0; fi
  if (( got_major < min_major )); then
    echo "check_compose_version_floor: Compose $raw is below the required floor $min_version" >&2
    return 1
  fi
  if (( got_minor > min_minor )); then return 0; fi
  if (( got_minor < min_minor )); then
    echo "check_compose_version_floor: Compose $raw is below the required floor $min_version" >&2
    return 1
  fi
  if (( got_patch >= min_patch )); then return 0; fi
  echo "check_compose_version_floor: Compose $raw is below the required floor $min_version" >&2
  return 1
}
