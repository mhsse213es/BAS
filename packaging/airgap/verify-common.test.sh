#!/usr/bin/env bash
# packaging/airgap/verify-common.test.sh
set -euo pipefail

TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

# shellcheck disable=SC1091
source "$(dirname "$0")/verify-common.sh"

echo "TEST: check_compose_version_floor passes when installed version is above the floor"
docker() { echo "2.24.5"; }
export -f docker
if ! check_compose_version_floor "2.8.0"; then
  echo "FAIL: expected 2.24.5 to pass the 2.8.0 floor"; exit 1
fi
echo "PASS"

echo "TEST: check_compose_version_floor rejects a version below the floor"
docker() { echo "2.7.9"; }
export -f docker
if check_compose_version_floor "2.8.0"; then
  echo "FAIL: expected 2.7.9 to fail the 2.8.0 floor"; exit 1
fi
echo "PASS"

echo "TEST: check_compose_version_floor rejects an unparseable version string"
docker() { echo "not-a-version"; }
export -f docker
if check_compose_version_floor "2.8.0"; then
  echo "FAIL: expected an unparseable string to be rejected, not silently accepted or crash-free"; exit 1
fi
echo "PASS"

echo "TEST: check_compose_version_floor rejects when the compose command itself fails"
docker() { return 1; }
export -f docker
if check_compose_version_floor "2.8.0"; then
  echo "FAIL: expected a failing 'docker compose version' to be rejected"; exit 1
fi
echo "PASS"

echo "TEST: verify_manifest passes when every listed file matches its checksum"
BUNDLE="$TESTDIR/bundle_ok"
mkdir -p "$BUNDLE"
echo "hello" > "$BUNDLE/a.txt"
HASH_A=$(sha256sum "$BUNDLE/a.txt" | cut -d' ' -f1)
printf '%s  a.txt\n' "$HASH_A" > "$BUNDLE/MANIFEST.sha256"
if ! verify_manifest "$BUNDLE"; then
  echo "FAIL: expected a correctly checksummed file to pass"; exit 1
fi
echo "PASS"

echo "TEST: verify_manifest fails when a listed file is altered after the manifest was generated"
BUNDLE="$TESTDIR/bundle_altered"
mkdir -p "$BUNDLE"
echo "hello" > "$BUNDLE/a.txt"
HASH_A=$(sha256sum "$BUNDLE/a.txt" | cut -d' ' -f1)
printf '%s  a.txt\n' "$HASH_A" > "$BUNDLE/MANIFEST.sha256"
echo "tampered" > "$BUNDLE/a.txt"
if verify_manifest "$BUNDLE"; then
  echo "FAIL: expected an altered file to fail manifest verification"; exit 1
fi
echo "PASS"

echo "TEST: verify_manifest fails when MANIFEST.sha256 itself is missing"
BUNDLE="$TESTDIR/bundle_no_manifest"
mkdir -p "$BUNDLE"
if verify_manifest "$BUNDLE"; then
  echo "FAIL: expected a missing MANIFEST.sha256 to fail, not skip silently"; exit 1
fi
echo "PASS"

echo "TEST: verify_gpg_signature fails when the signature file is missing"
TARBALL="$TESTDIR/bundle.tar.gz"
touch "$TARBALL"
PUBKEY="$TESTDIR/pubkey.asc"
touch "$PUBKEY"
if verify_gpg_signature "$TARBALL" "${TARBALL}.asc" "$PUBKEY"; then
  echo "FAIL: expected a missing .asc to fail verification"; exit 1
fi
echo "PASS"

echo "TEST: verify_gpg_signature fails when the public key file is missing"
touch "${TARBALL}.asc"
if verify_gpg_signature "$TARBALL" "${TARBALL}.asc" "$TESTDIR/no-such-pubkey.asc"; then
  echo "FAIL: expected a missing pubkey to fail verification"; exit 1
fi
echo "PASS"

echo "TEST: verify_manifest fails when the signature is valid but the manifest-checked file was altered after extraction (TOCTOU case)"
BUNDLE="$TESTDIR/bundle_toctou"
mkdir -p "$BUNDLE"
echo "original" > "$BUNDLE/payload.bin"
HASH_ORIG=$(sha256sum "$BUNDLE/payload.bin" | cut -d' ' -f1)
printf '%s  payload.bin\n' "$HASH_ORIG" > "$BUNDLE/MANIFEST.sha256"
# Simulate a swap introduced between signature verification and consumption --
# the signature itself is irrelevant to this function; verify_manifest alone
# must still catch the swap, independent of whatever verify_gpg_signature said.
echo "swapped" > "$BUNDLE/payload.bin"
if verify_manifest "$BUNDLE"; then
  echo "FAIL: a post-extraction swap must still be caught by the manifest check even if signature verification already passed"; exit 1
fi
echo "PASS"

echo "ALL TESTS PASSED"
