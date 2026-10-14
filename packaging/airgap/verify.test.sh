#!/usr/bin/env bash
# packaging/airgap/verify.test.sh
set -euo pipefail

TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

make_bundle() {
  local dir="$1"
  mkdir -p "$dir/images"
  echo "fake-orch" > "$dir/images/bas-orchestrator-1.0.0.tar.gz"
  echo "fake-orch-bundle" > "$dir/images/bas-orchestrator-1.0.0.tar.gz.bundle"
  echo "fake-cosign-pub"  > "$dir/cosign.pub"
  echo "fake-pg"   > "$dir/images/postgres-16-alpine.tar.gz"
  touch "$dir/setup.sh" "$dir/docker-compose.yml" "$dir/docker-compose.prod.yml"
  echo "1.0.0" > "$dir/VERSION"
  touch "$dir/import.sh"
  (cd "$dir" && find . -type f ! -name MANIFEST.sha256 | sort | while read -r f; do
    sha256sum "$f" | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/'
  done) > "$dir/MANIFEST.sha256"
}

make_tarball() {
  local src_dir="$1" out_tarball="$2"
  tar -czf "$out_tarball" -C "$(dirname "$src_dir")" "$(basename "$src_dir")"
}

echo "TEST: verify.sh passes for a correctly signed, correctly checksummed, flat-layout bundle"
BUNDLE="$TESTDIR/bas-airgap-1.0.0"
make_bundle "$BUNDLE"
TARBALL="$TESTDIR/bas-airgap-1.0.0.tar.gz"
make_tarball "$BUNDLE" "$TARBALL"
sha256sum "$TARBALL" > "${TARBALL}.sha256"

gpg() { # mock: always "verifies" -- return, not exit: `exit` inside an
        # exported function kills the whole verify.sh process on its
        # FIRST internal gpg call (--import), never reaching --verify or
        # anything after it.
  for a in "$@"; do [[ "$a" == "--verify" ]] && { echo "gpg: Good signature" >&2; return 0; }; done
  return 0
}
export -f gpg
docker() { [[ "$1 $2" == "compose version" ]] && echo "2.24.5"; }
export -f docker
touch "${TARBALL}.asc"
touch "$TESTDIR/pubkey.asc"

if ! BAS_VERIFY_PUBKEY="$TESTDIR/pubkey.asc" bash "$(dirname "$0")/verify.sh" "$TARBALL"; then
  echo "FAIL: expected a correctly signed, correctly checksummed bundle to pass"
  exit 1
fi
echo "PASS"

echo "TEST: verify.sh fails when the GPG signature file is missing"
rm -f "${TARBALL}.asc"
if BAS_VERIFY_PUBKEY="$TESTDIR/pubkey.asc" bash "$(dirname "$0")/verify.sh" "$TARBALL"; then
  echo "FAIL: expected a missing .asc to fail verify.sh, not warn and continue"
  exit 1
fi
echo "PASS"

echo "TEST: verify.sh fails when a bundle file was altered after the manifest was generated"
touch "${TARBALL}.asc"
BUNDLE2="$TESTDIR/bas-airgap-1.0.1"
make_bundle "$BUNDLE2"
echo "tampered" > "$BUNDLE2/images/bas-orchestrator-1.0.0.tar.gz"
TARBALL2="$TESTDIR/bas-airgap-1.0.1.tar.gz"
# repack without regenerating the manifest, to simulate a post-manifest tamper
tar -czf "$TARBALL2" -C "$(dirname "$BUNDLE2")" "$(basename "$BUNDLE2")"
touch "${TARBALL2}.asc"
if BAS_VERIFY_PUBKEY="$TESTDIR/pubkey.asc" bash "$(dirname "$0")/verify.sh" "$TARBALL2"; then
  echo "FAIL: expected an altered file to fail the manifest check"
  exit 1
fi
echo "PASS"

echo "TEST: verify.sh fails when the installed Compose version is below the floor"
docker() { [[ "$1 $2" == "compose version" ]] && echo "2.5.0"; }
export -f docker
if BAS_VERIFY_PUBKEY="$TESTDIR/pubkey.asc" bash "$(dirname "$0")/verify.sh" "$TARBALL"; then
  echo "FAIL: expected an old Compose version to fail verify.sh"
  exit 1
fi
echo "PASS"

echo "TEST: verify.sh fails a bundle missing cosign.pub (even though GPG+manifest both still pass)"
docker() { [[ "$1 $2" == "compose version" ]] && echo "2.24.5"; }
export -f docker
BUNDLE3="$TESTDIR/bas-airgap-1.0.2"
make_bundle "$BUNDLE3"
rm -f "$BUNDLE3/cosign.pub"
# regenerate the manifest to match the bundle with cosign.pub actually removed --
# this proves the REQUIRED-files check catches it, not a manifest mismatch.
(cd "$BUNDLE3" && find . -type f ! -name MANIFEST.sha256 | sort | while read -r f; do
  sha256sum "$f" | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/'
done) > "$BUNDLE3/MANIFEST.sha256"
TARBALL3="$TESTDIR/bas-airgap-1.0.2.tar.gz"
make_tarball "$BUNDLE3" "$TARBALL3"
touch "${TARBALL3}.asc"
if BAS_VERIFY_PUBKEY="$TESTDIR/pubkey.asc" bash "$(dirname "$0")/verify.sh" "$TARBALL3"; then
  echo "FAIL: expected a bundle missing cosign.pub to fail verify.sh"
  exit 1
fi
echo "PASS"

echo "TEST: verify.sh fails a bundle missing the orchestrator's cosign .bundle signature file"
BUNDLE4="$TESTDIR/bas-airgap-1.0.3"
make_bundle "$BUNDLE4"
rm -f "$BUNDLE4/images/bas-orchestrator-1.0.0.tar.gz.bundle"
(cd "$BUNDLE4" && find . -type f ! -name MANIFEST.sha256 | sort | while read -r f; do
  sha256sum "$f" | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/'
done) > "$BUNDLE4/MANIFEST.sha256"
TARBALL4="$TESTDIR/bas-airgap-1.0.3.tar.gz"
make_tarball "$BUNDLE4" "$TARBALL4"
touch "${TARBALL4}.asc"
if BAS_VERIFY_PUBKEY="$TESTDIR/pubkey.asc" bash "$(dirname "$0")/verify.sh" "$TARBALL4"; then
  echo "FAIL: expected a bundle missing the orchestrator .bundle signature to fail verify.sh"
  exit 1
fi
echo "PASS"

echo "TEST: verify.sh contains no inline signature/manifest/compose-version logic of its own"
if grep -E 'gpg .*--verify|docker compose version' "$(dirname "$0")/verify.sh" | grep -v 'source\|verify-common'; then
  echo "FAIL: verify.sh must call verify-common.sh's functions, not duplicate the checks inline"
  exit 1
fi
echo "PASS"

echo "ALL TESTS PASSED"
