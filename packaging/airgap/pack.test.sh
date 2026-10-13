#!/usr/bin/env bash
# packaging/airgap/pack.test.sh
#
# Mocks every external tool pack.sh calls (docker, go, gpg via sign.sh,
# cosign via cosign.sh) and runs the real pack.sh against this repo, then
# asserts on the resulting bundle's layout -- proving pack.sh calls the
# right tools in the right order and produces the flat shape setup.sh
# expects, not that the real tools would accept the (fake) artifacts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

CALL_LOG="$TESTDIR/calls.log"
MOCKDIR="$TESTDIR/mockbin"
mkdir -p "$MOCKDIR"

# docker: image inspect succeeds (pretend the orchestrator image is already
# built locally), pull succeeds, save writes a tiny fake tarball.
cat > "$MOCKDIR/docker" << 'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "$CALL_LOG"
case "$1" in
  info) exit 0 ;;
  pull) exit 0 ;;
  image) [[ "$2" == "inspect" ]] && exit 0 ;;
  save) echo "fake-image-bytes" ;;
esac
EOF
chmod +x "$MOCKDIR/docker"

# go: the builtin-scenario-signature release gate always passes.
cat > "$MOCKDIR/go" << 'EOF'
#!/usr/bin/env bash
echo "go $*" >> "$CALL_LOG"
exit 0
EOF
chmod +x "$MOCKDIR/go"

# packaging/signing/sign.sh and cosign.sh are the real call boundary pack.sh
# uses for GPG and cosign -- replace them with mocks that just prove they
# were invoked, so this test exercises pack.sh's own ordering/layout logic
# without needing a real gpg keyring or a real cosign key.
SIGNING_MOCK_DIR="$TESTDIR/signing"
mkdir -p "$SIGNING_MOCK_DIR"
cat > "$SIGNING_MOCK_DIR/sign.sh" << 'EOF'
#!/usr/bin/env bash
echo "sign.sh $*" >> "$CALL_LOG"
touch "$1.asc" "$1.sha256"
exit 0
EOF
cat > "$SIGNING_MOCK_DIR/cosign.sh" << 'EOF'
#!/usr/bin/env bash
echo "cosign.sh $*" >> "$CALL_LOG"
case "$1" in
  --sign)   touch "$2.bundle" ;;
  --verify) exit 0 ;;
esac
exit 0
EOF
chmod +x "$SIGNING_MOCK_DIR/sign.sh" "$SIGNING_MOCK_DIR/cosign.sh"
# cosign.sh's real counterpart (packaging/signing/cosign.sh --sign) always
# leaves a cosign.pub behind for the build to ship; the mock does not
# itself produce one as a side effect, so the fixture provides it directly.
touch "$SIGNING_MOCK_DIR/cosign.pub"

export PATH="$MOCKDIR:$PATH"
export CALL_LOG

cd "$REPO_ROOT"
TEST_DIST_DIR="$TESTDIR/dist"
mkdir -p "$TEST_DIST_DIR"

echo "TEST: pack.sh produces a flat bundle layout with setup.sh as a direct sibling of images/, VERSION, and cosign.pub"
BAS_PACK_SIGNING_DIR="$SIGNING_MOCK_DIR" BAS_PACK_DIST_DIR="$TEST_DIST_DIR" \
  bash packaging/airgap/pack.sh "0.0.0-test"

TARBALL="$TEST_DIST_DIR/bas-airgap-0.0.0-test.tar.gz"
[[ -f "$TARBALL" ]] || { echo "FAIL: expected tarball at $TARBALL"; exit 1; }

EXTRACT="$TESTDIR/extracted"
mkdir -p "$EXTRACT"
tar -xzf "$TARBALL" -C "$EXTRACT"
BUNDLE_DIR=$(find "$EXTRACT" -maxdepth 1 -mindepth 1 -type d | head -1)

for f in setup.sh uninstall.sh VERSION cosign.pub docker-compose.yml docker-compose.prod.yml MANIFEST.sha256 import.sh verify.sh; do
  [[ -f "${BUNDLE_DIR}/${f}" ]] || { echo "FAIL: expected ${f} at the bundle root, found nothing"; exit 1; }
done
[[ -f "${BUNDLE_DIR}/images/bas-orchestrator-0.0.0-test.tar.gz" ]] || { echo "FAIL: expected orchestrator image under images/"; exit 1; }
[[ -f "${BUNDLE_DIR}/images/bas-orchestrator-0.0.0-test.tar.gz.bundle" ]] || { echo "FAIL: expected a cosign .bundle signature alongside the orchestrator image"; exit 1; }
[[ ! -d "${BUNDLE_DIR}/compose" ]] || { echo "FAIL: expected no nested compose/ directory in the flat layout"; exit 1; }
echo "PASS"

echo "TEST: pack.sh cosign-signs the orchestrator tarball before packaging it, matching build.sh's own sequence"
grep -q "cosign.sh --sign" "$CALL_LOG" || { echo "FAIL: expected pack.sh to invoke cosign.sh --sign"; exit 1; }
grep -q "cosign.sh --verify" "$CALL_LOG" || { echo "FAIL: expected pack.sh to self-verify the cosign signature it just produced"; exit 1; }
echo "PASS"

echo "TEST: pack.sh fails the build (not warn) when no GPG signing key is available"
: > "$CALL_LOG"
cat > "$SIGNING_MOCK_DIR/sign.sh" << 'EOF'
#!/usr/bin/env bash
echo "sign.sh $*" >> "$CALL_LOG"
echo "No signing key found" >&2
exit 1
EOF
chmod +x "$SIGNING_MOCK_DIR/sign.sh"
if BAS_PACK_SIGNING_DIR="$SIGNING_MOCK_DIR" BAS_PACK_DIST_DIR="$TEST_DIST_DIR" \
    bash packaging/airgap/pack.sh "0.0.1-test"; then
  echo "FAIL: expected pack.sh to fail the build when GPG signing fails, not warn and produce an unsigned bundle"
  exit 1
fi
[[ ! -f "$TEST_DIST_DIR/bas-airgap-0.0.1-test.tar.gz" ]] || { echo "FAIL: an unsigned bundle must not be produced at all"; exit 1; }
echo "PASS"

echo "ALL TESTS PASSED"
