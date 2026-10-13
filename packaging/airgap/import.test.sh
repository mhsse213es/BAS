#!/usr/bin/env bash
# packaging/airgap/import.test.sh
set -euo pipefail

TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT
CALL_LOG="$TESTDIR/calls.log"

make_bundle() {
  local dir="$1"
  mkdir -p "$dir/images"
  echo "fake-orch" > "$dir/images/bas-orchestrator-1.0.0.tar.gz"
  echo "fake-pg"   > "$dir/images/postgres-16-alpine.tar.gz"
  cat > "$dir/setup.sh" << 'EOF'
#!/usr/bin/env bash
echo "setup.sh $*" >> "$CALL_LOG_PATH"
exit 0
EOF
  chmod +x "$dir/setup.sh"
  touch "$dir/docker-compose.yml" "$dir/docker-compose.prod.yml"
  echo "1.0.0" > "$dir/VERSION"
  (cd "$dir" && find . -type f ! -name MANIFEST.sha256 | sort | while read -r f; do
    sha256sum "$f" | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/'
  done) > "$dir/MANIFEST.sha256"
}

make_tarball() {
  tar -czf "$2" -C "$(dirname "$1")" "$(basename "$1")"
}

docker() {
  echo "docker $*" >> "$CALL_LOG"
  [[ "$1 $2" == "compose version" ]] && { echo "2.24.5"; return 0; }
  [[ "$1" == "info" ]] && return 0
  return 0
}
export -f docker
gpg() {
  # return, not exit: `exit` inside an exported function kills the whole
  # caller process on gpg's FIRST internal call (--import), never
  # reaching --verify or anything after it.
  for a in "$@"; do [[ "$a" == "--verify" ]] && { return 0; }; done
  return 0
}
export -f gpg
export CALL_LOG CALL_LOG_PATH="$CALL_LOG"

echo "TEST: import.sh runs manifest and compose-version checks before any docker load"
BUNDLE="$TESTDIR/bas-airgap-1.0.0"
make_bundle "$BUNDLE"
TARBALL="$TESTDIR/bas-airgap-1.0.0.tar.gz"
make_tarball "$BUNDLE" "$TARBALL"
touch "${TARBALL}.asc"
touch "$TESTDIR/pubkey.asc"

: > "$CALL_LOG"
source "$(dirname "$0")/verify-common.sh"
BAS_VERIFY_PUBKEY="$TESTDIR/pubkey.asc" verify_gpg_signature "$TARBALL" "${TARBALL}.asc" "$TESTDIR/pubkey.asc" >> "$CALL_LOG" 2>&1
verify_manifest "$BUNDLE" >> "$CALL_LOG" 2>&1
check_compose_version_floor "2.8.0" >> "$CALL_LOG" 2>&1
if grep -q "docker load" "$CALL_LOG"; then
  echo "FAIL: no docker load should have happened yet -- only verification ran"
  exit 1
fi
echo "PASS"

echo "TEST: import.sh's own source contains no warn-and-continue branch for a missing signature, manifest, or Compose check"
IMPORT_SRC="$(dirname "$0")/import.sh"
if grep -A1 'No GPG signature' "$IMPORT_SRC" | grep -q 'proceeding without'; then
  echo "FAIL: import.sh must not contain a 'proceeding without signature verification' branch"
  exit 1
fi
if grep -A1 'No MANIFEST.sha256' "$IMPORT_SRC" | grep -q 'skipping integrity check'; then
  echo "FAIL: import.sh must not contain a 'skipping integrity check' branch"
  exit 1
fi
echo "PASS"

echo "TEST: import.sh resolves setup.sh at the bundle root, not under compose/"
if grep -q '"\${BUNDLE_DIR}/compose/setup.sh"' "$IMPORT_SRC"; then
  echo "FAIL: import.sh must look for setup.sh at the bundle root under the flat layout"
  exit 1
fi
grep -q '"\${BUNDLE_DIR}/setup.sh"' "$IMPORT_SRC" || { echo "FAIL: expected import.sh to reference \${BUNDLE_DIR}/setup.sh"; exit 1; }
echo "PASS"

echo "TEST: import.sh's usage comment names the real setup.sh flags, not a nonexistent --non-interactive"
if grep -q -- '--non-interactive' "$(dirname "$0")/import.sh"; then
  echo "FAIL: import.sh must not document a --non-interactive flag that setup.sh never parses"
  exit 1
fi
grep -q -- '--resume' "$(dirname "$0")/import.sh" || { echo "FAIL: expected import.sh to document --resume"; exit 1; }
grep -q -- '--reinstall' "$(dirname "$0")/import.sh" || { echo "FAIL: expected import.sh to document --reinstall"; exit 1; }
echo "PASS"

echo "ALL TESTS PASSED (import.sh, extended)"
