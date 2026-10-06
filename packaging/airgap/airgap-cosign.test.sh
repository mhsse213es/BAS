#!/usr/bin/env bash
# packaging/airgap/airgap-cosign.test.sh
#
# Proves import.sh / verify.sh fail CLOSED on the orchestrator cosign check and
# never reach `docker load` unless verification passes. cosign and docker are
# stubs on PATH (no real signing, no daemon); the fake cosign verify-blob
# succeeds only if the sha256 recorded in the .bundle matches the tar, so a
# tampered tar is genuinely rejected by the stub's logic.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# import.sh requires root. Test copy only: neutralise that one check.
mkdir -p "$T/tools"
sed 's/\$EUID -ne 0/0 -ne 0/' "$HERE/import.sh" > "$T/tools/import.sh"
cp "$HERE/verify.sh" "$HERE/cosign-verify-lib.sh" "$T/tools/"

STUBS="$T/stubs"; mkdir -p "$STUBS"
cat > "$STUBS/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "$STUB_LOG"
case "$1" in
  info|tag) exit 0 ;;
  images) echo "bas-orchestrator 9.9.9 abc123"; exit 0 ;;
  image) exit 1 ;;
  load) cat > /dev/null; exit 0 ;;
esac
EOF
cat > "$STUBS/cosign" <<'EOF'
#!/usr/bin/env bash
echo "cosign $*" >> "$STUB_LOG"
case "$1" in
  version) echo "GitVersion:    ${FAKE_COSIGN_VERSION:-v3.1.3}"; exit 0 ;;
  verify-blob)
    bundle=""; target="${*: -1}"
    while [ $# -gt 0 ]; do [ "$1" = "--bundle" ] && bundle="$2"; shift; done
    want=$(cat "$bundle"); got=$(sha256sum "$target" | cut -d' ' -f1)
    [ "$want" = "$got" ] || { echo "Error: invalid signature" >&2; exit 1; }
    exit 0 ;;
esac
EOF
chmod +x "$STUBS/docker" "$STUBS/cosign"
export STUB_LOG="$T/calls.log"

# Build a signed bundle tarball: $1 = name of the output tarball.
make_bundle() {
  local out="$1" b="$T/build/bas-airgap-9.9.9"
  rm -rf "$T/build"; mkdir -p "$b/images" "$b/compose"
  echo 9.9.9 > "$b/VERSION"
  echo fake-orchestrator-image > "$b/images/bas-orchestrator-9.9.9.tar"
  sha256sum "$b/images/bas-orchestrator-9.9.9.tar" | cut -d' ' -f1 > "$b/images/bas-orchestrator-9.9.9.tar.bundle"
  echo fake-postgres | gzip > "$b/images/postgres-16-alpine.tar.gz"
  echo fake-pub > "$b/cosign.pub"
  printf '#!/usr/bin/env bash\necho SETUP-RAN >> "$STUB_LOG"\n' > "$b/compose/setup.sh"
  for f in docker-compose.yml docker-compose.prod.yml; do : > "$b/compose/$f"; done
  : > "$b/import.sh"
  [ -n "${MUTATE:-}" ] && eval "$MUTATE"
  # Manifest regenerated AFTER mutation so only cosign (not the manifest) can catch it.
  (cd "$b" && find . -type f ! -name MANIFEST.sha256 | sort | while read -r f; do sha256sum "$f" | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/'; done) > "$b/MANIFEST.sha256"
  tar -czf "$out" -C "$T/build" bas-airgap-9.9.9
}

run_import() { # <tarball> ; uses PATH_OVERRIDE for the stub path
  : > "$STUB_LOG"
  PATH="${TEST_PATH}" bash "$T/tools/import.sh" "$1" --non-interactive > "$T/out.txt" 2>&1
}

FAILED=0
expect_abort() { # <name>
  local rc=0; run_import "$T/b.tar.gz" || rc=$?
  if [ "$rc" -eq 0 ]; then echo "FAIL: $1 -- import succeeded"; FAILED=1; return; fi
  if grep -q '^docker load' "$STUB_LOG"; then echo "FAIL: $1 -- docker load was reached"; FAILED=1; return; fi
  if grep -q SETUP-RAN "$STUB_LOG"; then echo "FAIL: $1 -- setup ran"; FAILED=1; return; fi
  echo "PASS: $1"
}

TEST_PATH="$STUBS:$PATH"

echo "TEST: valid bundle -> verified, loads orchestrator LAST, runs setup"
MUTATE="" make_bundle "$T/b.tar.gz"
rc=0; run_import "$T/b.tar.gz" || rc=$?
if [ "$rc" -ne 0 ]; then echo "FAIL: valid import rc=$rc"; cat "$T/out.txt"; FAILED=1
else
  [ "$(grep -c '^docker load' "$STUB_LOG")" -eq 2 ] && grep -q SETUP-RAN "$STUB_LOG" && grep -q 'verify-blob' "$STUB_LOG" \
    && echo "PASS: valid" || { echo "FAIL: valid -- expected verify-blob, 2 loads, setup"; cat "$STUB_LOG"; FAILED=1; }
fi

echo "TEST: tampered tarball -> abort before docker load"
MUTATE='echo evil >> "$b/images/bas-orchestrator-9.9.9.tar"' make_bundle "$T/b.tar.gz"
expect_abort "tampered tarball"
grep -q "verification FAILED" "$T/out.txt" || { echo "FAIL: tamper message missing"; FAILED=1; }

echo "TEST: missing .bundle -> abort"
MUTATE='rm "$b/images/bas-orchestrator-9.9.9.tar.bundle"' make_bundle "$T/b.tar.gz"
expect_abort "missing .bundle"

echo "TEST: legacy .tar.gz orchestrator, no .bundle -> refused as unsigned"
MUTATE='rm "$b/images/bas-orchestrator-9.9.9.tar" "$b/images/bas-orchestrator-9.9.9.tar.bundle"; echo x | gzip > "$b/images/bas-orchestrator-9.9.9.tar.gz"' make_bundle "$T/b.tar.gz"
expect_abort "legacy .tar.gz"
grep -q "legacy unsigned" "$T/out.txt" || { echo "FAIL: legacy message missing"; FAILED=1; }

echo "TEST: cosign too old -> abort"
MUTATE="" make_bundle "$T/b.tar.gz"
FAKE_COSIGN_VERSION=v3.0.2 expect_abort "cosign too old"
grep -q "too old" "$T/out.txt" || { echo "FAIL: too-old message missing"; FAILED=1; }

echo "TEST: cosign absent -> abort, message names offline install"
# PATH with every directory that provides a real cosign removed, plus docker stub only.
NOCOSIGN="$T/nocosign"; mkdir -p "$NOCOSIGN"; cp "$STUBS/docker" "$NOCOSIGN/docker"
CLEAN_PATH="$NOCOSIGN"
IFS=':' read -ra _dirs <<< "$PATH"
for d in "${_dirs[@]}"; do
  { [ -x "$d/cosign" ] || [ -x "$d/cosign.exe" ]; } || CLEAN_PATH="$CLEAN_PATH:$d"
done
TEST_PATH="$CLEAN_PATH" expect_abort "cosign absent"
grep -q "github.com/sigstore/cosign/releases" "$T/out.txt" || { echo "FAIL: offline-install hint missing"; FAILED=1; }
TEST_PATH="$STUBS:$PATH"

echo "TEST: verify.sh fails (cannot verify) when cosign is absent; passes when valid"
MUTATE="" make_bundle "$T/b.tar.gz"
rc=0; PATH="$CLEAN_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" > "$T/out.txt" 2>&1 || rc=$?
[ "$rc" -ne 0 ] && grep -q "Cannot verify signature" "$T/out.txt" && echo "PASS: verify.sh cosign absent" || { echo "FAIL: verify.sh cosign absent rc=$rc"; cat "$T/out.txt"; FAILED=1; }
rc=0; PATH="$TEST_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" > "$T/out.txt" 2>&1 || rc=$?
[ "$rc" -eq 0 ] && echo "PASS: verify.sh valid" || { echo "FAIL: verify.sh valid rc=$rc"; cat "$T/out.txt"; FAILED=1; }
MUTATE='echo evil >> "$b/images/bas-orchestrator-9.9.9.tar"' make_bundle "$T/b.tar.gz"
rc=0; PATH="$TEST_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" > "$T/out.txt" 2>&1 || rc=$?
[ "$rc" -ne 0 ] && echo "PASS: verify.sh tampered" || { echo "FAIL: verify.sh accepted tampered tar"; FAILED=1; }

[ "$FAILED" -eq 0 ] && echo "ALL PASS" || { echo "SOME FAILED"; exit 1; }
