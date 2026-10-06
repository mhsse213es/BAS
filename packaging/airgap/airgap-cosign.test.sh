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
  image) [ -n "${FAKE_LATEST_EXISTS:-}" ] && exit 0; exit 1 ;;
  load) cat > "$STUB_LOG.in"
        if gzip -t "$STUB_LOG.in" 2>/dev/null; then c=$(gzip -dc "$STUB_LOG.in"); else c=$(cat "$STUB_LOG.in"); fi
        echo "LOADED $c" >> "$STUB_LOG"; exit 0 ;;
esac
EOF
cat > "$STUBS/cosign" <<'EOF'
#!/usr/bin/env bash
echo "cosign $*" >> "$STUB_LOG"
case "$1" in
  version) echo "GitVersion:    ${FAKE_COSIGN_VERSION:-v3.1.3}"; exit 0 ;;
  verify-blob)
    bundle=""; key=""; target="${*: -1}"
    while [ $# -gt 0 ]; do [ "$1" = "--bundle" ] && bundle="$2"; [ "$1" = "--key" ] && key="$2"; shift; done
    want=$(cat "$bundle"); got="$(sha256sum "$target" | cut -d' ' -f1):$(cat "$key")"
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
  sha256sum "$b/images/bas-orchestrator-9.9.9.tar" | cut -d' ' -f1 | sed 's/$/:fake-pub/' > "$b/images/bas-orchestrator-9.9.9.tar.bundle"
  echo fake-postgres | gzip > "$b/images/postgres-16-alpine.tar.gz"
  echo fake-pub > "$b/cosign.pub"; echo fake-pub > "$b/compose/cosign.pub"; echo 9.9.9 > "$b/compose/VERSION"
  printf '#!/usr/bin/env bash\necho "PUBENV=${BAS_COSIGN_PUB:-}" >> "$STUB_LOG"; echo SETUP-RAN >> "$STUB_LOG"\n' > "$b/compose/setup.sh"
  for f in docker-compose.yml docker-compose.prod.yml; do : > "$b/compose/$f"; done
  : > "$b/import.sh"; cp "$HERE/cosign-verify-lib.sh" "$b/"
  [ -n "${MUTATE:-}" ] && eval "$MUTATE"
  # Manifest regenerated AFTER mutation so only cosign (not the manifest) can catch it.
  (cd "$b" && find . -type f ! -name MANIFEST.sha256 | sort | while read -r f; do sha256sum "$f" | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/'; done) > "$b/MANIFEST.sha256"
  tar -czf "$out" -C "$T/build" bas-airgap-9.9.9
}

run_import() { # <tarball> ; uses PATH_OVERRIDE for the stub path
  : > "$STUB_LOG"
  # shellcheck disable=SC2086
  PATH="${TEST_PATH}" bash "$T/tools/import.sh" "$1" --non-interactive ${IMPORT_EXTRA:-} > "$T/out.txt" 2>&1
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
check_valid() { # <label> ; asserts order: postgres load, orchestrator load, THEN tag latest from verified, THEN setup
  local rc=0; run_import "$T/b.tar.gz" || rc=$?
  if [ "$rc" -ne 0 ]; then echo "FAIL: $1 rc=$rc"; cat "$T/out.txt"; FAILED=1; return; fi
  local lines; lines=$(grep -n -E '^(LOADED|docker tag|SETUP-RAN|cosign verify-blob)' "$STUB_LOG" | sed 's/^[0-9]*://' | tr '
' '|')
  local want='cosign verify-blob --key '
  case "$lines" in
    "cosign verify-blob"*"|LOADED fake-postgres|LOADED fake-orchestrator-image|docker tag bas-orchestrator:9.9.9 bas-orchestrator:latest|SETUP-RAN|")
      echo "PASS: $1" ;;
    *) echo "FAIL: $1 -- wrong order: $lines"; FAILED=1 ;;
  esac
  : "$want"
}
MUTATE="" make_bundle "$T/b.tar.gz"
check_valid "valid: verify, postgres load, orchestrator load LAST, tag :latest from verified, then setup"
echo "TEST: pre-existing/planted :latest is overwritten, not trusted"
FAKE_LATEST_EXISTS=1 check_valid "valid with pre-existing :latest still re-tags unconditionally"

echo "TEST: bundle-shipped compose/cosign.pub that differs -> abort"
MUTATE='echo other > "$b/compose/cosign.pub"' make_bundle "$T/b.tar.gz"
rc=0; run_import "$T/b.tar.gz" || rc=$?
{ [ "$rc" -ne 0 ] && ! grep -q SETUP-RAN "$STUB_LOG" && echo "PASS: compose/cosign.pub mismatch"; } || { echo "FAIL: pub mismatch accepted"; FAILED=1; }

echo "TEST: out-of-band cosign key"
printf 'fake-pub' > "$T/ext-good.pub"; printf 'other-pub' > "$T/ext-bad.pub"
GOODFP=$(sha256sum "$T/ext-good.pub" | cut -d' ' -f1)
MUTATE="" make_bundle "$T/b.tar.gz"
check_valid "no external key (bundled)"
if grep -q "BUNDLED key, sha256:" "$T/out.txt" && ! grep -q '^PUBENV=.' "$STUB_LOG"; then echo "PASS: bundled fingerprint printed, no env export"; else echo "FAIL: bundled-key behaviour"; FAILED=1; fi
IMPORT_EXTRA="--cosign-pub $T/ext-good.pub" check_valid "external key matches"
if grep -q "Verifying with EXTERNAL key, sha256: ${GOODFP}" "$T/out.txt" && grep -q "PUBENV=.*ext-good.pub" "$STUB_LOG"; then echo "PASS: external fingerprint printed, setup.sh handed the key"; else echo "FAIL: external key output/handoff"; FAILED=1; fi
IMPORT_EXTRA="--cosign-pub $T/ext-bad.pub" expect_abort "external key differs from signing key (bundled key would pass)"
if grep -q "EXTERNAL key" "$T/out.txt" && grep -q "DIFFERS" "$T/out.txt"; then echo "PASS: mismatch warned"; else echo "FAIL: mismatch output"; FAILED=1; fi
IMPORT_EXTRA="--cosign-pub $T/nope.pub" expect_abort "external key path missing (flag)"
BAS_COSIGN_PUB="$T/nope.pub" expect_abort "external key path missing (env)"
BAS_COSIGN_PUB="$T/ext-bad.pub" IMPORT_EXTRA="--cosign-pub $T/ext-good.pub" check_valid "flag (good) beats env (bad)"
BAS_COSIGN_PUB="$T/ext-good.pub" IMPORT_EXTRA="--cosign-pub $T/ext-bad.pub" expect_abort "flag (bad) beats env (good)"
BAS_COSIGN_PUB="$T/ext-bad.pub" expect_abort "env (bad) beats bundled (good)"
BAS_COSIGN_PUB="$T/ext-good.pub" check_valid "env (good) without flag"
rc=0; PATH="$TEST_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" --cosign-pub "$T/ext-bad.pub" > "$T/out.txt" 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then echo "PASS: verify.sh external key differs -> fail"; else echo "FAIL: verify.sh accepted wrong external key"; FAILED=1; fi
rc=0; PATH="$TEST_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" --cosign-pub "$T/ext-good.pub" > "$T/out.txt" 2>&1 || rc=$?
if [ "$rc" -eq 0 ] && grep -q "EXTERNAL key" "$T/out.txt"; then echo "PASS: verify.sh external key ok"; else echo "FAIL: verify.sh external key"; FAILED=1; fi

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
[ "$rc" -ne 0 ] && grep -q "verification FAILED" "$T/out.txt" && echo "PASS: verify.sh tampered (cosign reason)" || { echo "FAIL: verify.sh accepted tampered tar"; FAILED=1; }

echo "TEST: ISO post-install.sh and packer install-bas.sh refuse a legacy orchestrator tar.gz BEFORE any docker load"
MUTATE='rm "$b/images/bas-orchestrator-9.9.9.tar" "$b/images/bas-orchestrator-9.9.9.tar.bundle"; echo x | gzip > "$b/images/bas-orchestrator-9.9.9.tar.gz"' make_bundle "$T/legacy.tar.gz"
REPO="$HERE/../.."
mkdir -p "$T/pi"
sed -e "s|^LOG=.*|LOG=\"$T/pi/log\"|" -e "s|^STAGING=.*|STAGING=\"$T/pi/staging\"|"     -e "s|^DONE_MARKER=.*|DONE_MARKER=\"$T/pi/done\"|" -e "s|^AIRGAP_BUNDLE=.*|AIRGAP_BUNDLE=\"$T/legacy.tar.gz\"|"     "$REPO/packaging/iso/autoinstall/scripts/post-install.sh" > "$T/pi/post-install.sh"
sed -e "s|^BUNDLE=.*|BUNDLE=\"$T/legacy.tar.gz\"|" -e "s|^STAGING_DIR=.*|STAGING_DIR=\"$T/pi/stg2\"|"     "$REPO/packaging/packer/scripts/install-bas.sh" > "$T/pi/install-bas.sh"
for sc in post-install install-bas; do
  : > "$STUB_LOG"; rc=0
  PATH="$STUBS:$PATH" bash "$T/pi/$sc.sh" > "$T/out.txt" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] && ! grep -q '^docker load' "$STUB_LOG" && { grep -q "legacy unsigned" "$T/out.txt" || grep -q "legacy unsigned" "$T/pi/log" 2>/dev/null; }; then
    echo "PASS: $sc refuses legacy tar.gz before load"
  else echo "FAIL: $sc rc=$rc"; cat "$STUB_LOG"; FAILED=1; fi
done

echo "TEST: GPG key selection (real throwaway keys)"
if ! command -v gpg >/dev/null 2>&1; then
  echo "SKIP: gpg not available"
else
  export GNUPGHOME="$T/gnupg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "A <a@test.invalid>" default default never >/dev/null 2>&1
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "B <b@test.invalid>" default default never >/dev/null 2>&1
  gpg --armor --export a@test.invalid > "$T/gpg-a.asc"; gpg --armor --export b@test.invalid > "$T/gpg-b.asc"
  FPA=$(gpg --with-colons --list-keys a@test.invalid | awk -F: '/^fpr/{print $10; exit}')
  MUTATE="" make_bundle "$T/b.tar.gz"
  rm -f "$T/b.tar.gz.asc"; gpg --batch --pinentry-mode loopback --passphrase '' -u a@test.invalid --detach-sign --armor -o "$T/b.tar.gz.asc" "$T/b.tar.gz"
  cp "$HERE/../signing/verify-sig.sh" "$T/tools/"; cp "$T/gpg-a.asc" "$T/tools/pubkey.asc"   # bundled key = A (signer)
  vs() { PATH="$TEST_PATH" bash "$T/tools/verify-sig.sh" "$T/b.tar.gz" "$@" > "$T/out.txt" 2>&1; }
  gok() { local rc=0; "$@" || rc=$?; [ "$rc" -eq 0 ]; }
  if gok vs && grep -q "BUNDLED GPG key, fingerprint: ${FPA}" "$T/out.txt" && grep -q "integrity, not origin" "$T/out.txt"; then echo "PASS: bundled GPG key: fingerprint + origin warning"; else echo "FAIL: bundled GPG"; cat "$T/out.txt"; FAILED=1; fi
  if gok vs --gpg-pub "$T/gpg-a.asc" && grep -q "EXTERNAL GPG key, fingerprint: ${FPA}" "$T/out.txt"; then echo "PASS: external GPG key matches"; else echo "FAIL: external GPG match"; FAILED=1; fi
  if gok vs --gpg-pub "$T/gpg-b.asc"; then echo "FAIL: mismatching external GPG key accepted"; FAILED=1; else echo "PASS: external GPG key mismatch fails (bundled would pass)"; fi
  if gok vs --gpg-pub "$T/nope.asc"; then echo "FAIL: missing GPG path accepted"; FAILED=1; else echo "PASS: missing GPG path aborts"; fi
  if BAS_GPG_PUB="$T/gpg-b.asc" gok vs --gpg-pub "$T/gpg-a.asc"; then echo "PASS: GPG flag beats env"; else echo "FAIL: GPG flag/env precedence"; FAILED=1; fi
  if BAS_GPG_PUB="$T/gpg-a.asc" gok vs --gpg-pub "$T/gpg-b.asc"; then echo "FAIL: GPG flag(bad) lost to env(good)"; FAILED=1; else echo "PASS: GPG flag(bad) beats env(good)"; fi
  if BAS_GPG_PUB="$T/gpg-b.asc" gok vs; then echo "FAIL: GPG env(bad) lost to bundled(good)"; FAILED=1; else echo "PASS: GPG env beats bundled"; fi
  # import.sh / verify.sh pass the key through and abort before docker load on mismatch
  IMPORT_EXTRA="--gpg-pub $T/gpg-b.asc" expect_abort "import.sh: external GPG mismatch"
  IMPORT_EXTRA="--gpg-pub $T/gpg-a.asc" check_valid "import.sh: external GPG match"
  rc=0; PATH="$TEST_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" --gpg-pub "$T/gpg-b.asc" > "$T/out.txt" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then echo "PASS: verify.sh external GPG mismatch fails"; else echo "FAIL: verify.sh accepted wrong GPG key"; FAILED=1; fi
  rc=0; PATH="$TEST_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" --gpg-pub "$T/gpg-a.asc" > "$T/out.txt" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then echo "PASS: verify.sh external GPG ok"; else echo "FAIL: verify.sh external GPG"; cat "$T/out.txt"; FAILED=1; fi
  # gpg-agent is auto-spawned per GNUPGHOME and would otherwise outlive the test holding its pipes
  gpgconf --kill all >/dev/null 2>&1 || true
  rm -f "$T/b.tar.gz.asc" "$T/tools/verify-sig.sh" "$T/tools/pubkey.asc"
fi

echo "TEST: fetch-cosign.sh --verify enforces the pinned checksum"
printf 'fake-cosign' > "$T/cos.bin"
printf 'COSIGN_VERSION=v3.1.3
COSIGN_SHA256_LINUX_AMD64=%s
' "$(sha256sum "$T/cos.bin" | cut -d' ' -f1)" > "$T/ok.pin"
printf 'COSIGN_VERSION=v3.0.2
COSIGN_SHA256_LINUX_AMD64=%s
' "$(sha256sum "$T/cos.bin" | cut -d' ' -f1)" > "$T/old.pin"
if bash "$REPO/packaging/appliance/fetch-cosign.sh" --verify "$T/cos.bin" "$T/ok.pin" >/dev/null 2>&1; then echo "PASS: matching checksum accepted"; else echo "FAIL: good checksum rejected"; FAILED=1; fi
if bash "$REPO/packaging/appliance/fetch-cosign.sh" --verify "$T/cos.bin" "$T/old.pin" >/dev/null 2>&1; then echo "FAIL: pin < v3.1.0 accepted"; FAILED=1; else echo "PASS: pin older than v3.1.0 rejected"; fi
printf 'tampered' > "$T/cos.bin"
if bash "$REPO/packaging/appliance/fetch-cosign.sh" --verify "$T/cos.bin" "$T/ok.pin" >/dev/null 2>&1; then echo "FAIL: tampered cosign accepted"; FAILED=1; else [ ! -e "$T/cos.bin" ] && echo "PASS: checksum mismatch rejected and file removed"; fi

[ "$FAILED" -eq 0 ] && echo "ALL PASS" || { echo "SOME FAILED"; exit 1; }
