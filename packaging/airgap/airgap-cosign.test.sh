#!/usr/bin/env bash
# packaging/airgap/airgap-cosign.test.sh
#
# Proves the air-gap flow (pack output -> verify.sh / import.sh -> setup.sh
# --offline, ISO post-install, Packer install-bas, install.sh) fails CLOSED:
# no image tar reaches `docker load` unless it carries a valid cosign signature
# made by the selected key AND its manifest carries exactly the expected tag, and
# after load the tag must resolve to the manifest's image ID. GPG key handling
# (verify-sig.sh, setup.sh agent check) is tested with REAL throwaway keys.
#
# cosign and docker are stubs on PATH (no real signing, no daemon):
#  - fake cosign verify-blob succeeds only if the .bundle's "<tar sha256>:<key>"
#    matches the tar and the key file it is given, so tampered tars and wrong
#    keys are genuinely rejected by the stub's logic;
#  - fake docker models tags -> image IDs from each loaded tar's manifest.json
#    (last load wins, like the real daemon), so planted/clobbered tags are real.
# NOT covered here: a real `cosign sign-blob` / `docker save` round trip.
set -euo pipefail
[ -z "${T_DEBUG:-}" ] || set -x
unset CDPATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$HERE/../.."
T="$(mktemp -d)"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$T"' EXIT

# ── Never touch the host: snapshot the real system paths the scripts could write ──
snap() { { ls -ld /usr/local/bin/cosign /var/tmp/bas-appliance /var/tmp/bas-airgap.tar.gz /opt/bas-platform-src /opt/bas-install 2>&1 || true; } | md5sum; }
HOST_SNAP="$(snap)"

# import.sh requires root. Test copy only: neutralise that one check.
mkdir -p "$T/tools"
sed 's/\$EUID -ne 0/0 -ne 0/' "$HERE/import.sh" > "$T/tools/import.sh"
cp "$HERE/verify.sh" "$HERE/cosign-verify-lib.sh" "$T/tools/"

export STUB_LOG="$T/calls.log"
export DOCKER_STATE="$T/dstate"
STUBS="$T/stubs"; mkdir -p "$STUBS"
cat > "$STUBS/docker" <<'EOF'
#!/usr/bin/env bash
S="$DOCKER_STATE"; mkdir -p "$S"
k() { echo "$1" | tr '/:' '__'; }
echo "docker $*" >> "$STUB_LOG"
case "$1" in
  info) exit 0 ;;
  images) echo "bas-orchestrator 9.9.9 abc123"; exit 0 ;;
  tag) f="$S/tag.$(k "$2")"; [ -f "$f" ] || exit 1; cp "$f" "$S/tag.$(k "$3")"; exit 0 ;;
  image) shift 2; fmt=0; [ "$1" = "-f" ] && { fmt=1; shift 2; }
         f="$S/tag.$(k "$1")"; [ -f "$f" ] || exit 1; [ "$fmt" = 1 ] && cat "$f"; exit 0 ;;
  load) cat > "$S/in"
        if gzip -t "$S/in" 2>/dev/null; then gzip -dc "$S/in" > "$S/in.tar"; else cp "$S/in" "$S/in.tar"; fi
        m=$(tar -xOf "$S/in.tar" manifest.json 2>/dev/null) || { echo "Error: not a docker image" >&2; exit 1; }
        tags=$(sed -n 's/.*"RepoTags":\[\([^]]*\)\].*/\1/p' <<<"$m" | tr -d '"' | tr ',' ' ')
        cfg=$(sed -n 's/.*"Config":"\([^"]*\)".*/\1/p' <<<"$m"); cfg="${cfg##*/}"
        for t in $tags; do
          id="sha256:$cfg"
          if [ -n "${FAKE_DOCKER_CLOBBER:-}" ] && [[ "$t" == bas-orchestrator:* ]]; then id="sha256:$(printf 'f%.0s' $(seq 64))"; fi
          echo "$id" > "$S/tag.$(k "$t")"
        done
        echo "LOADED $tags" >> "$STUB_LOG"; exit 0 ;;
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
cat > "$STUBS/curl" <<'EOF'
#!/usr/bin/env bash
out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
[ -n "${STUB_CURL_SRC:-}" ] && [ -f "$STUB_CURL_SRC" ] || exit 22
cp "$STUB_CURL_SRC" "$out"
EOF
chmod +x "$STUBS/docker" "$STUBS/cosign" "$STUBS/curl"

# ── Image / bundle builders ────────────────────────────────────────────────────
mk_image_tar() { # <out> <quoted,comma,separated RepoTags> <config seed>
  local d="$T/imgtmp" hex; rm -rf "$d"; mkdir -p "$d"
  hex=$(printf '%s' "$3" | sha256sum | cut -d' ' -f1)
  printf '[{"Config":"blobs/sha256/%s","RepoTags":[%s],"Layers":[]}]' "$hex" "$2" > "$d/manifest.json"
  tar -cf "$1" -C "$d" manifest.json
}
img_id() { echo "sha256:$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"; }
sign_tar() { echo "$(sha256sum "$1" | cut -d' ' -f1):${2:-fake-pub}" > "$1.bundle"; }

# Build a signed bundle tarball ($1 = output). MUTATE (eval'd, may use $b) tweaks it
# AFTER signing; the manifest is regenerated after, so only cosign/identity checks can catch it.
make_bundle() {
  local out="$1" b="$T/build/bas-airgap-9.9.9"
  rm -rf "$T/build"; mkdir -p "$b/images" "$b/compose"
  echo 9.9.9 > "$b/VERSION"
  mk_image_tar "$b/images/bas-orchestrator-9.9.9.tar" '"bas-orchestrator:9.9.9"' orch; sign_tar "$b/images/bas-orchestrator-9.9.9.tar" "${SIGN_KEY:-fake-pub}"
  mk_image_tar "$b/images/postgres-16-alpine.tar" '"postgres:16-alpine"' pg;          sign_tar "$b/images/postgres-16-alpine.tar" "${SIGN_KEY:-fake-pub}"
  printf '%s' "${BUNDLED_PUB:-fake-pub}" > "$b/cosign.pub"; cp "$b/cosign.pub" "$b/compose/cosign.pub"; echo 9.9.9 > "$b/compose/VERSION"
  printf '#!/usr/bin/env bash\necho "PUBENV=${BAS_COSIGN_PUB:-}" >> "$STUB_LOG"; echo "GPGENV=${BAS_GPG_PUB:-}" >> "$STUB_LOG"; echo "STRICT=${BAS_REQUIRE_SIGNED_IMAGES:-}" >> "$STUB_LOG"; echo SETUP-RAN >> "$STUB_LOG"\n' > "$b/compose/setup.sh"
  for f in docker-compose.yml docker-compose.prod.yml; do : > "$b/compose/$f"; done
  : > "$b/import.sh"; cp "$HERE/cosign-verify-lib.sh" "$b/"
  [ -n "${MUTATE:-}" ] && eval "$MUTATE"
  (cd "$b" && find . -type f ! -name MANIFEST.sha256 | sort | xargs sha256sum | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/') > "$b/MANIFEST.sha256"
  tar -czf "$out" -C "$T/build" bas-airgap-9.9.9
}

TEST_PATH="$STUBS:$PATH"
# PATH with every directory that provides a real cosign removed, plus the stubs but NO cosign stub.
NOCOSIGN="$T/nocosign"; mkdir -p "$NOCOSIGN"; cp "$STUBS/docker" "$STUBS/curl" "$NOCOSIGN/"
CLEAN_PATH="$NOCOSIGN"
IFS=':' read -ra _dirs <<< "$PATH"
for d in "${_dirs[@]}"; do
  { [ -x "$d/cosign" ] || [ -x "$d/cosign.exe" ]; } || CLEAN_PATH="$CLEAN_PATH:$d"
done

run_import() { # <tarball>
  : > "$STUB_LOG"; rm -rf "$DOCKER_STATE"; mkdir -p "$DOCKER_STATE"
  [ -n "${FAKE_LATEST_EXISTS:-}" ] && echo "sha256:old" > "$DOCKER_STATE/tag.bas-orchestrator_latest"
  # shellcheck disable=SC2086
  PATH="${TEST_PATH}" bash "$T/tools/import.sh" "$1" --non-interactive ${IMPORT_EXTRA:-} > "$T/out.txt" 2>&1
}

FAILED=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }
expect_abort() { # <name>  (import must fail, load NOTHING, never reach setup)
  local rc=0; run_import "$T/b.tar.gz" || rc=$?
  if [ "$rc" -eq 0 ]; then fail "$1 -- import succeeded"; return; fi
  if grep -q '^LOADED' "$STUB_LOG"; then fail "$1 -- an image was loaded"; return; fi
  if grep -q SETUP-RAN "$STUB_LOG"; then fail "$1 -- setup ran"; return; fi
  pass "$1"
}
check_valid() { # <label>  (verify, postgres load, orchestrator load LAST, :latest from verified, then setup)
  local rc=0; run_import "$T/b.tar.gz" || rc=$?
  if [ "$rc" -ne 0 ]; then fail "$1 rc=$rc"; cat "$T/out.txt"; return; fi
  local seq firstload lastverify
  seq=$(grep -E '^(LOADED|docker tag|SETUP-RAN)' "$STUB_LOG" | tr '\n' '|')
  firstload=$(grep -n '^LOADED' "$STUB_LOG" | head -1 | cut -d: -f1)
  lastverify=$(grep -n '^cosign verify-blob' "$STUB_LOG" | tail -1 | cut -d: -f1)
  if [ "$seq" != "LOADED postgres:16-alpine|LOADED bas-orchestrator:9.9.9|docker tag bas-orchestrator:9.9.9 bas-orchestrator:latest|SETUP-RAN|" ]; then
    fail "$1 -- wrong order: $seq"; return
  fi
  if [ "$(grep -c '^cosign verify-blob' "$STUB_LOG")" -ne 2 ] || [ "$lastverify" -gt "$firstload" ]; then
    fail "$1 -- both images must be verified before the first load"; return
  fi
  if [ "$(cat "$DOCKER_STATE/tag.bas-orchestrator_latest")" != "$(img_id orch)" ]; then
    fail "$1 -- :latest does not point at the verified orchestrator image"; return
  fi
  pass "$1"
}

echo "TEST: valid bundle -> every image verified first, postgres then orchestrator loaded, :latest re-tagged from the verified image, then setup"
MUTATE="" make_bundle "$T/b.tar.gz"
check_valid "valid bundle"
grep -q "^STRICT=1" "$STUB_LOG" && pass "setup.sh told to require signed images" || fail "BAS_REQUIRE_SIGNED_IMAGES not exported"
echo "TEST: a pre-existing/planted :latest is overwritten, not trusted"
FAKE_LATEST_EXISTS=1 check_valid "pre-existing :latest re-tagged unconditionally"

echo "TEST: bundle-shipped compose/cosign.pub that differs -> abort"
MUTATE='echo other > "$b/compose/cosign.pub"' make_bundle "$T/b.tar.gz"; expect_abort "compose/cosign.pub mismatch"

echo "TEST: stale compose/VERSION (compose would run another tag) -> abort"
MUTATE='echo 9.9.8 > "$b/compose/VERSION"' make_bundle "$T/b.tar.gz"; expect_abort "stale compose/VERSION"

echo "TEST: every image tar is signed and verified"
MUTATE='echo evil >> "$b/images/bas-orchestrator-9.9.9.tar"' make_bundle "$T/b.tar.gz"; expect_abort "tampered orchestrator tar"
grep -q "verification FAILED" "$T/out.txt" && pass "tamper reason reported" || fail "tamper message missing"
MUTATE='echo evil >> "$b/images/postgres-16-alpine.tar"' make_bundle "$T/b.tar.gz"; expect_abort "tampered postgres tar (nothing loaded, not even the orchestrator)"
MUTATE='rm "$b/images/postgres-16-alpine.tar.bundle"' make_bundle "$T/b.tar.gz"; expect_abort "missing postgres .bundle"
MUTATE='rm "$b/images/bas-orchestrator-9.9.9.tar.bundle"' make_bundle "$T/b.tar.gz"; expect_abort "missing orchestrator .bundle"
MUTATE='echo x > "$b/images/extra.tar"; sign_tar "$b/images/extra.tar"' make_bundle "$T/b.tar.gz"; expect_abort "extra (even signed) unlisted tar in images/ is refused (fail closed)"
MUTATE='echo x > "$b/images/extra.tar"' make_bundle "$T/b.tar.gz"; expect_abort "extra unsigned tar in images/ is refused (fail closed)"
MUTATE='rm "$b/images/postgres-16-alpine.tar" "$b/images/postgres-16-alpine.tar.bundle"; echo x | gzip > "$b/images/postgres-16-alpine.tar.gz"' make_bundle "$T/b.tar.gz"; expect_abort "legacy postgres .tar.gz"
MUTATE='rm "$b/images/bas-orchestrator-9.9.9.tar" "$b/images/bas-orchestrator-9.9.9.tar.bundle"; echo x | gzip > "$b/images/bas-orchestrator-9.9.9.tar.gz"' make_bundle "$T/b.tar.gz"; expect_abort "legacy orchestrator .tar.gz"
grep -q "legacy unsigned\|Unexpected file" "$T/out.txt" && pass "legacy refusal reported" || fail "legacy message missing"

echo "TEST: image identity -- the verified tar must carry exactly the expected tag"
MUTATE='mk_image_tar "$b/images/postgres-16-alpine.tar" "\"postgres:15\"" pg; sign_tar "$b/images/postgres-16-alpine.tar"' make_bundle "$T/b.tar.gz"; expect_abort "postgres tar with wrong RepoTags (genuinely signed)"
MUTATE='mk_image_tar "$b/images/postgres-16-alpine.tar" "\"postgres:16-alpine\",\"bas-orchestrator:9.9.9\"" pg; sign_tar "$b/images/postgres-16-alpine.tar"' make_bundle "$T/b.tar.gz"; expect_abort "bas-orchestrator:<v> planted inside the postgres tar"
MUTATE='mk_image_tar "$b/images/bas-orchestrator-9.9.9.tar" "\"bas-orchestrator:9.9.8\"" older; sign_tar "$b/images/bas-orchestrator-9.9.9.tar"' make_bundle "$T/b.tar.gz"; expect_abort "older genuinely-signed tar renamed to a newer version"
MUTATE="" make_bundle "$T/b.tar.gz"
rc=0; FAKE_DOCKER_CLOBBER=1 run_import "$T/b.tar.gz" || rc=$?
if [ "$rc" -ne 0 ] && ! grep -q SETUP-RAN "$STUB_LOG" && grep -q "not the verified image after load" "$T/out.txt"; then pass "daemon resolving the orchestrator tag to a different image ID after load aborts before setup"; else fail "post-load ID mismatch not caught (rc=$rc)"; fi

echo "TEST: out-of-band cosign key governs EVERY image"
printf 'fake-pub' > "$T/ext-good.pub"; printf 'other-pub' > "$T/ext-bad.pub"; printf 'ext-pub' > "$T/ext-only.pub"
GOODFP=$(sha256sum "$T/ext-good.pub" | cut -d' ' -f1)
MUTATE="" make_bundle "$T/b.tar.gz"
check_valid "no external key (bundled)"
if grep -q "BUNDLED key, sha256:" "$T/out.txt" && ! grep -q '^PUBENV=.' "$STUB_LOG"; then pass "bundled fingerprint printed, no env export"; else fail "bundled-key behaviour"; fi
IMPORT_EXTRA="--cosign-pub $T/ext-good.pub" check_valid "external key matches"
if grep -q "Verifying with EXTERNAL key, sha256: ${GOODFP}" "$T/out.txt" && grep -q "PUBENV=.*ext-good.pub" "$STUB_LOG"; then pass "external fingerprint printed, setup.sh handed the key"; else fail "external key output/handoff"; fi
IMPORT_EXTRA="--cosign-pub=$T/ext-good.pub" check_valid "--cosign-pub=<path> form"
IMPORT_EXTRA="--cosign-pub $T/ext-bad.pub" expect_abort "external key differs from signing key (bundled key would pass)"
if grep -q "EXTERNAL key" "$T/out.txt" && grep -q "DIFFERS" "$T/out.txt"; then pass "mismatch warned"; else fail "mismatch output"; fi
IMPORT_EXTRA="--cosign-pub $T/nope.pub" expect_abort "external key path missing (flag)"
BAS_COSIGN_PUB="$T/nope.pub" expect_abort "external key path missing (env)"
BAS_COSIGN_PUB="$T/ext-bad.pub" IMPORT_EXTRA="--cosign-pub $T/ext-good.pub" check_valid "flag (good) beats env (bad)"
BAS_COSIGN_PUB="$T/ext-good.pub" IMPORT_EXTRA="--cosign-pub $T/ext-bad.pub" expect_abort "flag (bad) beats env (good)"
BAS_COSIGN_PUB="$T/ext-bad.pub" expect_abort "env (bad) beats bundled (good)"
BAS_COSIGN_PUB="$T/ext-good.pub" check_valid "env (good) without flag"
# both images signed ONLY by the external key; the bundled key would fail both
SIGN_KEY=ext-pub MUTATE="" make_bundle "$T/b.tar.gz"
expect_abort "bundled key rejects images signed by the external key"
IMPORT_EXTRA="--cosign-pub $T/ext-only.pub" check_valid "external key verifies BOTH orchestrator and postgres"
# postgres signed by a different key than the orchestrator -> external key must reject it
MUTATE='sign_tar "$b/images/postgres-16-alpine.tar" other-pub' make_bundle "$T/b.tar.gz"
IMPORT_EXTRA="--cosign-pub $T/ext-good.pub" expect_abort "external key matches orchestrator but NOT postgres"

echo "TEST: unknown import.sh flags are rejected (a key flag can never be silently dropped)"
MUTATE="" make_bundle "$T/b.tar.gz"
IMPORT_EXTRA="--cosgn-pub $T/ext-good.pub" expect_abort "typo'd key flag rejected"
IMPORT_EXTRA="--bogus" expect_abort "unknown flag rejected"
IMPORT_EXTRA="--config $T/x.conf --no-wizard" check_valid "allowlisted pass-through flags accepted"

echo "TEST: verify.sh"
vsh() { PATH="$1" bash "$T/tools/verify.sh" "$T/b.tar.gz" "${@:2}" > "$T/out.txt" 2>&1; }
MUTATE="" make_bundle "$T/b.tar.gz"
rc=0; vsh "$CLEAN_PATH" || rc=$?
if [ "$rc" -ne 0 ] && grep -q "Cannot verify signature" "$T/out.txt"; then pass "verify.sh: cosign absent is a FAILURE (cannot verify)"; else fail "verify.sh cosign absent rc=$rc"; fi
rc=0; vsh "$TEST_PATH" || rc=$?; [ "$rc" -eq 0 ] && pass "verify.sh: valid bundle" || { fail "verify.sh valid rc=$rc"; cat "$T/out.txt"; }
MUTATE='echo evil >> "$b/images/postgres-16-alpine.tar"' make_bundle "$T/b.tar.gz"
rc=0; vsh "$TEST_PATH" || rc=$?
if [ "$rc" -ne 0 ] && grep -q "verification FAILED" "$T/out.txt"; then pass "verify.sh: tampered POSTGRES tar rejected (cosign reason)"; else fail "verify.sh accepted tampered postgres tar"; fi
MUTATE='rm "$b/images/postgres-16-alpine.tar.bundle"' make_bundle "$T/b.tar.gz"
rc=0; vsh "$TEST_PATH" || rc=$?; [ "$rc" -ne 0 ] && pass "verify.sh: missing postgres .bundle rejected" || fail "verify.sh accepted missing postgres .bundle"
MUTATE='echo 9.9.8 > "$b/compose/VERSION"' make_bundle "$T/b.tar.gz"
rc=0; vsh "$TEST_PATH" || rc=$?; [ "$rc" -ne 0 ] && pass "verify.sh: stale compose/VERSION rejected" || fail "verify.sh accepted stale compose/VERSION"
MUTATE="" make_bundle "$T/b.tar.gz"
rc=0; vsh "$TEST_PATH" --cosign-pub "$T/ext-bad.pub" || rc=$?; [ "$rc" -ne 0 ] && pass "verify.sh: external key differs -> fail" || fail "verify.sh accepted wrong external key"
rc=0; vsh "$TEST_PATH" --cosign-pub="$T/ext-good.pub" || rc=$?
if [ "$rc" -eq 0 ] && grep -q "EXTERNAL key" "$T/out.txt"; then pass "verify.sh: --cosign-pub=<path> ok"; else fail "verify.sh external key"; fi

echo "TEST: compose/install.sh and setup.sh (functions extracted from the real files)"
extract_fn() { awk -v n="$2" '$0 ~ "^"n"\\(\\) \\{" {p=1} p{print} p && /^}/ {exit}' "$1"; }
INST="$REPO/packaging/compose/install.sh"; SETUP="$REPO/packaging/compose/setup.sh"
{ for fn in _key_fp _tar_image_id _docker_tag_is _cosign_version_ok _resolve_cosign_pub _verify_orchestrator_artifact; do extract_fn "$INST" "$fn"; done; } > "$T/inst-fns.sh"
{ for fn in _key_fp _tar_image_id _docker_tag_is _cosign_version_ok _verify_orchestrator_artifact _expected_image_tag _verify_all_images; do extract_fn "$SETUP" "$fn"; done; } > "$T/setup-fns.sh"

IB="$T/instbundle"; rm -rf "$IB"; mkdir -p "$IB"
mk_image_tar "$IB/o.tar" '"bas-orchestrator:9.9.9"' orch; sign_tar "$IB/o.tar"
printf 'fake-pub' > "$IB/cosign.pub"
run_inst() { # key selection via COSIGN_PUB_FLAG / BAS_COSIGN_PUB in the caller's env
  PATH="$STUBS:$PATH" bash -c '
    err() { echo "ERR: $*" >&2; }; warn() { echo "WARN: $*"; }; info() { echo "$*"; }; log() { echo "$*"; }
    SCRIPT_DIR="$1"; COSIGN_PUB_FLAG="${COSIGN_PUB_FLAG:-}"; COSIGN_PUB_USED="$1/cosign.pub"
    source "$2"
    _resolve_cosign_pub || exit 3
    _verify_orchestrator_artifact "$1/o.tar"' _ "$IB" "$T/inst-fns.sh" > "$T/out.txt" 2>&1
}
inst_ok() { local rc=0; run_inst || rc=$?; [ "$rc" -eq 0 ]; }
if inst_ok && grep -q "BUNDLED key, sha256:" "$T/out.txt"; then pass "install.sh default (bundled key) unchanged + fingerprint"; else fail "install.sh default"; cat "$T/out.txt"; fi
if COSIGN_PUB_FLAG="$T/ext-good.pub" inst_ok && grep -q "Verifying with EXTERNAL key, sha256: ${GOODFP}" "$T/out.txt"; then pass "install.sh external key matches"; else fail "install.sh external match"; cat "$T/out.txt"; fi
if COSIGN_PUB_FLAG="$T/ext-bad.pub" inst_ok; then fail "install.sh accepted mismatching external key"; elif grep -q "DIFFERS" "$T/out.txt"; then pass "install.sh mismatching external key fails (bundled would pass) + warning"; else fail "install.sh mismatch output"; fi
if COSIGN_PUB_FLAG="$T/nope.pub" inst_ok; then fail "install.sh missing path accepted"; else pass "install.sh missing external path aborts"; fi
if BAS_COSIGN_PUB="$T/ext-bad.pub" inst_ok; then fail "install.sh env(bad) lost to bundled"; else pass "install.sh env beats bundled"; fi
if BAS_COSIGN_PUB="$T/ext-bad.pub" COSIGN_PUB_FLAG="$T/ext-good.pub" inst_ok; then pass "install.sh flag beats env"; else fail "install.sh flag/env"; fi
if BAS_COSIGN_PUB="$T/ext-good.pub" COSIGN_PUB_FLAG="$T/ext-bad.pub" inst_ok; then fail "install.sh flag(bad) lost to env(good)"; else pass "install.sh flag(bad) beats env(good)"; fi
grep -q -- '--cosign-pub <key.pub>' "$INST" && pass "install.sh usage lists --cosign-pub" || fail "install.sh usage text"
grep -q -- '--cosign-pub=\*' "$INST" && pass "install.sh accepts --cosign-pub=<path>" || fail "install.sh = form"
# image identity helpers (shared text in install.sh and setup.sh)
for F in "$T/inst-fns.sh" "$T/setup-fns.sh"; do
  n=$(basename "$F" -fns.sh)
  id=$(bash -c 'source "$1"; _tar_image_id "$2" "bas-orchestrator:9.9.9"' _ "$F" "$IB/o.tar" 2>/dev/null) || id=""
  [ "$id" = "$(img_id orch)" ] && pass "$n: _tar_image_id returns the manifest Config digest" || fail "$n: _tar_image_id ($id)"
  if bash -c 'source "$1"; _tar_image_id "$2" "bas-orchestrator:9.9.8"' _ "$F" "$IB/o.tar" >/dev/null 2>&1; then fail "$n: wrong expected tag accepted"; else pass "$n: tag mismatch refused"; fi
done

# setup.sh --offline: _verify_all_images over an extracted bundle's compose/ dir
run_setup_verify() { # <env assignments...> uses $SX as SCRIPT_DIR
  env "$@" PATH="$STUBS:$PATH" bash -c '
    err() { echo "ERR: $*" >&2; }; warn() { echo "WARN: $*"; }; info() { echo "$*"; }; log() { echo "$*"; }
    SCRIPT_DIR="$1"; BAS_VERSION=9.9.9
    source "$2"
    _verify_all_images
    echo "OK orch_id=$ORCH_ID imgs=${#IMG_TARS[@]}"' _ "$SX" "$T/setup-fns.sh" > "$T/out.txt" 2>&1
}
stage_setup() { # build bundle (MUTATE) and unpack it so SX=<bundle>/compose with a real images/ dir
  make_bundle "$T/b.tar.gz"; rm -rf "$T/ex"; mkdir "$T/ex"; tar -xzf "$T/b.tar.gz" -C "$T/ex"
  SX="$T/ex/bas-airgap-9.9.9/compose"; rm -rf "$SX/images"; cp -r "$T/ex/bas-airgap-9.9.9/images" "$SX/images"
}
sv_ok() { local rc=0; run_setup_verify "$@" || rc=$?; [ "$rc" -eq 0 ]; }
MUTATE="" stage_setup
if sv_ok BAS_REQUIRE_SIGNED_IMAGES=1 && grep -q "^OK orch_id=$(img_id orch) imgs=1" "$T/out.txt"; then pass "setup.sh strict: valid images verified up front, orchestrator ID recorded"; else fail "setup.sh strict valid"; cat "$T/out.txt"; fi
MUTATE='echo x > "$b/images/extra.tar"' stage_setup
sv_ok BAS_REQUIRE_SIGNED_IMAGES=1 && fail "setup.sh strict accepted extra unsigned tar" || pass "setup.sh strict: extra unsigned tar refused"
MUTATE='rm "$b/images/postgres-16-alpine.tar.bundle"' stage_setup
sv_ok BAS_REQUIRE_SIGNED_IMAGES=1 && fail "setup.sh strict accepted unsigned postgres" || pass "setup.sh strict: unsigned postgres refused (fatal, no || true)"
MUTATE='mk_image_tar "$b/images/postgres-16-alpine.tar" "\"postgres:16-alpine\",\"bas-orchestrator:9.9.9\"" pg; sign_tar "$b/images/postgres-16-alpine.tar"' stage_setup
sv_ok BAS_REQUIRE_SIGNED_IMAGES=1 && fail "setup.sh accepted planted tag" || pass "setup.sh: planted orchestrator tag inside postgres tar refused"
MUTATE='mk_image_tar "$b/images/bas-orchestrator-9.9.9.tar" "\"bas-orchestrator:9.9.8\"" older; sign_tar "$b/images/bas-orchestrator-9.9.9.tar"' stage_setup
sv_ok BAS_REQUIRE_SIGNED_IMAGES=1 && fail "setup.sh accepted older tar renamed" || pass "setup.sh: older signed tar renamed to this version refused"
sv_ok && fail "setup.sh (non-strict) accepted renamed older orchestrator" || pass "setup.sh non-strict: orchestrator identity still enforced"
MUTATE='rm "$b/images/postgres-16-alpine.tar" "$b/images/postgres-16-alpine.tar.bundle"; echo x | gzip > "$b/images/postgres-16-alpine.tar.gz"' stage_setup
sv_ok && pass "setup.sh non-strict (release-ZIP style bundle with unsigned postgres.tar.gz) unchanged" || { fail "setup.sh non-strict regression"; cat "$T/out.txt"; }
sv_ok BAS_REQUIRE_SIGNED_IMAGES=1 && fail "setup.sh strict accepted .tar.gz" || pass "setup.sh strict: legacy .tar.gz refused"
MUTATE="" stage_setup
sv_ok BAS_REQUIRE_SIGNED_IMAGES=1 BAS_COSIGN_PUB="$T/ext-bad.pub" && fail "setup.sh ignored external cosign key" || pass "setup.sh: external cosign key (BAS_COSIGN_PUB) governs verification"
grep -q "EXTERNAL key" "$T/out.txt" && pass "setup.sh error shows EXTERNAL label + key path" || fail "setup.sh error context missing"
sv_ok BAS_REQUIRE_SIGNED_IMAGES=1 BAS_COSIGN_PUB="$T/ext-good.pub" && pass "setup.sh: matching external key accepted" || fail "setup.sh external good"
# post-load identity (setup.sh and install.sh share _docker_tag_is)
rm -rf "$DOCKER_STATE"; mkdir -p "$DOCKER_STATE"; echo "$(img_id orch)" > "$DOCKER_STATE/tag.bas-orchestrator_9.9.9"
PATH="$STUBS:$PATH" bash -c 'source "$1"; _docker_tag_is bas-orchestrator:9.9.9 "$2"' _ "$T/setup-fns.sh" "$(img_id orch)" && pass "_docker_tag_is: matching ID" || fail "_docker_tag_is match"
PATH="$STUBS:$PATH" bash -c 'source "$1"; _docker_tag_is bas-orchestrator:9.9.9 "$2"' _ "$T/setup-fns.sh" "$(img_id other)" && fail "_docker_tag_is accepted wrong ID" || pass "_docker_tag_is: wrong ID refused"

echo "TEST: GPG (real throwaway keys): verify-sig.sh, import.sh, verify.sh and setup.sh agent check"
if ! command -v gpg >/dev/null 2>&1; then
  echo "SKIP: gpg not available"
else
  export GNUPGHOME="$T/gnupg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "A <a@test.invalid>" default default never >/dev/null 2>&1
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "B <b@test.invalid>" default default never >/dev/null 2>&1
  gpg --armor --export a@test.invalid > "$T/gpg-a.asc"; gpg --armor --export b@test.invalid > "$T/gpg-b.asc"
  cat "$T/gpg-a.asc" "$T/gpg-b.asc" > "$T/gpg-multi.asc"           # [genuine A, attacker B]
  FPA=$(gpg --with-colons --list-keys a@test.invalid | awk -F: '/^fpr/{print $10; exit}')
  gsign() { # <signer email> <file>
    rm -f "$2.asc"; gpg --batch --pinentry-mode loopback --passphrase '' -u "$1" --detach-sign --armor -o "$2.asc" "$2"
  }
  MUTATE="" make_bundle "$T/b.tar.gz"
  gsign a@test.invalid "$T/b.tar.gz"
  cp "$REPO/packaging/signing/verify-sig.sh" "$T/tools/"; cp "$T/gpg-a.asc" "$T/tools/pubkey.asc"   # bundled key = A (signer)
  vs() { PATH="$TEST_PATH" bash "$T/tools/verify-sig.sh" "$T/b.tar.gz" "$@" > "$T/out.txt" 2>&1; }
  gok() { local rc=0; "$@" || rc=$?; [ "$rc" -eq 0 ]; }
  if gok vs && grep -q "BUNDLED GPG key, fingerprint: ${FPA}" "$T/out.txt" && grep -q "integrity, not origin" "$T/out.txt" && grep -q "signed by key ${FPA}" "$T/out.txt"; then pass "bundled GPG key: fingerprint + origin warning + VALIDSIG fingerprint"; else fail "bundled GPG"; cat "$T/out.txt"; fi
  if gok vs --gpg-pub "$T/gpg-a.asc" && grep -q "EXTERNAL GPG key, fingerprint: ${FPA}" "$T/out.txt"; then pass "external GPG key matches"; else fail "external GPG match"; fi
  if gok vs --gpg-pub="$T/gpg-a.asc"; then pass "--gpg-pub=<path> form"; else fail "--gpg-pub= form"; fi
  if gok vs --gpg-pub "$T/gpg-b.asc"; then fail "mismatching external GPG key accepted"; else pass "external GPG key mismatch fails (bundled would pass)"; fi
  if gok vs --gpg-pub "$T/nope.asc"; then fail "missing GPG path accepted"; else pass "missing GPG path aborts"; fi
  if BAS_GPG_PUB="$T/gpg-b.asc" gok vs --gpg-pub "$T/gpg-a.asc"; then pass "GPG flag beats env"; else fail "GPG flag/env precedence"; fi
  if BAS_GPG_PUB="$T/gpg-a.asc" gok vs --gpg-pub "$T/gpg-b.asc"; then fail "GPG flag(bad) lost to env(good)"; else pass "GPG flag(bad) beats env(good)"; fi
  if BAS_GPG_PUB="$T/gpg-b.asc" gok vs; then fail "GPG env(bad) lost to bundled(good)"; else pass "GPG env beats bundled"; fi
  if gok vs --bogus; then fail "unknown verify-sig flag accepted"; else pass "verify-sig.sh rejects unknown flags"; fi
  # C1: a multi-key file must never let another key vouch while a genuine fingerprint is shown
  gsign b@test.invalid "$T/b.tar.gz"                                  # attacker signs
  if gok vs --gpg-pub "$T/gpg-multi.asc"; then fail "multi-key external file accepted"; else grep -q "primary keys" "$T/out.txt" && pass "multi-key --gpg-pub file refused" || fail "multi-key external: wrong reason"; fi
  cp "$T/gpg-multi.asc" "$T/tools/pubkey.asc"
  if gok vs; then fail "multi-key BUNDLED pubkey.asc accepted (attacker signature, genuine fingerprint shown)"; else grep -q "primary keys" "$T/out.txt" && pass "multi-key bundled pubkey.asc refused" || fail "multi-key bundled: wrong reason"; fi
  cp "$T/gpg-a.asc" "$T/tools/pubkey.asc"
  if gok vs; then fail "signature by a DIFFERENT key accepted"; else pass "signature made by a different key than the single imported key refused"; fi
  gsign a@test.invalid "$T/b.tar.gz"
  # import.sh / verify.sh: key passed through; mismatch aborts before any load
  IMPORT_EXTRA="--gpg-pub $T/gpg-b.asc" expect_abort "import.sh: external GPG mismatch"
  IMPORT_EXTRA="--gpg-pub $T/gpg-a.asc" check_valid "import.sh: external GPG match"
  grep -q "^GPGENV=.*gpg-a.asc" "$STUB_LOG" && pass "import.sh exports the GPG key to setup.sh" || fail "BAS_GPG_PUB not handed to setup.sh"
  IMPORT_EXTRA="--gpg-pub=$T/gpg-a.asc" check_valid "import.sh: --gpg-pub=<path> form"
  rc=0; PATH="$TEST_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" --gpg-pub "$T/gpg-b.asc" > "$T/out.txt" 2>&1 || rc=$?
  [ "$rc" -ne 0 ] && pass "verify.sh external GPG mismatch fails" || fail "verify.sh accepted wrong GPG key"
  rc=0; PATH="$TEST_PATH" bash "$T/tools/verify.sh" "$T/b.tar.gz" --gpg-pub="$T/gpg-a.asc" > "$T/out.txt" 2>&1 || rc=$?
  [ "$rc" -eq 0 ] && pass "verify.sh external GPG ok" || { fail "verify.sh external GPG"; cat "$T/out.txt"; }

  # ── setup.sh verify_bundle_signatures (agents' BINARIES.sha256) ──
  { extract_fn "$SETUP" _gpg_verify_single_key; extract_fn "$SETUP" verify_bundle_signatures; } > "$T/setup-gpg-fns.sh"
  AG="$T/sgpg"; rm -rf "$AG"; mkdir -p "$AG/agents"
  printf 'agent-binary-bytes' > "$AG/agents/bas-agent-linux-amd64"
  (cd "$AG/agents" && sha256sum bas-agent-linux-amd64 > BINARIES.sha256); gsign a@test.invalid "$AG/agents/BINARIES.sha256"
  cp "$T/gpg-a.asc" "$AG/agents/pubkey.asc"                          # bundled key = A (signer)
  run_vbs() { # env assignments; optional NO_GPG=1 to hide gpg
    env "$@" PATH="$TEST_PATH" bash -c '
      err() { echo "ERR: $*" >&2; }; warn() { echo "WARN: $*"; }; log() { echo "$*"; }
      if [ -n "${NO_GPG:-}" ]; then command() { if [ "$1" = "-v" ] && [ "$2" = "gpg" ]; then return 1; fi; builtin command "$@"; }; fi
      SCRIPT_DIR="$1"; GPG_PUB_FLAG="${GPG_PUB_FLAG:-}"
      source "$2"; verify_bundle_signatures; echo VBS-OK' _ "$AG" "$T/setup-gpg-fns.sh" > "$T/out.txt" 2>&1
  }
  vb_ok() { local rc=0; run_vbs "$@" || rc=$?; [ "$rc" -eq 0 ] && grep -q VBS-OK "$T/out.txt"; }
  if vb_ok && grep -q "BUNDLED GPG key, fingerprint: ${FPA}" "$T/out.txt" && grep -q "Agent binaries match the signed manifest" "$T/out.txt"; then pass "setup.sh agents: bundled key + signed manifest + binary hashes OK"; else fail "setup.sh agents default"; cat "$T/out.txt"; fi
  if vb_ok BAS_GPG_PUB="$T/gpg-a.asc" && grep -q "EXTERNAL GPG key, fingerprint: ${FPA}" "$T/out.txt"; then pass "setup.sh agents: external key matches"; else fail "setup.sh agents external match"; fi
  if vb_ok GPG_PUB_FLAG="$T/gpg-a.asc" BAS_GPG_PUB="$T/gpg-b.asc"; then pass "setup.sh agents: flag beats env"; else fail "setup.sh agents flag/env"; fi
  if vb_ok BAS_GPG_PUB="$T/gpg-b.asc"; then fail "setup.sh agents: mismatching external key accepted (bundled would pass)"; else pass "setup.sh agents: mismatching external key fails even though the bundled key would pass"; fi
  if vb_ok BAS_GPG_PUB="$T/nope.asc"; then fail "setup.sh agents: missing external path accepted"; else pass "setup.sh agents: missing external path aborts"; fi
  if vb_ok BAS_GPG_PUB="$T/gpg-multi.asc"; then fail "setup.sh agents: multi-key external file accepted"; else grep -q "primary keys" "$T/out.txt" && pass "setup.sh agents: multi-key file refused" || fail "setup.sh agents multi-key reason"; fi
  cp "$AG/agents/pubkey.asc" "$AG/pubkey.keep"; cp "$T/gpg-multi.asc" "$AG/agents/pubkey.asc"
  if vb_ok; then fail "setup.sh agents: multi-key BUNDLED file accepted"; else pass "setup.sh agents: multi-key bundled pubkey.asc refused"; fi
  cp "$AG/pubkey.keep" "$AG/agents/pubkey.asc"
  if vb_ok NO_GPG=1; then fail "setup.sh agents: .asc present + gpg missing was NOT fatal"; else grep -q "gpg is not installed" "$T/out.txt" && pass "setup.sh agents: .asc present + gpg missing is FATAL" || fail "gpg-missing reason"; fi
  mv "$AG/agents/BINARIES.sha256.asc" "$AG/asc.keep"
  if vb_ok && grep -q "unsigned" "$T/out.txt"; then pass "setup.sh agents: manifest without .asc stays a warning (unchanged)"; else fail "unsigned-manifest behaviour changed"; fi
  if vb_ok BAS_GPG_PUB="$T/gpg-a.asc"; then fail "external key supplied but no .asc was accepted"; else pass "setup.sh agents: external key + no .asc is fatal"; fi
  mv "$AG/asc.keep" "$AG/agents/BINARIES.sha256.asc"
  printf 'TAMPERED' > "$AG/agents/bas-agent-linux-amd64"
  if vb_ok; then fail "setup.sh agents: tampered binary accepted"; else grep -q "does not match the signed BINARIES.sha256" "$T/out.txt" && pass "setup.sh agents: tampered binary fails the sha256 check (signature itself was valid)" || fail "tamper reason"; fi
  gpgconf --kill all >/dev/null 2>&1 || true
  rm -f "$T/b.tar.gz.asc" "$T/tools/verify-sig.sh" "$T/tools/pubkey.asc"
fi

echo "TEST: ISO post-install.sh and Packer install-bas.sh are sandboxed and fail closed"
SBX="$T/sbx"; APPL="$T/appl"
pin_sha() { sha256sum "$1" | cut -d' ' -f1; }
setup_sbx() { # fresh sandbox, bundle at $SBX/var/tmp/bas-airgap.tar.gz
  rm -rf "$SBX" "$APPL"; mkdir -p "$SBX/var/log" "$SBX/var/tmp" "$SBX/opt/bas-platform" "$SBX/usr/local/bin" "$APPL"
  cp "$T/b.tar.gz" "$SBX/var/tmp/bas-airgap.tar.gz"
  cp "$REPO/packaging/appliance/fetch-cosign.sh" "$APPL/"
  printf 'COSIGN_VERSION=v3.1.3\nCOSIGN_SHA256_LINUX_AMD64=%s\n' "$(pin_sha "$STUBS/cosign")" > "$APPL/cosign.pin"
  cp "$STUBS/cosign" "$APPL/cosign-linux-amd64"; : > "$STUB_LOG"; rm -rf "$DOCKER_STATE"; mkdir -p "$DOCKER_STATE"
}
run_pi() { # <PATH> ; post-install.sh sandboxed by BAS_ROOT
  : > "$SBX/var/log/bas-postinstall.log"
  BAS_ROOT="$SBX" APPLIANCE_DIR="$APPL" PATH="$1" bash "$REPO/packaging/iso/autoinstall/scripts/post-install.sh" > "$T/out.txt" 2>&1
}
run_ib() { # <PATH> ; install-bas.sh sandboxed by BAS_ROOT; "download" comes from the curl stub
  BAS_ROOT="$SBX" APPLIANCE_DIR="$APPL" PATH="$1" STUB_CURL_SRC="${CURL_SRC:-$STUBS/cosign}" bash "$REPO/packaging/packer/scripts/install-bas.sh" > "$T/out.txt" 2>&1
}
sb_expect_fail() { # <label> <runner> <PATH> <expected text in its own output/log>
  local rc=0; "$2" "$3" || rc=$?
  local own; own="$(cat "$T/out.txt" "$SBX/var/log/bas-postinstall.log" 2>/dev/null || true)"
  if [ "$rc" -eq 0 ]; then fail "$1 -- succeeded"; return; fi
  if grep -q '^LOADED' "$STUB_LOG"; then fail "$1 -- an image was loaded"; return; fi
  if ! grep -q -- "$4" <<<"$own"; then fail "$1 -- failed for the wrong reason (expected '$4'): $own"; return; fi
  pass "$1"
}
for sc in pi ib; do
  case "$sc" in pi) name="post-install.sh" ;; ib) name="install-bas.sh" ;; esac
  # (a) legacy tar.gz orchestrator
  MUTATE='rm "$b/images/bas-orchestrator-9.9.9.tar" "$b/images/bas-orchestrator-9.9.9.tar.bundle"; echo x | gzip > "$b/images/bas-orchestrator-9.9.9.tar.gz"' make_bundle "$T/b.tar.gz"
  setup_sbx; sb_expect_fail "$name: legacy .tar.gz refused before any docker load" "run_$sc" "$TEST_PATH" "legacy unsigned\|Unexpected file"
  # (b) tampered tar
  MUTATE='echo evil >> "$b/images/bas-orchestrator-9.9.9.tar"' make_bundle "$T/b.tar.gz"
  setup_sbx; sb_expect_fail "$name: tampered orchestrator .tar refused" "run_$sc" "$TEST_PATH" "verification FAILED"
  MUTATE='echo evil >> "$b/images/postgres-16-alpine.tar"' make_bundle "$T/b.tar.gz"
  setup_sbx; sb_expect_fail "$name: tampered postgres .tar refused" "run_$sc" "$TEST_PATH" "verification FAILED"
  # (c) stale compose/VERSION
  MUTATE='echo 9.9.8 > "$b/compose/VERSION"' make_bundle "$T/b.tar.gz"
  setup_sbx; sb_expect_fail "$name: stale compose/VERSION refused" "run_$sc" "$TEST_PATH" "compose/VERSION"
  # (d) planted tag in postgres tar
  MUTATE='mk_image_tar "$b/images/postgres-16-alpine.tar" "\"postgres:16-alpine\",\"bas-orchestrator:9.9.9\"" pg; sign_tar "$b/images/postgres-16-alpine.tar"' make_bundle "$T/b.tar.gz"
  setup_sbx; sb_expect_fail "$name: planted orchestrator tag in postgres tar refused" "run_$sc" "$TEST_PATH" "does not carry exactly"
done
# pinned cosign missing / mismatched (cosign not on PATH so the pin is what provides it)
MUTATE="" make_bundle "$T/b.tar.gz"
setup_sbx; rm "$APPL/cosign-linux-amd64"
sb_expect_fail "post-install.sh: pinned cosign missing" run_pi "$CLEAN_PATH" "pinned cosign missing or failed"
setup_sbx; printf 'wrong-bytes' > "$APPL/cosign-linux-amd64"
sb_expect_fail "post-install.sh: pinned cosign checksum mismatch" run_pi "$CLEAN_PATH" "pinned cosign missing or failed"
[ ! -e "$SBX/usr/local/bin/cosign" ] && pass "post-install.sh: mismatched cosign was not installed" || fail "mismatched cosign got installed"
setup_sbx; rm "$APPL/cosign.pin"
sb_expect_fail "install-bas.sh: pin file missing" run_ib "$CLEAN_PATH" "pinned cosign could not be installed"
setup_sbx; CURL_SRC="$T/ext-bad.pub" sb_expect_fail "install-bas.sh: downloaded cosign fails the pinned checksum" run_ib "$CLEAN_PATH" "checksum mismatch"
[ ! -e "$SBX/usr/local/bin/cosign" ] && pass "install-bas.sh: mismatched cosign was not installed" || fail "mismatched downloaded cosign got installed"
[ "$(snap)" = "$HOST_SNAP" ] && pass "sandbox guard: nothing outside the temp dir was touched (/usr/local/bin, /var/tmp, /opt)" || fail "SANDBOX LEAK: a script touched a real system path"

echo "TEST: fetch-cosign.sh --verify enforces the pinned checksum"
printf 'fake-cosign' > "$T/cos.bin"
printf 'COSIGN_VERSION=v3.1.3\nCOSIGN_SHA256_LINUX_AMD64=%s\n' "$(sha256sum "$T/cos.bin" | cut -d' ' -f1)" > "$T/ok.pin"
printf 'COSIGN_VERSION=v3.0.2\nCOSIGN_SHA256_LINUX_AMD64=%s\n' "$(sha256sum "$T/cos.bin" | cut -d' ' -f1)" > "$T/old.pin"
if bash "$REPO/packaging/appliance/fetch-cosign.sh" --verify "$T/cos.bin" "$T/ok.pin" >/dev/null 2>&1; then pass "matching checksum accepted"; else fail "good checksum rejected"; fi
if bash "$REPO/packaging/appliance/fetch-cosign.sh" --verify "$T/cos.bin" "$T/old.pin" >/dev/null 2>&1; then fail "pin < v3.1.0 accepted"; else pass "pin older than v3.1.0 rejected"; fi
printf 'tampered' > "$T/cos.bin"
if bash "$REPO/packaging/appliance/fetch-cosign.sh" --verify "$T/cos.bin" "$T/ok.pin" >/dev/null 2>&1; then fail "tampered cosign accepted"; else [ ! -e "$T/cos.bin" ] && pass "checksum mismatch rejected and file removed"; fi

if [ "$FAILED" -eq 0 ]; then echo "ALL PASS"; else echo "SOME FAILED"; exit 1; fi
