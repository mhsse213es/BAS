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
          idx=$(tar -xOf "$S/in.tar" index.json 2>/dev/null | grep -o 'sha256:[0-9a-f]*' | head -1 || true)
          case "${FAKE_DOCKER_ID_MODE:-config}" in
            index) [ -n "$idx" ] && id="$idx" ;;
            third) id="sha256:$(printf 'e%.0s' $(seq 64))" ;;
          esac
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

# Runtime image pin (packaging/images.pin) -- the chrome tag every consumer must agree on.
CHROME_TAG="chromedp/headless-shell:$(sed -n 's/^CHROME_VERSION=//p' "$REPO/packaging/images.pin")"
# ── Image / bundle builders ────────────────────────────────────────────────────
# Mimics `docker save` on a containerd-store daemon (manifest.json + OCI index.json);
# a 4th arg "noindex" mimics an older tar with manifest.json only.
mk_image_tar() { # <out> <quoted,comma,separated RepoTags> <config seed> [noindex]
  local d="$T/imgtmp" hex ihex; rm -rf "$d"; mkdir -p "$d"
  hex=$(printf '%s' "$3" | sha256sum | cut -d' ' -f1)
  ihex=$(printf '%s-idx' "$3" | sha256sum | cut -d' ' -f1)
  printf '[{"Config":"blobs/sha256/%s","RepoTags":[%s],"Layers":[]}]' "$hex" "$2" > "$d/manifest.json"
  if [ "${4:-}" = noindex ]; then
    tar -cf "$1" -C "$d" manifest.json
  else
    printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":1}]}' "$ihex" > "$d/index.json"
    tar -cf "$1" -C "$d" manifest.json index.json
  fi
}
img_id() { echo "sha256:$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"; }   # manifest Config digest
idx_id() { echo "sha256:$(printf '%s-idx' "$1" | sha256sum | cut -d' ' -f1)"; } # index.json digest
sign_tar() { echo "$(sha256sum "$1" | cut -d' ' -f1):${2:-fake-pub}" > "$1.bundle"; }

# Build a signed bundle tarball ($1 = output). MUTATE (eval'd, may use $b) tweaks it
# AFTER signing; the manifest is regenerated after, so only cosign/identity checks can catch it.
make_bundle() {
  local out="$1" b="$T/build/bas-airgap-9.9.9"
  rm -rf "$T/build"; mkdir -p "$b/images" "$b/compose"
  echo 9.9.9 > "$b/VERSION"
  mk_image_tar "$b/images/bas-orchestrator-9.9.9.tar" '"bas-orchestrator:9.9.9"' orch; sign_tar "$b/images/bas-orchestrator-9.9.9.tar" "${SIGN_KEY:-fake-pub}"
  mk_image_tar "$b/images/postgres-16-alpine.tar" '"postgres:16-alpine"' pg;          sign_tar "$b/images/postgres-16-alpine.tar" "${SIGN_KEY:-fake-pub}"
  mk_image_tar "$b/images/headless-shell.tar" "\"$CHROME_TAG\"" chrome;               sign_tar "$b/images/headless-shell.tar" "${SIGN_KEY:-fake-pub}"
  mk_image_tar "$b/images/bas-caldera-9.9.9.tar" '"bas-caldera:9.9.9"' caldera;         sign_tar "$b/images/bas-caldera-9.9.9.tar" "${SIGN_KEY:-fake-pub}"
  printf '%s' "${BUNDLED_PUB:-fake-pub}" > "$b/cosign.pub"; cp "$b/cosign.pub" "$b/compose/cosign.pub"; echo 9.9.9 > "$b/compose/VERSION"
  printf '#!/usr/bin/env bash\necho "PUBENV=${BAS_COSIGN_PUB:-}" >> "$STUB_LOG"; echo "GPGENV=${BAS_GPG_PUB:-}" >> "$STUB_LOG"; echo SETUP-RAN >> "$STUB_LOG"\n' > "$b/compose/setup.sh"
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
  if [ "$seq" != "LOADED bas-caldera:9.9.9|LOADED $CHROME_TAG|LOADED postgres:16-alpine|LOADED bas-orchestrator:9.9.9|docker tag bas-orchestrator:9.9.9 bas-orchestrator:latest|SETUP-RAN|" ]; then
    fail "$1 -- wrong order: $seq"; return
  fi
  if [ "$(grep -c '^cosign verify-blob' "$STUB_LOG")" -ne 4 ] || [ "$lastverify" -gt "$firstload" ]; then
    fail "$1 -- all four images must be verified before the first load"; return
  fi
  local lid; lid="$(cat "$DOCKER_STATE/tag.bas-orchestrator_latest")"
  if [ "$lid" != "$(img_id orch)" ] && [ "$lid" != "$(idx_id orch)" ]; then
    fail "$1 -- :latest does not point at the verified orchestrator image"; return
  fi
  pass "$1"
}

echo "TEST: valid bundle -> every image verified first, postgres then orchestrator loaded, :latest re-tagged from the verified image, then setup"
MUTATE="" make_bundle "$T/b.tar.gz"
check_valid "valid bundle"
! grep -rq "BAS_REQUIRE_SIGNED_IMAGES" "$REPO/packaging/compose" "$REPO/packaging/iso" "$REPO/packaging/packer" "$REPO/packaging/airgap/import.sh" && pass "no BAS_REQUIRE_SIGNED_IMAGES opt-in left in setup/install/ISO/Packer/import" || fail "BAS_REQUIRE_SIGNED_IMAGES still referenced"
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

echo "TEST: post-load image ID: Config digest (overlay2) OR index digest (containerd store), both from the signed tar"
FAKE_DOCKER_ID_MODE=config check_valid "daemon reports the Config digest -> accepted"
FAKE_DOCKER_ID_MODE=index  check_valid "daemon reports the index digest (containerd store) -> accepted"
rc=0; FAKE_DOCKER_ID_MODE=third run_import "$T/b.tar.gz" || rc=$?
if [ "$rc" -ne 0 ] && ! grep -q SETUP-RAN "$STUB_LOG" && grep -q "not the verified image after load" "$T/out.txt"; then pass "daemon reports a third (unsigned-tar) digest -> refused"; else fail "third digest accepted (rc=$rc)"; fi
MUTATE='mk_image_tar "$b/images/bas-orchestrator-9.9.9.tar" "\"bas-orchestrator:9.9.9\"" orch noindex; sign_tar "$b/images/bas-orchestrator-9.9.9.tar"; mk_image_tar "$b/images/postgres-16-alpine.tar" "\"postgres:16-alpine\"" pg noindex; sign_tar "$b/images/postgres-16-alpine.tar"' make_bundle "$T/b.tar.gz"
FAKE_DOCKER_ID_MODE=config check_valid "older tars without index.json: Config match accepted"
rc=0; FAKE_DOCKER_ID_MODE=index run_import "$T/b.tar.gz" || rc=$?
[ "$rc" -eq 0 ] && pass "no index.json: daemon falls back to Config digest in the stub -> accepted" || fail "noindex fallback rc=$rc"
MUTATE="" make_bundle "$T/b.tar.gz"

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
{ for fn in _key_fp _tar_image_id _docker_tag_is _cosign_version_ok _resolve_cosign_pub _verify_orchestrator_artifact _expected_image_tag _verify_all_images _load_verified_images; do extract_fn "$INST" "$fn"; done; } > "$T/inst-fns.sh"
{ for fn in _key_fp _tar_image_id _docker_tag_is _cosign_version_ok _verify_orchestrator_artifact _expected_image_tag _verify_all_images _load_verified_images; do extract_fn "$SETUP" "$fn"; done; } > "$T/setup-fns.sh"
# One logical copy: the image helpers must be byte-identical in install.sh and setup.sh.
for fn in _key_fp _tar_image_id _docker_tag_is _cosign_version_ok _expected_image_tag _verify_all_images _load_verified_images; do
  a="$(extract_fn "$INST" "$fn")"; s="$(extract_fn "$SETUP" "$fn")"
  if [ -n "$a" ] && [ "$a" = "$s" ]; then pass "$fn is byte-identical in install.sh and setup.sh"; else fail "$fn drifted between install.sh and setup.sh (or is missing)"; fi
done

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
  [ "$id" = "$(img_id orch) $(idx_id orch)" ] && pass "$n: _tar_image_id returns the Config digest AND the index.json digest" || fail "$n: _tar_image_id ($id)"
  if bash -c 'source "$1"; _tar_image_id "$2" "bas-orchestrator:9.9.8"' _ "$F" "$IB/o.tar" >/dev/null 2>&1; then fail "$n: wrong expected tag accepted"; else pass "$n: tag mismatch refused"; fi
done

# setup.sh --offline: _verify_all_images over an extracted bundle's compose/ dir
run_setup_verify() { # <env assignments...> uses $SX as SCRIPT_DIR
  env "$@" PATH="$STUBS:$PATH" bash -c '
    err() { echo "ERR: $*" >&2; }; warn() { echo "WARN: $*"; }; info() { echo "$*"; }; log() { echo "$*"; }
    SCRIPT_DIR="$1"; BAS_VERSION=9.9.9
    source "$2"
    _verify_all_images "$SCRIPT_DIR/images" installation
    echo "OK orch_id=$ORCH_ID imgs=${#IMG_TARS[@]}"' _ "$SX" "$T/setup-fns.sh" > "$T/out.txt" 2>&1
}
stage_setup() { # build bundle (MUTATE) and unpack it so SX=<bundle>/compose with a real images/ dir
  make_bundle "$T/b.tar.gz"; rm -rf "$T/ex"; mkdir "$T/ex"; tar -xzf "$T/b.tar.gz" -C "$T/ex"
  SX="$T/ex/bas-airgap-9.9.9/compose"; rm -rf "$SX/images"; cp -r "$T/ex/bas-airgap-9.9.9/images" "$SX/images"
}
sv_ok() { local rc=0; run_setup_verify "$@" || rc=$?; [ "$rc" -eq 0 ]; }
MUTATE="" stage_setup
if sv_ok && grep -q "^OK orch_id=$(img_id orch) $(idx_id orch) imgs=3" "$T/out.txt"; then pass "setup.sh: valid images verified up front, orchestrator ID recorded"; else fail "setup.sh valid"; cat "$T/out.txt"; fi
MUTATE='echo x > "$b/images/extra.tar"' stage_setup
sv_ok && fail "setup.sh accepted extra unsigned tar" || pass "setup.sh: extra unsigned tar refused"
MUTATE='rm "$b/images/postgres-16-alpine.tar.bundle"' stage_setup
sv_ok && fail "setup.sh accepted unsigned postgres" || pass "setup.sh: unsigned postgres refused (fatal, no || true)"
MUTATE='mk_image_tar "$b/images/postgres-16-alpine.tar" "\"postgres:16-alpine\",\"bas-orchestrator:9.9.9\"" pg; sign_tar "$b/images/postgres-16-alpine.tar"' stage_setup
sv_ok && fail "setup.sh accepted planted tag" || pass "setup.sh: planted orchestrator tag inside postgres tar refused"
MUTATE='mk_image_tar "$b/images/bas-orchestrator-9.9.9.tar" "\"bas-orchestrator:9.9.8\"" older; sign_tar "$b/images/bas-orchestrator-9.9.9.tar"' stage_setup
sv_ok && fail "setup.sh accepted older tar renamed" || pass "setup.sh: older signed tar renamed to this version refused"
sv_ok && fail "setup.sh accepted renamed older orchestrator" || pass "setup.sh: orchestrator identity enforced (no env needed)"
MUTATE='rm "$b/images/postgres-16-alpine.tar" "$b/images/postgres-16-alpine.tar.bundle"; echo x | gzip > "$b/images/postgres-16-alpine.tar.gz"' stage_setup
sv_ok && fail "setup.sh accepted release-ZIP-style unsigned postgres.tar.gz" || pass "setup.sh: legacy unsigned postgres.tar.gz is fatal by default (no env)"
MUTATE='rm "$b/images/postgres-16-alpine.tar.bundle"' stage_setup
sv_ok && fail "setup.sh accepted unsigned postgres tar by default" || pass "setup.sh: release-ZIP-shaped bundle, unsigned postgres tar, no env -> fatal"
MUTATE='echo tampered >> "$b/images/postgres-16-alpine.tar"' stage_setup
sv_ok && fail "setup.sh accepted tampered postgres tar" || pass "setup.sh: release-ZIP-shaped bundle, tampered postgres tar -> fatal"
MUTATE="" stage_setup
sv_ok && grep -q "^OK orch_id=" "$T/out.txt" && pass "setup.sh: correctly signed release-ZIP-shaped bundle passes with no env" || { fail "setup.sh signed bundle default"; cat "$T/out.txt"; }
MUTATE="" stage_setup
sv_ok BAS_COSIGN_PUB="$T/ext-bad.pub" && fail "setup.sh ignored external cosign key" || pass "setup.sh: external cosign key (BAS_COSIGN_PUB) governs verification"
grep -q "EXTERNAL key" "$T/out.txt" && pass "setup.sh error shows EXTERNAL label + key path" || fail "setup.sh error context missing"
sv_ok BAS_COSIGN_PUB="$T/ext-good.pub" && pass "setup.sh: matching external key accepted" || fail "setup.sh external good"
# post-load identity (setup.sh and install.sh share _docker_tag_is)
rm -rf "$DOCKER_STATE"; mkdir -p "$DOCKER_STATE"; echo "$(img_id orch)" > "$DOCKER_STATE/tag.bas-orchestrator_9.9.9"
PATH="$STUBS:$PATH" bash -c 'source "$1"; _docker_tag_is bas-orchestrator:9.9.9 "$2"' _ "$T/setup-fns.sh" "$(img_id orch)" && pass "_docker_tag_is: matching ID" || fail "_docker_tag_is match"
PATH="$STUBS:$PATH" bash -c 'source "$1"; _docker_tag_is bas-orchestrator:9.9.9 "$2"' _ "$T/setup-fns.sh" "$(img_id other)" && fail "_docker_tag_is accepted wrong ID" || pass "_docker_tag_is: wrong ID refused"
PATH="$STUBS:$PATH" bash -c 'source "$1"; _docker_tag_is bas-orchestrator:9.9.9 "$2"' _ "$T/setup-fns.sh" "$(img_id other) $(img_id orch)" && pass "_docker_tag_is: matches any ONE of the candidate digests" || fail "_docker_tag_is candidate list"

echo "TEST: release-images.sh (pack.sh + build.sh): pin parsing, pull BY DIGEST, every failure fatal (stubbed docker/cosign)"
BSTUB="$T/bstub"; rm -rf "$BSTUB"; mkdir -p "$BSTUB"
# Fake docker for the release side: pull <repo>@<digest> records the digest;
# image inspect reports it back (or a WRONG one with FAKE_WRONG_DIGEST); save
# writes a minimal tar; FAKE_FAIL=<subcommand> makes that subcommand fail.
cat > "$BSTUB/docker" <<'DEOF'
#!/usr/bin/env bash
echo "docker $*" >> "$REL_LOG"
[ "${FAKE_FAIL:-}" = "$1" ] && exit 1
case "$1" in
  pull)  exit 0 ;;
  image) ref="${*: -1}"; d="${ref#*@}"; [ -n "${FAKE_WRONG_DIGEST:-}" ] && d="sha256:$(printf '0%.0s' $(seq 64))"; echo "[\"x@$d\"]"; exit 0 ;;
  tag|build) exit 0 ;;
  save)  out=""; img="$2"; while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done
         d=$(mktemp -d); printf '[{"Config":"blobs/sha256/%064d","RepoTags":["%s"],"Layers":[]}]' 1 "$img" > "$d/manifest.json"
         tar -cf "$out" -C "$d" manifest.json; rm -rf "$d"; exit 0 ;;
esac
exit 0
DEOF
cat > "$BSTUB/cosign.sh" <<'CEOF'
#!/usr/bin/env bash
case "$1" in
  --sign) sha256sum "$2" | cut -d' ' -f1 > "$2.bundle" ;;
  --verify) [ "$(cat "$2.bundle")" = "$(sha256sum "$2" | cut -d' ' -f1)" ] ;;
esac
CEOF
chmod +x "$BSTUB/docker" "$BSTUB/cosign.sh"
export REL_LOG="$T/rel.log"
RROOT="$T/relroot"; rm -rf "$RROOT"; mkdir -p "$RROOT/packaging/caldera"
run_rel() { # <function + args, eval'd>  env from caller; images land in $T/rimg
  : > "$REL_LOG"; rm -rf "$T/rimg"; mkdir -p "$T/rimg"
  PATH="$BSTUB:$PATH" bash -c 'log(){ echo "$*"; }; err(){ echo "ERR $*" >&2; }; source "$1"; eval "$2"' _ \
    "$REPO/packaging/signing/release-images.sh" "$1" > "$T/out.txt" 2>&1
}
rel_ok() { local rc=0; run_rel "$@" || rc=$?; [ "$rc" -eq 0 ]; }
PG_PIN_DIGEST="$(sed -n 's/^POSTGRES_DIGEST=//p' "$REPO/packaging/images.pin")"
CH_PIN_DIGEST="$(sed -n 's/^CHROME_DIGEST=//p' "$REPO/packaging/images.pin")"
cp "$REPO/packaging/images.pin" "$RROOT/packaging/images.pin"
SHIP='rel_ship_postgres "'"$RROOT"'" "'"$T/rimg"'" "'"$BSTUB/cosign.sh"'"; rel_ship_caldera_chrome 9.9.9 "'"$RROOT"'" "'"$T/rimg"'" "'"$BSTUB/cosign.sh"'"'
if rel_ok "$SHIP" && [ -f "$T/rimg/postgres-16-alpine.tar.bundle" ] && [ -f "$T/rimg/headless-shell.tar.bundle" ] && [ -f "$T/rimg/bas-caldera-9.9.9.tar.bundle" ] && [ ! -e "$T/rimg/postgres-16-alpine.tar.gz" ]; then pass "release: postgres, chrome and caldera tars saved uncompressed + signed"; else fail "release happy path"; cat "$T/out.txt"; fi
tar -tf "$T/rimg/postgres-16-alpine.tar" >/dev/null 2>&1 && pass "release: postgres tar is a plain (uncompressed) tar" || fail "release: postgres tar not a plain tar"
grep -qx "docker pull postgres@${PG_PIN_DIGEST}" "$REL_LOG" && grep -qx "docker tag postgres@${PG_PIN_DIGEST} postgres:16-alpine" "$REL_LOG" && pass "release: postgres pulled BY the images.pin digest, then tagged postgres:16-alpine" || { fail "release: postgres not pulled by digest"; cat "$REL_LOG"; }
grep -qx "docker pull chromedp/headless-shell@${CH_PIN_DIGEST}" "$REL_LOG" && pass "release: chrome pulled BY the images.pin digest" || fail "release: chrome not pulled by digest"
! grep -Eq '^docker pull [^@]+$' "$REL_LOG" && pass "release: no pull by mutable tag" || fail "release: an image was pulled by tag"
FAKE_FAIL=pull rel_ok "$SHIP" && fail "release: pull failure ignored" || pass "release: a failed pull exits non-zero"
FAKE_WRONG_DIGEST=1 rel_ok "$SHIP" && fail "release: digest mismatch ignored" || { grep -q "does not carry the pinned digest" "$T/out.txt" && pass "release: pulled image without the pinned digest exits non-zero" || fail "release: digest-mismatch reason"; }
FAKE_FAIL=build rel_ok "$SHIP" && fail "release: caldera build failure ignored" || { grep -q "Failed to build bas-caldera" "$T/out.txt" && pass "release: a failed caldera build exits non-zero" || fail "release: caldera failure reason"; }
FAKE_FAIL=save rel_ok "$SHIP" && fail "release: save failure ignored" || pass "release: a failed docker save exits non-zero"
# images.pin is PARSED, never sourced: every malformed variant is fatal.
pin_case() { # <label> <pin content>
  printf '%b' "$2" > "$RROOT/packaging/images.pin"
  if rel_ok "$SHIP"; then fail "images.pin: $1 accepted"; elif grep -q '^docker pull' "$REL_LOG"; then fail "images.pin: $1 -- pulled before failing"; else pass "images.pin: $1 is fatal (nothing pulled)"; fi
}
GOODPIN="$(cat "$REPO/packaging/images.pin")"
pin_case "CRLF line endings" "$(sed 's/$/\\r/' "$REPO/packaging/images.pin")\n"
pin_case "duplicate key" "${GOODPIN}\nPOSTGRES_DIGEST=${PG_PIN_DIGEST}\n"
pin_case "unknown key" "${GOODPIN}\nEVIL=1\n"
pin_case "shell code (would run if sourced)" "${GOODPIN}\nCHROME_VERSION=\$(touch $T/pwned)\n"
pin_case "malformed digest" "$(sed "s/^POSTGRES_DIGEST=.*/POSTGRES_DIGEST=sha256:abc/" "$REPO/packaging/images.pin")\n"
pin_case "missing POSTGRES_DIGEST" "$(grep -v '^POSTGRES_DIGEST=' "$REPO/packaging/images.pin")\n"
pin_case "space-separated value" "$(sed "s/^POSTGRES_TAG=.*/POSTGRES_TAG=16 alpine/" "$REPO/packaging/images.pin")\n"
[ ! -e "$T/pwned" ] && pass "images.pin content is never executed" || fail "images.pin content was executed"
cp "$REPO/packaging/images.pin" "$RROOT/packaging/images.pin"
rel_ok 'rel_read_pin "'"$RROOT"'/packaging/images.pin"; echo "PIN $POSTGRES_TAG $POSTGRES_DIGEST"' && grep -qx "PIN 16-alpine ${PG_PIN_DIGEST}" "$T/out.txt" && pass "images.pin: the shipped file parses (POSTGRES_TAG + POSTGRES_DIGEST)" || { fail "shipped images.pin rejected"; cat "$T/out.txt"; }
! grep -rnE '(source|\.)[[:space:]]+"?[^ ]*images\.pin' "$REPO/packaging" --include=*.sh | grep -v airgap-cosign.test.sh | grep -q . && pass "no script sources images.pin" || fail "images.pin is still sourced somewhere"
for f in packaging/airgap/pack.sh packaging/build.sh; do
  if grep -q '^rel_ship_postgres ' "$REPO/$f" && ! grep -Eq 'docker (pull|save) "?(postgres|\$\{?POSTGRES_IMAGE)' "$REPO/$f"; then pass "$f ships postgres only via rel_ship_postgres (by digest)"; else fail "$f still pulls/saves postgres by tag"; fi
done
grep -q "Get-PinnedImage -Repo 'postgres' -Tag \$pin\['POSTGRES_TAG'\] -Digest \$pin\['POSTGRES_DIGEST'\]" "$REPO/packaging/windows-build.ps1" && ! grep -q 'docker pull postgres:' "$REPO/packaging/windows-build.ps1" && pass "windows-build.ps1 pulls postgres by the images.pin digest" || fail "windows-build.ps1 postgres not pinned"

echo "TEST: windows-build.ps1: cosign image signing is gated separately from Authenticode"
PS1="$REPO/packaging/windows-build.ps1"
grep -q '\[switch\] \$AllowUnsignedImages' "$PS1" && grep -q '\$CosignSigningRequired  = (-not \$AllowUnsignedImages)' "$PS1" && pass "windows-build.ps1: \$CosignSigningRequired defaults to true, -AllowUnsignedImages is the dev opt-out" || fail "windows-build.ps1 cosign switches"
awk '/^# D2\/cosign-enforcement:/{f=1} /^\$orchSizeMB = /{f=0} f' "$PS1" > "$T/ps-cosign.txt"
[ -s "$T/ps-cosign.txt" ] && ! grep -v "NOT by Authenticode" "$T/ps-cosign.txt" | grep -q 'WindowsSigningRequired' && pass "windows-build.ps1: cosign signing no longer keyed on \$WindowsSigningRequired" || fail "windows-build.ps1 cosign still gated by Authenticode flag"
gate_line=$(grep -n 'Image(s) without a cosign .bundle' "$PS1" | head -1 | cut -d: -f1)
zip_line=$(grep -n 'Compress-Archive -Path \$OutDir -DestinationPath \$ZipPath' "$PS1" | head -1 | cut -d: -f1)
[ -n "$gate_line" ] && [ -n "$zip_line" ] && [ "$gate_line" -lt "$zip_line" ] && pass "windows-build.ps1: every images\\*.tar must have a .bundle before Compress-Archive" || fail "windows-build.ps1 ZIP gate missing/misplaced"
echo "TEST: runtime image set: orchestrator + postgres + bas-caldera + chrome are ALL required, signed and bound; golang is never shipped"
DIGEST="$(sed -n 's/^CHROME_DIGEST=//p' "$REPO/packaging/images.pin")"
echo "$DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$' && pass "images.pin carries a sha256 digest" || fail "images.pin digest malformed"
grep -q "image: $CHROME_TAG\$" "$REPO/packaging/compose/docker-compose.yml" && pass "compose chrome image == images.pin version tag (no :latest)" || fail "compose chrome tag drifted from images.pin"
for f in packaging/compose/setup.sh packaging/compose/install.sh packaging/airgap/cosign-verify-lib.sh; do
  grep -q "\"$CHROME_TAG\"" "$REPO/$f" && pass "$f expects $CHROME_TAG" || fail "$f chrome tag drifted from images.pin"
done
grep -Eq '^FROM ghcr.io/mitre/caldera:[0-9][0-9.]*@sha256:[0-9a-f]{64}$' "$REPO/packaging/caldera/Dockerfile" && pass "caldera base pinned by version and digest" || fail "caldera base not pinned"
! grep -rn "caldera-latest\|ghcr.io/mitre/caldera:latest\|headless-shell:latest" "$REPO/packaging/compose" "$REPO/packaging/airgap" "$REPO/packaging/build.sh" "$REPO/packaging/windows-build.ps1" --include=*.sh --include=*.yml --include=*.ps1 --exclude=uninstall.sh | grep -v "airgap-cosign.test.sh" | grep -q . && pass "no :latest / stock-caldera fallback left in runtime paths" || fail "stale :latest / stock caldera reference"
! grep -rq "golang:" "$REPO/packaging/airgap/pack.sh" "$REPO/packaging/build.sh" "$REPO/packaging/signing/release-images.sh" "$REPO/packaging/compose/setup.sh" "$REPO/packaging/compose/install.sh" && pass "golang image not shipped by any bundle script" || fail "golang referenced by a bundle script"
for missing in headless-shell.tar headless-shell.tar.bundle bas-caldera-9.9.9.tar bas-caldera-9.9.9.tar.bundle; do
  MUTATE="rm \"\$b/images/$missing\"" make_bundle "$T/b.tar.gz"
  expect_abort "import: bundle missing $missing is refused (nothing loaded)"
done
MUTATE='echo tampered >> "$b/images/headless-shell.tar"' make_bundle "$T/b.tar.gz"
expect_abort "import: tampered chrome tar refused"
MUTATE='mk_image_tar "$b/images/bas-caldera-9.9.9.tar" "\"bas-caldera:9.9.9\",\"bas-orchestrator:9.9.9\"" caldera; sign_tar "$b/images/bas-caldera-9.9.9.tar"' make_bundle "$T/b.tar.gz"
expect_abort "import: caldera tar carrying an extra orchestrator tag refused"
MUTATE='mk_image_tar "$b/images/headless-shell.tar" "\"chromedp/headless-shell:latest\"" chrome; sign_tar "$b/images/headless-shell.tar"' make_bundle "$T/b.tar.gz"
expect_abort "import: chrome tar not carrying the pinned version tag refused"
MUTATE="" make_bundle "$T/b.tar.gz"
for missing in headless-shell.tar bas-caldera-9.9.9.tar; do
  MUTATE="rm \"\$b/images/$missing\"" stage_setup
  sv_ok && fail "setup.sh accepted bundle without $missing" || pass "setup.sh: bundle without $missing is fatal"
  MUTATE="rm \"\$b/images/$missing.bundle\"" stage_setup
  sv_ok && fail "setup.sh accepted unsigned $missing" || pass "setup.sh: unsigned $missing is fatal"
done
MUTATE="" stage_setup

echo "TEST: postgres pin + no fail-open path: compose never pulls, nothing pulls in a bundle path"
PGT="$(sed -n 's/^POSTGRES_TAG=//p' "$REPO/packaging/images.pin")"
[ "$PGT" = "16-alpine" ] && grep -Eq '^POSTGRES_DIGEST=sha256:[0-9a-f]{64}$' "$REPO/packaging/images.pin" && pass "images.pin pins POSTGRES_TAG=16-alpine + a sha256 POSTGRES_DIGEST" || fail "images.pin postgres pin missing/malformed"
grep -q "image: postgres:${PGT}\$" "$REPO/packaging/compose/docker-compose.yml" && pass "compose postgres image == images.pin tag" || fail "compose postgres tag drifted from images.pin"
for f in packaging/compose/setup.sh packaging/compose/install.sh packaging/airgap/cosign-verify-lib.sh; do
  grep -q "\"postgres:${PGT}\"" "$REPO/$f" && pass "$f expects postgres:${PGT}" || fail "$f postgres tag drifted from images.pin"
done
for svc in postgres caldera chrome orchestrator; do
  blk=$(awk -v s="  ${svc}:" '$0==s {f=1; print; next} f && /^  [a-z][a-z-]*:$/ {exit} f' "$REPO/packaging/compose/docker-compose.yml")
  grep -q '^    pull_policy: never$' <<<"$blk" && pass "compose: ${svc} has pull_policy: never" || fail "compose: ${svc} may be pulled (no pull_policy: never)"
done
! grep -nE 'compose[^#]*[[:space:]]pull\b|docker pull' "$REPO/packaging/compose/setup.sh" "$REPO/packaging/compose/install.sh" "$REPO/packaging/airgap/import.sh" "$REPO/packaging/iso/autoinstall/scripts/post-install.sh" "$REPO/packaging/packer/scripts/install-bas.sh" | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' | grep -q . && pass "no compose/docker pull reachable in setup.sh, install.sh, import.sh, ISO or Packer paths" || fail "a pull is still reachable in a bundle path"
! grep -Eq 'headless-shell:(latest|[0-9])' "$REPO/packaging/compose/uninstall.sh" && grep -q 'chromedp/headless-shell):' "$REPO/packaging/compose/uninstall.sh" && pass "uninstall.sh matches chromedp/headless-shell:* (no hardcoded chrome tag)" || fail "uninstall.sh hardcodes a chrome tag"

echo "TEST: setup.sh flags + images/ forces the verify path (real parse_args / _do_install_steps)"
{ extract_fn "$SETUP" parse_args; extract_fn "$SETUP" _do_install_steps; } > "$T/setup-main-fns.sh"
NOIMG="$T/noimg"; rm -rf "$NOIMG"; mkdir -p "$NOIMG"; printf 'fake-pub' > "$NOIMG/cosign.pub"
run_setup_main() { # <script dir> <args...>   parse_args "$@" then _do_install_steps (stops at its first _step)
  local sd="$1"; shift
  : > "$STUB_LOG"
  PATH="$STUBS:$PATH" bash -c '
    set -euo pipefail
    err() { echo "ERR: $*" >&2; }; warn() { echo "WARN: $*"; }; log() { echo "$*"; }
    _step() { echo "STEP $1" >> "$STUB_LOG"; exit 42; }
    SCRIPT_DIR="$1"; shift; BAS_VERSION=9.9.9; OFFLINE=false; NO_WIZARD=false; CONFIG_FILE=""; GPG_PUB_FLAG=""
    source "$T_FNS"; source "$T_MAIN"
    parse_args "$@"
    echo "PARSED OFFLINE=$OFFLINE NOWIZ=$NO_WIZARD CONFIG=$CONFIG_FILE GPG=$GPG_PUB_FLAG COSIGN=${BAS_COSIGN_PUB:-}"
    [ -n "${PARSE_ONLY:-}" ] && exit 0
    _do_install_steps' _ "$sd" "$@" > "$T/out.txt" 2>&1
}
export T_FNS="$T/setup-fns.sh" T_MAIN="$T/setup-main-fns.sh"
MUTATE="" stage_setup
rc=0; run_setup_main "$SX" || rc=$?
if [ "$rc" -eq 42 ] && grep -q "PARSED OFFLINE=true" "$T/out.txt" && [ "$(grep -c '^cosign verify-blob' "$STUB_LOG")" -eq 4 ]; then pass "setup.sh WITHOUT --offline but with images/: verify path forced (all 4 images verified before the first step)"; else fail "setup.sh without --offline did not verify (rc=$rc)"; cat "$T/out.txt"; fi
MUTATE='echo evil >> "$b/images/postgres-16-alpine.tar"' stage_setup
rc=0; run_setup_main "$SX" || rc=$?
[ "$rc" -ne 0 ] && [ "$rc" -ne 42 ] && pass "setup.sh without --offline: tampered image is fatal before anything is written" || fail "setup.sh without --offline accepted a tampered image (rc=$rc)"
rc=0; run_setup_main "$NOIMG" || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 42 ] && grep -q "refusing to install" "$T/out.txt" && ! grep -q "pull" "$STUB_LOG"; then pass "setup.sh with no images/: fatal, nothing pulled"; else fail "setup.sh with no images/ (rc=$rc)"; cat "$T/out.txt"; fi
rc=0; run_setup_main "$NOIMG" --offline || rc=$?
[ "$rc" -ne 0 ] && [ "$rc" -ne 42 ] && grep -q "images/ directory not found" "$T/out.txt" && pass "setup.sh --offline with no images/: fatal" || fail "setup.sh --offline without images (rc=$rc)"
MUTATE="" stage_setup
pa_ok() { local rc=0; PARSE_ONLY=1 run_setup_main "$@" || rc=$?; [ "$rc" -eq 0 ]; }
pa_ok "$SX" --offline --no-wizard --config "$T/x.conf" --gpg-pub "$T/k.asc" --cosign-pub "$T/k.pub" --non-interactive --web \
  && grep -q "PARSED OFFLINE=true NOWIZ=true CONFIG=$T/x.conf GPG=$T/k.asc COSIGN=$T/k.pub" "$T/out.txt" \
  && pass "setup.sh: every supported flag still works (--offline --no-wizard --config --gpg-pub --cosign-pub --non-interactive --web)" || { fail "setup.sh supported flags"; cat "$T/out.txt"; }
pa_ok "$SX" --gpg-pub="$T/k.asc" --cosign-pub="$T/k.pub" --config="$T/x.conf" && grep -q "GPG=$T/k.asc COSIGN=$T/k.pub" "$T/out.txt" && pass "setup.sh: --flag=<value> forms" || fail "setup.sh = forms"
BAS_COSIGN_PUB="$T/env.pub" pa_ok "$SX" --cosign-pub "$T/k.pub" && grep -q "COSIGN=$T/k.pub" "$T/out.txt" && pass "setup.sh: --cosign-pub beats BAS_COSIGN_PUB" || fail "setup.sh cosign flag/env precedence"
for bad in "--gpg-pub" "--cosign-pub" "--config" "--gpg-pub=" "--cosign-pub=" "--gpg-pub --offline" "--cosgn-pub $T/k.pub" "--bogus"; do
  # shellcheck disable=SC2086
  if pa_ok "$SX" $bad; then fail "setup.sh accepted: $bad"; else pass "setup.sh rejects: $bad"; fi
done

echo "TEST: install.sh mode_install / mode_upgrade (real functions): images/ required, verify first, orchestrator loaded last"
{ cat "$T/inst-fns.sh"; extract_fn "$INST" mode_install; extract_fn "$INST" mode_upgrade; } > "$T/inst-mode-fns.sh"
run_mode() { # <mode_install|mode_upgrade> <script dir>   stops (rc 42) at the step after the image load
  : > "$STUB_LOG"; rm -rf "$DOCKER_STATE" "$T/datadir"; mkdir -p "$DOCKER_STATE" "$T/datadir"
  if [ "$1" = mode_upgrade ]; then : > "$T/datadir/docker-compose.yml"; echo "BAS_ENROLL_PORT=9443" > "$T/datadir/.env"; fi
  PATH="$STUBS:$PATH" bash -c '
    set -euo pipefail
    err() { echo "ERR: $*" >&2; }; warn() { echo "WARN: $*"; }; info() { echo "$*"; }; log() { echo "$*"; }
    step() { echo "STEP $*" >> "$STUB_LOG"; case "$*" in 5/10*|3/5*) exit 42 ;; esac; }
    load_config() { :; }; render_checks() { return 0; }; chown() { :; }
    for f in _check_os _check_docker _check_compose _check_cosign _check_ram _check_cpu _check_disk _check_port _check_dns_sink_port _check_openssl _check_bundle_integrity _check_licence _check_tls_certs; do eval "$f() { echo PASS:stub; }"; done
    SCRIPT_DIR="$2"; DATA_DIR="$3"; CONFIG_FILE=x; BAS_VERSION=9.9.9; YES=true; NEED_DOCKER=false; NEED_COMPOSE=false
    BAS_TLS=false; BAS_PORT=1; BAS_ENROLL_PORT=2; BAS_LEGACY_PORT=3; BAS_DASHBOARD_PORT=4; DNS_SINK_BIND_IP=x; LIC_PATH=x; PRODUCT=x
    COSIGN_PUB_FLAG=""; COSIGN_PUB_USED="$2/cosign.pub"
    source "$4"; _resolve_cosign_pub
    "$1"' _ "$1" "$2" "$T/datadir" "$T/inst-mode-fns.sh" > "$T/out.txt" 2>&1
}
want_order="LOADED bas-caldera:9.9.9|LOADED $CHROME_TAG|LOADED postgres:16-alpine|LOADED bas-orchestrator:9.9.9|"
for m in mode_install mode_upgrade; do
  MUTATE="" stage_setup
  rc=0; run_mode "$m" "$SX" || rc=$?
  seq=$(grep '^LOADED' "$STUB_LOG" | tr '\n' '|')
  lastverify=$(grep -n '^cosign verify-blob' "$STUB_LOG" | tail -1 | cut -d: -f1); firstload=$(grep -n '^LOADED' "$STUB_LOG" | head -1 | cut -d: -f1)
  if [ "$rc" -eq 42 ] && [ "$seq" = "$want_order" ] && [ -n "$firstload" ] && [ "$lastverify" -lt "$firstload" ]; then pass "install.sh $m: all 4 verified, then loaded with the orchestrator LAST"; else fail "install.sh $m load loop (rc=$rc seq=$seq)"; cat "$T/out.txt"; fi
  rc=0; FAKE_DOCKER_CLOBBER=1 run_mode "$m" "$SX" || rc=$?
  [ "$rc" -ne 0 ] && [ "$rc" -ne 42 ] && grep -q "not the verified image after load" "$T/out.txt" && pass "install.sh $m: post-load orchestrator ID mismatch is fatal" || fail "install.sh $m post-load ID (rc=$rc)"
  rc=0; run_mode "$m" "$NOIMG" || rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 42 ] && grep -q "images/ directory not found" "$T/out.txt" && ! grep -q '^LOADED' "$STUB_LOG" && ! grep -Eq '^STEP ([2-9]/|1/5)' "$STUB_LOG"; then pass "install.sh $m with no images/: FATAL before anything is installed, backed up or written (nothing pulled)"; else fail "install.sh $m without images/ (rc=$rc)"; cat "$T/out.txt"; fi
  MUTATE='echo evil >> "$b/images/postgres-16-alpine.tar"' stage_setup
  rc=0; run_mode "$m" "$SX" || rc=$?
  [ "$rc" -ne 0 ] && [ "$rc" -ne 42 ] && ! grep -q '^LOADED' "$STUB_LOG" && pass "install.sh $m: tampered postgres -> nothing loaded" || fail "install.sh $m tampered (rc=$rc)"
done
[ ! -e "$T/datadir/backups" ] && pass "install.sh mode_upgrade: a refused bundle writes no backup" || fail "mode_upgrade wrote a backup before verifying"
MUTATE="" stage_setup

echo "TEST: import.sh checks free space in \${TMPDIR:-/tmp} before copying"
REAL_DF="$(command -v df)"
cat > "$STUBS/df" <<DFEOF
#!/usr/bin/env bash
if [ -n "\${FAKE_DF_KB:-}" ]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfake 1 1 %s 1%% /\n' "\$FAKE_DF_KB"; exit 0; fi
exec "$REAL_DF" "\$@"
DFEOF
chmod +x "$STUBS/df"
MUTATE="" make_bundle "$T/b.tar.gz"
FAKE_DF_KB=1 expect_abort "import.sh: too little free space in TMPDIR -> abort before copying"
grep -q "Not enough free space" "$T/out.txt" && grep -q "TMPDIR" "$T/out.txt" && pass "free-space error is clear and names TMPDIR" || fail "free-space message"
need_kb=$(( ( $(wc -c < "$T/b.tar.gz") + 1023 ) / 1024 * 3 ))
FAKE_DF_KB=$((need_kb - 1)) expect_abort "import.sh: just under 3x the bundle size -> abort"
FAKE_DF_KB=$need_kb check_valid "import.sh: exactly 3x the bundle size free -> proceeds"
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
  # ── Trust bootstrap: run the ONE canonical snippet against a POLLUTED default
  # GNUPGHOME ($GNUPGHOME holds A and attacker B, B's secret key included) ──
  SNIP="$REPO/packaging/airgap/trust-bootstrap.sh"
  awk '/<a id="trust-bootstrap">/{f=1} f && /^```bash/{g=1; next} g && /^```/{exit} g' "$REPO/docs/guides/installation.md" | tr -d '\r' > "$T/doc-snip.txt"
  grep -v '^# shellcheck ' "$SNIP" > "$T/canon-snip.txt"   # the file's only extra line is the shellcheck directive
  cmp -s "$T/doc-snip.txt" "$T/canon-snip.txt" && pass "trust bootstrap: installation.md shows exactly the canonical snippet" || { fail "trust bootstrap: doc snippet drifted from trust-bootstrap.sh"; diff "$T/doc-snip.txt" "$T/canon-snip.txt"; }
  grep -q 'packaging/airgap/trust-bootstrap.sh' "$REPO/packaging/airgap/pack.sh" && pass "trust bootstrap: pack.sh prints the canonical file" || fail "pack.sh has its own copy of the snippet"
  ! grep -rnF 'GNUPGHOME=$(mktemp' "$REPO/docs/guides/installation.md" "$REPO/packaging/airgap" "$REPO/packaging/build.sh" | grep -v airgap-cosign.test.sh | grep -q . && pass "trust bootstrap: the broken GNUPGHOME= prefix form is gone" || fail "broken GNUPGHOME= prefix form still present"
  TB="$T/tb"; rm -rf "$TB"; mkdir -p "$TB/tmp"
  cp "$T/b.tar.gz" "$TB/bundle.tar.gz"; cp "$T/gpg-a.asc" "$TB/oob.asc"     # oob key = genuine A
  run_tb() { (cd "$TB" && TMPDIR="$TB/tmp" bash "$SNIP") > "$T/out.txt" 2>&1 || true; }
  gsign b@test.invalid "$TB/bundle.tar.gz"                                  # attacker B signs
  (cd "$TB" && GNUPGHOME=$(TMPDIR="$T" mktemp -d) gpg --import oob.asc >/dev/null 2>&1 && gpg --status-fd 1 --verify bundle.tar.gz.asc bundle.tar.gz) > "$T/old.txt" 2>&1 || true
  grep -q '^\[GNUPG:\] VALIDSIG ' "$T/old.txt" && pass "trust bootstrap control: the OLD prefix form is fooled by the polluted keyring (test discriminates)" || fail "control: old form not fooled -- test does not prove anything"
  run_tb
  ! grep -q '^\[GNUPG:\] VALIDSIG ' "$T/out.txt" && pass "trust bootstrap: attacker-signed bundle gets NO VALIDSIG (only oob.asc can vouch)" || fail "trust bootstrap: the polluted default keyring vouched for the bundle"
  gsign a@test.invalid "$TB/bundle.tar.gz"
  run_tb
  vfpr=$(awk '/^\[GNUPG:\] VALIDSIG /{print toupper($12)}' "$T/out.txt")
  [ "$vfpr" = "$(tr '[:lower:]' '[:upper:]' <<<"$FPA")" ] && pass "trust bootstrap: genuine bundle -> VALIDSIG primary fingerprint = oob key" || { fail "trust bootstrap genuine ($vfpr)"; cat "$T/out.txt"; }
  [ -z "$(ls -A "$TB/tmp")" ] && pass "trust bootstrap: temp homedir removed (rm -rf \"\$H\")" || fail "trust bootstrap left its temp homedir behind"

  # ── Signing SUBKEY: VALIDSIG field 3 is the subkey, field 12 the primary ──
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "C <c@test.invalid>" ed25519 cert never >/dev/null 2>&1
  FPC=$(gpg --with-colons --list-keys c@test.invalid | awk -F: '/^fpr/{print $10; exit}')
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$FPC" ed25519 sign never >/dev/null 2>&1
  gpg --armor --export c@test.invalid > "$T/gpg-c.asc"
  gsign c@test.invalid "$T/b.tar.gz"
  st=$(gpg --status-fd 1 --verify "$T/b.tar.gz.asc" "$T/b.tar.gz" 2>/dev/null | grep '^\[GNUPG:\] VALIDSIG ' || true)
  if [ -n "$st" ] && [ "$(awk '{print $3}' <<<"$st")" != "$FPC" ] && [ "$(awk '{print $12}' <<<"$st")" = "$FPC" ]; then pass "subkey fixture: signature made by a signing SUBKEY (field 3 != primary, field 12 = primary)"; else fail "subkey fixture did not sign with a subkey: $st"; fi
  if gok vs --gpg-pub "$T/gpg-c.asc" && grep -q "signed by key ${FPC}" "$T/out.txt"; then pass "verify-sig.sh: subkey signature accepted (VALIDSIG primary = the key's primary)"; else fail "verify-sig.sh rejected a subkey signature"; cat "$T/out.txt"; fi
  printf 'agent-binary-bytes' > "$AG/agents/bas-agent-linux-amd64"
  gsign c@test.invalid "$AG/agents/BINARIES.sha256"
  if vb_ok BAS_GPG_PUB="$T/gpg-c.asc"; then pass "setup.sh agents: subkey-signed manifest accepted"; else fail "setup.sh agents rejected a subkey signature"; cat "$T/out.txt"; fi
  if vb_ok BAS_GPG_PUB="$T/gpg-a.asc"; then fail "setup.sh agents: C's subkey signature accepted for key A"; else pass "setup.sh agents: subkey signature still bound to ITS primary (key A refused)"; fi
  gsign a@test.invalid "$T/b.tar.gz"
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

echo "TEST: operator docs never instruct a raw docker load (it skips signature, tag and image-ID checks)"
# docs/superpowers/ is excluded: dated design plans/specs that record how the
# verify-before-load code was built, not operator instructions.
raw_load=$(find "$REPO/docs" "$REPO/packaging" -name '*.md' -not -path "$REPO/docs/superpowers/*" -print0 \
  | xargs -0 grep -nE 'docker load([[:space:]]*<|[[:space:]]+(-i|--input)([[:space:]=]|$))' | grep -iv 'do not' || true)
[ -z "$raw_load" ] && pass "docs: no raw 'docker load' instruction in docs/ or packaging/ *.md" || { fail "docs: raw 'docker load' instruction found"; echo "$raw_load"; }

echo "TEST: every compose up in shipped scripts/units carries --pull never (no-pull holds even with an old, restored compose file)"
# --rollback / --restore put back an older docker-compose.yml that may lack
# pull_policy: never; the CLI flag makes the invariant independent of the file.
compose_up=$(find "$REPO/packaging" \( -name '*.sh' -o -name '*.service' \) ! -name airgap-cosign.test.sh -print0 \
  | xargs -0 grep -nE 'docker[- ]compose([[:space:]][^#]*)?[[:space:]](up|create|run)([[:space:]]|$|")' \
  | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' || true)
[ -n "$compose_up" ] && pass "found $(wc -l <<<"$compose_up") compose up/create/run invocations to check" || fail "no compose up invocation found (scan broken)"
no_pull=$(grep -v -- '--pull never' <<<"$compose_up" || true)
[ -z "$no_pull" ] && pass "every compose up/create/run line has --pull never" || { fail "compose invocation without --pull never"; echo "$no_pull"; }

if [ "$FAILED" -eq 0 ]; then echo "ALL PASS"; else echo "SOME FAILED"; exit 1; fi
