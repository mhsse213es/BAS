#!/usr/bin/env bash
# BAS Platform -- offline acceptance test for the air-gap bundle.
#
# Proves a bundle is OFFLINE-COMPLETE: inside an ISOLATED Docker-in-Docker
# daemon that has NO registry access, the REAL import.sh copies, checks, cosign-
# verifies and loads every image, then at its setup.sh hand-off setup.sh's own
# (extracted, unmodified) verify + load functions run against the staged
# compose/ dir, and the stack is started with `docker compose -p audspect up -d --pull never`
# (the exact command bas-compose.service runs). Any image Docker would silently
# pull makes the test fail.
#
# NOT run inside the test daemon: the rest of setup.sh (licence check, whiptail/
# web wizard, systemd unit) -- the dind container has no systemd. A PATH shim
# for `bash` intercepts exactly the `bash compose/setup.sh` call import.sh makes.
# The bundle carries no bas.lic, so the orchestrator is EXPECTED to start, run
# its crypto self-test and then crash-loop ("restarting") on the missing
# licence; that proves the verified image executed, not that it is healthy.
#
# Host side effects: building the bundle runs the real pack.sh against the HOST
# Docker daemon, which pulls postgres/chrome by digest (re-pointing the host's
# postgres:16-alpine and chromedp/headless-shell:<ver> tags at the pinned
# digests), builds and tags bas-caldera:<version>, and saves images. Host images
# are never removed. The isolation harness adds a private network, one dind
# container with its anonymous volumes, a harness image tag and a temp dir, all
# removed on exit.
#
# Usage (run from anywhere; needs docker, bash, go, cosign on PATH, internet for
# the bundle build step and for pulling docker:dind/building the harness image
# BEFORE isolation):
#   bash packaging/airgap/offline-acceptance.sh [version]        # build a bundle with the real pack.sh
#   SAVE_BUNDLE=/path/keep.tar.gz  keeps the freshly built bundle for re-runs
#   BUNDLE=/path/bas-airgap-<ver>.tar.gz bash ... [version]      # test an existing bundle (skips pack.sh)
#
# [version] must match a local image bas-orchestrator:<version> (pack.sh requires
# it). Without BUNDLE the real pack.sh runs from a throwaway COPY of packaging/,
# scenarios/ and orchestrator/ with a throwaway cosign key (the repo's release
# key is never needed or used).
#
# Result: prints PASS / FAIL lines and "ACCEPTANCE: PASS|FAIL"; exit status 0 only on PASS.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
VERSION="${1:-}"
[[ -n "$VERSION" ]] || { echo "usage: $0 <version>   (a local bas-orchestrator:<version> image must exist)" >&2; exit 2; }

# Git Bash on Windows rewrites /work style paths; disable that for container paths only.
dk() { MSYS_NO_PATHCONV=1 docker "$@"; }
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }

ID="acc$$"
NET="${ID}-net"
DIND="${ID}-dind"
HARNESS="bas-offline-harness:${ID}"
WORK="$(mktemp -d)"
FAILED=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

# shellcheck disable=SC2329  # invoked via trap cleanup EXIT below
cleanup() {
  docker rm -fv "$DIND" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker rmi "$HARNESS" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ── 1. The bundle ─────────────────────────────────────────────────────────────
if [[ -n "${BUNDLE:-}" ]]; then
  [[ -f "$BUNDLE" ]] || { echo "BUNDLE not found: $BUNDLE" >&2; exit 2; }
else
  echo "== Building the bundle with the real pack.sh (throwaway copy + throwaway cosign key)"
  SB="$WORK/repo"
  mkdir -p "$SB"
  cp -r "$REPO_ROOT/packaging" "$SB/packaging"
  cp -r "$REPO_ROOT/scenarios" "$SB/scenarios"
  # orchestrator/ (Go module): pack.sh's release gate verifies the builtin
  # scenario signatures with `go run scripts/signer.go verify-all`.
  cp -r "$REPO_ROOT/orchestrator" "$SB/orchestrator"
  mkdir -p "$SB/orchestrator/wwwroot"
  rm -f "$SB/packaging/signing/cosign.key" "$SB/packaging/signing/cosign.pub"
  (cd "$SB/packaging/signing" && COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix "$SB/packaging/signing/cosign" >/dev/null)
  # Empty GNUPGHOME: pack.sh then skips its optional GPG step (the test bundle is never signed with a real release key).
  mkdir -p "$WORK/gnupg-empty"; chmod 700 "$WORK/gnupg-empty"
  GOWORK=off GNUPGHOME="$WORK/gnupg-empty" bash "$SB/packaging/airgap/pack.sh" "$VERSION"
  BUNDLE="$SB/dist/bas-airgap-${VERSION}.tar.gz"
fi
[[ -n "${SAVE_BUNDLE:-}" && "$BUNDLE" != "$SAVE_BUNDLE" ]] && cp "$BUNDLE" "$SAVE_BUNDLE" && BUNDLE="$SAVE_BUNDLE"
BUNDLE_BYTES=$(wc -c < "$BUNDLE")
echo "Bundle: $BUNDLE ($((BUNDLE_BYTES / 1048576)) MiB)"

# ── 2. Bundle contents: all four runtime images, each signed ──────────────────
LIST="$WORK/list.txt"
tar -tzf - < "$BUNDLE" > "$LIST"   # stdin form: GNU tar reads "C:/..." as host:path
for img in "bas-orchestrator-${VERSION}.tar" postgres-16-alpine.tar headless-shell.tar "bas-caldera-${VERSION}.tar"; do
  if grep -q "/images/${img}\$" "$LIST" && grep -q "/images/${img}.bundle\$" "$LIST"; then pass "bundle ships ${img} + .bundle"; else fail "bundle is missing ${img} or its .bundle"; fi
done
if grep -q "/images/.*golang" "$LIST"; then fail "bundle ships a golang image"; else pass "no golang image in the bundle"; fi

# ── 3. Isolated, registry-less test daemon ────────────────────────────────────
echo "== Preparing the isolated Docker-in-Docker daemon"
docker image inspect docker:dind >/dev/null 2>&1 || docker pull docker:dind
docker image inspect gcr.io/projectsigstore/cosign:v3.1.3 >/dev/null 2>&1 || docker pull gcr.io/projectsigstore/cosign:v3.1.3
cat > "$WORK/Dockerfile" <<'EOF'
FROM docker:dind
RUN apk add --no-cache bash coreutils openssl gnupg tar gzip
COPY --from=gcr.io/projectsigstore/cosign:v3.1.3 /ko-app/cosign /usr/local/bin/cosign
EOF
docker build -q -t "$HARNESS" "$WORK" >/dev/null
docker network create --internal "$NET" >/dev/null
docker run -d --privileged --name "$DIND" --network "$NET" -e DOCKER_TLS_CERTDIR= "$HARNESS" >/dev/null
for _ in $(seq 1 60); do dk exec "$DIND" docker info >/dev/null 2>&1 && break; sleep 2; done
dk exec "$DIND" docker info >/dev/null 2>&1 || { fail "dind daemon did not start"; echo "ACCEPTANCE: FAIL"; exit 1; }

# Control: the isolation must actually block registries, or a pass proves nothing.
if dk exec "$DIND" docker pull alpine >/dev/null 2>&1; then
  fail "ISOLATION BROKEN: 'docker pull alpine' succeeded inside the test daemon"
  echo "ACCEPTANCE: FAIL"; exit 1
fi
pass "control: 'docker pull alpine' FAILS inside the test daemon (no registry access)"
if [[ -n "$(dk exec "$DIND" docker images -q)" ]]; then fail "test daemon is not empty before the test"; else pass "test daemon starts with zero images"; fi

# ── 4. Verify + load + start, inside the isolated daemon ──────────────────────
dk exec "$DIND" mkdir -p /work
dk cp "$(hostpath "$BUNDLE")" "$DIND:/work/bundle.tar.gz"
cat > "$WORK/inner.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VER="$1"
cd /work
# Only the bundle's verifier/importer scripts are unpacked here; import.sh does
# its own private copy + extraction under $TMPDIR.
mkdir -p /work/tools
tar -xzf bundle.tar.gz -C /work/tools --strip-components=1 \
  "bas-airgap-${VER}/verify.sh" "bas-airgap-${VER}/import.sh" "bas-airgap-${VER}/cosign-verify-lib.sh"
# Record every image pull the daemon attempts for the rest of this run.
docker events --filter type=image --filter event=pull > /work/pull-events.log 2>&1 &
EVPID=$!
echo "== verify.sh (bundle's own integrity + signature check)"
bash /work/tools/verify.sh "/work/bundle.tar.gz" || { echo "INNER-FAIL verify.sh"; exit 11; }

# PATH shim: `bash <bundle>/compose/setup.sh ...` (import.sh's hand-off) runs
# setup-handoff.sh instead; every other `bash` call is the real bash.
mkdir -p /work/shim
cat > /work/shim/bash <<'SH'
#!/bin/sh
case "${1:-}" in
  */compose/setup.sh) exec /bin/bash /work/setup-handoff.sh "$@" ;;
esac
exec /bin/bash "$@"
SH
chmod +x /work/shim/bash
cat > /work/setup-handoff.sh <<'SH'
#!/bin/bash
# Runs setup.sh's OWN image verify + load functions, extracted unmodified from
# the bundle's setup.sh, against its staged compose/ dir (images/ -> ../images).
set -euo pipefail
SETUP="$1"; shift
D="$(cd "$(dirname "$SETUP")" && pwd)"
echo "SETUP-HANDOFF reached: setup.sh $*"
extract_fn() { awk -v n="$2" '$0 ~ "^"n"\\(\\) \\{" {p=1} p{print} p && /^}/ {exit}' "$1"; }
for fn in _key_fp _tar_image_id _docker_tag_is _verify_orchestrator_artifact _expected_image_tag _verify_all_images _load_verified_images; do
  extract_fn "$SETUP" "$fn"
done > /work/setup-fns.sh
log() { echo "$*"; }; err() { echo "ERR: $*" >&2; }; warn() { echo "WARN: $*"; }
SCRIPT_DIR="$D"; BAS_VERSION="$(tr -d '[:space:]' < "$D/VERSION")"
# shellcheck disable=SC1091
source /work/setup-fns.sh
_verify_all_images "$D/images" "installation"
_load_verified_images "installation"
echo "SETUP-VERIFY-LOAD-OK"
# Keep the staged compose/ dir (minus the images symlink) for `compose up`:
# import.sh deletes its private work dir on exit.
rm -rf /work/staged-compose; mkdir /work/staged-compose
(cd "$D" && tar --exclude=./images -cf - .) | tar -xf - -C /work/staged-compose
SH
echo "== REAL import.sh: private copy, manifest, verify + load all images, :latest, setup.sh hand-off"
# The dind container's /tmp is small; use the documented TMPDIR override.
mkdir -p /work/itmp; df -h /tmp /work/itmp || true
PATH="/work/shim:$PATH" TMPDIR=/work/itmp bash /work/tools/import.sh /work/bundle.tar.gz --non-interactive || { echo "INNER-FAIL import.sh"; exit 12; }
[[ -f /work/staged-compose/docker-compose.yml ]] || { echo "INNER-FAIL setup.sh hand-off not reached"; exit 12; }
cd /work/staged-compose
echo "== docker compose -p audspect up -d --pull never  (exact bas-compose.service command)"
cp .env.example .env
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
sed -i \
  -e "s|^BAS_VERSION=.*|BAS_VERSION=${VER}|" \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rnd 16)|" \
  -e "s|^JWT_SECRET=.*|JWT_SECRET=$(rnd 32)|" \
  -e "s|^AGENT_SECRET=.*|AGENT_SECRET=$(rnd 24)|" \
  -e "s|^BAS_ADMIN_EMAIL=.*|BAS_ADMIN_EMAIL=acceptance@example.invalid|" \
  -e "s|^BAS_ADMIN_PASSWORD=.*|BAS_ADMIN_PASSWORD=$(rnd 12)|" \
  -e "s|^CALDERA_API_KEY=.*|CALDERA_API_KEY=$(rnd 12)|" \
  -e "s|^CALDERA_API_KEY_BLUE=.*|CALDERA_API_KEY_BLUE=$(rnd 12)|" .env
echo "BAS_APP_DB_PASSWORD=$(rnd 16)" >> .env
grep -q '^DNS_SINK_BIND_IP=' .env || echo "DNS_SINK_BIND_IP=127.0.0.1" >> .env
if ! docker compose -p audspect up -d --pull never --remove-orphans; then echo "INNER-FAIL compose up"; kill $EVPID 2>/dev/null || true; exit 13; fi
sleep 25
kill $EVPID 2>/dev/null || true
echo "== orchestrator log tail"; docker logs --tail 15 audspect-orchestrator 2>&1 || true
echo "== services"
docker compose -p audspect ps -a --format '{{.Service}} {{.State}}'
echo "== expected (non-profile) services"
docker compose -p audspect config --services
echo "== pull events"
cat /work/pull-events.log
echo "PULL-EVENT-COUNT=$(grep -c . /work/pull-events.log || true)"
EOF
dk cp "$(hostpath "$WORK/inner.sh")" "$DIND:/work/inner.sh"
INNER_RC=0
dk exec "$DIND" bash /work/inner.sh "$VERSION" 2>&1 | tee "$WORK/inner.out" || INNER_RC=${PIPESTATUS[0]}

# shellcheck disable=SC2015  # pass/fail only echo (always succeed): C runs only when A fails
grep -q "INNER-FAIL" "$WORK/inner.out" && fail "inner step failed: $(grep INNER-FAIL "$WORK/inner.out")" || pass "bundle verify.sh, the real import.sh (verify + load), setup.sh's verify + load functions, and compose up all succeeded offline"
if grep -q "^SETUP-HANDOFF reached: setup.sh --offline" "$WORK/inner.out" && grep -q "^SETUP-VERIFY-LOAD-OK" "$WORK/inner.out"; then pass "import.sh handed off to setup.sh --offline, whose own verify + load passed"; else fail "setup.sh hand-off / verify + load not observed"; fi
if grep -q "Not enough free space" "$WORK/inner.out"; then fail "import.sh free-space check refused (test daemon disk too small)"; fi

# ── 5. Assertions ─────────────────────────────────────────────────────────────
[[ "$INNER_RC" -eq 0 ]] || fail "inner script exited ${INNER_RC}"
EXPECTED="$(dk exec "$DIND" sh -c "cd /work/staged-compose && docker compose -p audspect config --services" 2>/dev/null | sort || true)"
STATES="$(dk exec "$DIND" docker compose -p audspect ps -a --format '{{.Service}} {{.State}}' 2>/dev/null || true)"
for svc in $EXPECTED; do
  # "restarting" is accepted for the orchestrator only: this test deliberately has no bas.lic, so
  # the real orchestrator starts, runs its self-test and exits on the missing licence (checked below).
  if echo "$STATES" | grep -q "^${svc} running" || { [[ "$svc" == orchestrator ]] && echo "$STATES" | grep -q "^orchestrator restarting"; }; then pass "service ${svc} created and started"; else fail "service ${svc} not started (state: $(echo "$STATES" | grep "^${svc} " || echo none))"; fi
done
[[ -n "$EXPECTED" ]] || fail "could not enumerate compose services"
if grep -q "Crypto self-test passed" "$WORK/inner.out"; then pass "the verified orchestrator image executed (its own self-test ran)"; else fail "orchestrator binary never ran"; fi
if grep -q "^PULL-EVENT-COUNT=0$" "$WORK/inner.out"; then pass "no image pull events recorded by the daemon"; else fail "image pull attempt(s) recorded"; fi
if docker logs "$DIND" 2>&1 | grep -Eqi 'pulling from|PullImage|pull access denied'; then fail "daemon log shows a pull attempt"; else pass "daemon log shows no pull attempts"; fi
LOADED="$(dk exec "$DIND" docker images --format '{{.Repository}}:{{.Tag}}' | sort | tr '\n' ' ')"
echo "Images in the test daemon: $LOADED"

if [[ "$FAILED" -eq 0 ]]; then echo "ACCEPTANCE: PASS (bundle $((BUNDLE_BYTES / 1048576)) MiB)"; else echo "ACCEPTANCE: FAIL"; fi
exit "$FAILED"
