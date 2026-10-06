#!/usr/bin/env bash
# BAS Platform -- offline acceptance test for the air-gap bundle.
#
# Proves a bundle is OFFLINE-COMPLETE: it is verified, loaded and started by
# `docker compose -p audspect up -d` (the exact command bas-compose.service runs)
# inside an ISOLATED Docker-in-Docker daemon that has NO registry access, so any
# image Docker would silently pull makes the test fail.
#
# It never touches the host daemon's images/containers/volumes: the only things
# it creates (a private network, one dind container with its anonymous volumes, a
# harness image tag, a temp dir) are removed on exit.
#
# Usage (run from anywhere; needs docker, bash, cosign on PATH, internet for the
# bundle build step and for pulling docker:dind/building the harness image BEFORE
# isolation):
#   bash packaging/airgap/offline-acceptance.sh [version]        # build a bundle with the real pack.sh
#   SAVE_BUNDLE=/path/keep.tar.gz  keeps the freshly built bundle for re-runs
#   BUNDLE=/path/bas-airgap-<ver>.tar.gz bash ... [version]      # test an existing bundle (skips pack.sh)
#
# [version] must match a local image bas-orchestrator:<version> (pack.sh requires
# it). Without BUNDLE the real pack.sh runs from a throwaway COPY of packaging/
# with a throwaway cosign key (the repo's release key is never needed or used).
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
  mkdir -p "$SB/orchestrator"
  cp -r "$REPO_ROOT/packaging" "$SB/packaging"
  cp -r "$REPO_ROOT/scenarios" "$SB/scenarios"
  if [[ -d "$REPO_ROOT/orchestrator/wwwroot" ]]; then cp -r "$REPO_ROOT/orchestrator/wwwroot" "$SB/orchestrator/wwwroot"; else mkdir -p "$SB/orchestrator/wwwroot"; fi
  rm -f "$SB/packaging/signing/cosign.key" "$SB/packaging/signing/cosign.pub"
  (cd "$SB/packaging/signing" && COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix "$SB/packaging/signing/cosign" >/dev/null)
  # Empty GNUPGHOME: pack.sh then skips its optional GPG step (the test bundle is never signed with a real release key).
  mkdir -p "$WORK/gnupg-empty"; chmod 700 "$WORK/gnupg-empty"
  GNUPGHOME="$WORK/gnupg-empty" bash "$SB/packaging/airgap/pack.sh" "$VERSION"
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
tar -xzf bundle.tar.gz
B="/work/bas-airgap-${VER}"
cd "$B"
# Record every image pull the daemon attempts for the rest of this run.
docker events --filter type=image --filter event=pull > /work/pull-events.log 2>&1 &
EVPID=$!
echo "== verify.sh (bundle's own integrity + signature check)"
bash verify.sh "/work/bundle.tar.gz" || { echo "INNER-FAIL verify.sh"; exit 11; }
echo "== verify + load all runtime images (import.sh's exact functions)"
# shellcheck disable=SC1091
source ./cosign-verify-lib.sh
log() { echo "$*"; }; err() { echo "ERR: $*" >&2; }; warn() { echo "WARN: $*"; }
airgap_verify_and_load_images "$B/images" "$B/cosign.pub" "$VER" || { echo "INNER-FAIL verify+load"; exit 12; }
echo "== setup.sh's own verify step on the staged compose/ dir"
cd "$B/compose"
rm -rf images; ln -s ../images images
echo "== docker compose -p audspect up -d  (exact bas-compose.service command)"
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
if ! docker compose -p audspect up -d --remove-orphans; then echo "INNER-FAIL compose up"; kill $EVPID 2>/dev/null || true; exit 13; fi
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

grep -q "INNER-FAIL" "$WORK/inner.out" && fail "inner step failed: $(grep INNER-FAIL "$WORK/inner.out")" || pass "bundle verify.sh, signed-image verification + load, and compose up all succeeded offline"

# ── 5. Assertions ─────────────────────────────────────────────────────────────
EXPECTED="$(dk exec "$DIND" sh -c "cd /work/bas-airgap-${VERSION}/compose && docker compose -p audspect config --services" 2>/dev/null | sort)"
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
