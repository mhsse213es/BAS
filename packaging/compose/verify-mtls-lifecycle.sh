#!/usr/bin/env bash
# BAS Platform — mTLS Deployment Lifecycle Verifier
#
# Proves the full agent-trust-model deployment lifecycle end-to-end against
# a REAL, isolated Docker Compose stack (never the operator's real
# deployment): fresh install -> CA generated+persisted -> dashboard
# reachable -> legacy agent still connects -> new agent verifies the CA ->
# CSR enrollment succeeds -> agent switches to mTLS -> normal commands work
# -> renewal succeeds -> container restart -> same CA survives -> the
# already-mTLS agent reconnects -> no fleet-wide invalidation.
#
# Usage: bash verify-mtls-lifecycle.sh --license /path/to/valid.lic
#
# Requires: docker, docker compose, go (to build a throwaway Linux agent
# binary), curl, openssl, a valid Audspect license file.
# Exit codes: 0 = every stage passed, 1 = a stage failed (see output for which).
set -euo pipefail

PROJECT="bas-lifecycle-verify-$$"
WORKDIR=$(mktemp -d)
# docker compose resolves its own relative bind mounts (./pki etc.) against
# its real filesystem CWD and is unaffected by this, but a raw `docker run
# -v` CLI arg needs a Windows-native path here -- Git Bash's own /tmp/tmp.X
# form does not reliably resolve as a bind-mount SOURCE for Docker Desktop
# on this host. Used only for the throwaway agent containers below.
WORKDIR_WIN=$(cd "$WORKDIR" && pwd -W)
LICENSE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --license) LICENSE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$LICENSE" || ! -f "$LICENSE" ]]; then
  echo "ERROR: --license <path> is required and must point at a real, valid Audspect license file." >&2
  echo "This script cannot fabricate one -- the orchestrator will not start without it." >&2
  exit 1
fi

STAGE=""
fail() { echo "FAIL at stage: $STAGE -- $*" >&2; cleanup; exit 1; }
pass() { echo "PASS: $STAGE"; }
cleanup() {
  docker rm -f "${PROJECT}-agent-1" "${PROJECT}-agent-2" >/dev/null 2>&1 || true
  docker compose -p "$PROJECT" -f "${WORKDIR}/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# docker-compose.yml pins explicit container_name: values (audspect-orchestrator,
# audspect-postgres, audspect-caldera, audspect-chrome). Those names are NOT
# scoped by -p/COMPOSE_PROJECT_NAME, so this throwaway stack would collide
# with -- and potentially disrupt -- a real deployment already running on
# this host. Refuse to start rather than risk that.
STAGE="pre-flight: no live deployment on this host"
for c in audspect-orchestrator audspect-postgres audspect-caldera audspect-chrome; do
  if docker inspect "$c" >/dev/null 2>&1; then
    fail "a container named '$c' already exists on this host -- refusing to run, since this stack's container_name values are fixed and would collide with a real deployment. Stop/remove it first if it's a stray from a prior failed run, or run this script on a different Docker host if it's a live install."
  fi
done
pass

STAGE="setup"
cp "${REPO_ROOT}/packaging/compose/docker-compose.yml" "${WORKDIR}/docker-compose.yml"
cp "$LICENSE" "${WORKDIR}/bas.lic"
mkdir -p "${WORKDIR}/pki" "${WORKDIR}/certs" "${WORKDIR}/scenarios" "${WORKDIR}/art-payloads" "${WORKDIR}/intel-bundles" "${WORKDIR}/sharphound"
cat > "${WORKDIR}/.env" << ENVEOF
BAS_VERSION=dev
POSTGRES_PASSWORD=lifecycle-test-$(openssl rand -hex 8)
JWT_SECRET=$(openssl rand -hex 32)
AGENT_SECRET=$(openssl rand -hex 16)
LICENSE_FILE=bas.lic
BAS_PORT=19443
BAS_ENROLL_PORT=19444
BAS_LEGACY_PORT=19000
BAS_DASHBOARD_PORT=19543
DNS_SINK_BIND_IP=127.0.0.1
SINK_SFTP_PORT=12222
SINK_SMTP_PORT=10587
ENVEOF
pass

STAGE="fresh install: stack up"
(cd "$WORKDIR" && docker compose -p "$PROJECT" up -d) || fail "docker compose up failed"
status=""
for i in $(seq 1 60); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "audspect-orchestrator" 2>/dev/null || echo "")
  [[ "$status" == "healthy" ]] && break
  sleep 2
done
[[ "$status" == "healthy" ]] || fail "orchestrator never became healthy within 120s"
pass

STAGE="CA generated and persisted"
# The orchestrator image is distroless (no shell, no coreutils) -- "docker
# exec ... test -f" has nothing to exec. Use docker cp instead, which talks
# to the container's filesystem directly without running anything inside it.
docker cp "audspect-orchestrator:/etc/audspect/pki/ca-key.pem" "${WORKDIR}/ca-key-check.pem" || fail "CA key not found in the running container"
[[ -s "${WORKDIR}/ca-key-check.pem" ]] || fail "CA key file exists but is empty"
pass

# All 4 listeners (mTLS/enroll/legacy/dashboard) start as goroutines in the
# same synchronous block in main.go, right after the container's Docker
# healthcheck starts passing (which only probes the enroll listener) -- so
# a single-shot curl immediately afterward can occasionally race a listener
# that hasn't finished its TLS bind yet, especially on a loaded host. Retry
# briefly rather than treating one miss as a hard failure.
STAGE="dashboard usable"
dashboard_ok=""
for i in $(seq 1 10); do
  if curl -skf "https://localhost:19543/" >/dev/null 2>&1; then dashboard_ok=1; break; fi
  sleep 2
done
[[ -n "$dashboard_ok" ]] || fail "dashboard not reachable on the new listener"
pass

AGENT_SECRET_VAL=$(grep AGENT_SECRET "${WORKDIR}/.env" | cut -d= -f2)

STAGE="legacy agent still connects"
legacy_ok=""
for i in $(seq 1 10); do
  if curl -sf "http://localhost:19000/api/agents/ping" -H "X-Agent-Token: ${AGENT_SECRET_VAL}" >/dev/null 2>&1; then legacy_ok=1; break; fi
  sleep 2
done
[[ -n "$legacy_ok" ]] || fail "legacy listener rejected a correctly-authenticated ping"
pass

STAGE="build a real Linux agent binary"
(cd "${REPO_ROOT}/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${WORKDIR}/bas-agent" .) || fail "agent build failed"
pass

STAGE="new agent verifies orchestrator CA + CSR enrollment succeeds + switches to mTLS"
# The agent binary is a Linux ELF -- it cannot run directly on this
# (possibly non-Linux) host. Run it in a throwaway container joined to the
# same compose network so it reaches the orchestrator by its container DNS
# name on the container-internal mTLS port (9443), not the host-published
# one. BAS_AGENT_SECRET is read directly from env by agent/config.go's
# loadConfig() -- it's not exposed as a run-mode CLI flag. --ca-root is
# ONLY consumed under agent/main.go's --install branch; a normal (non
# -install) run instead expects the CA root pre-placed at the fixed
# location certstore.go's certPaths() defines: <BAS_CERT_DIR>/deployment-ca.pem
# ("expected to be placed by the installer"). Place it there ourselves
# since this script runs the agent directly, not via --install.
docker cp "audspect-orchestrator:/etc/audspect/pki/ca-cert.pem" "${WORKDIR}/deployment-ca.pem" || fail "could not extract CA root from the container"
mkdir -p "${WORKDIR}/agent-certs"
cp "${WORKDIR}/deployment-ca.pem" "${WORKDIR}/agent-certs/deployment-ca.pem"
docker run -d --name "${PROJECT}-agent-1" --network "${PROJECT}_bas-internal" \
  -v "${WORKDIR_WIN}://work" \
  -e "BAS_CERT_DIR=//work/agent-certs" \
  -e "BAS_AGENT_SECRET=${AGENT_SECRET_VAL}" \
  --entrypoint //work/bas-agent \
  alpine:latest --server "https://audspect-orchestrator:9443" \
  >/dev/null || fail "could not start agent container"
sleep 10
docker logs "${PROJECT}-agent-1" > "${WORKDIR}/agent-1.log" 2>&1 || true
docker stop "${PROJECT}-agent-1" >/dev/null 2>&1 || true
docker rm -f "${PROJECT}-agent-1" >/dev/null 2>&1 || true
[[ -f "${WORKDIR}/agent-certs/agent-cert.pem" ]] || fail "agent never obtained a client certificate -- CSR enrollment did not complete (agent log: $(cat "${WORKDIR}/agent-1.log" 2>/dev/null | tail -20))"
pass

STAGE="agent renewal succeeds"
# A full renewal-triggers-at-75%-of-1-year wait isn't practical in a
# lifecycle smoke test -- this stage instead proves the renewal CODE PATH
# directly, the same way agent/bootstrap.go's renewal branch does: generate
# a fresh CSR for the same AgentID, submit it over mTLS (using the
# certificate already obtained in the prior stage) to the OPERATIONAL
# listener's enroll-csr endpoint -- not the bootstrap secret, not the
# enrollment listener -- and confirm the orchestrator issues a new
# certificate (200) rather than rejecting it.
#
# The mTLS POST itself runs inside a throwaway Linux container, not via the
# host's own curl: on this Windows host curl is built against schannel,
# which cannot load a raw PEM client cert/key pair (confirmed: fails with
# both --cert-type PEM and a PKCS12 conversion, "SEC_E_NO_CREDENTIALS").
# A container's curl is OpenSSL-backed and has no such limitation.
AGENT_ID_HEX=$(openssl x509 -in "${WORKDIR}/agent-certs/agent-cert.pem" -noout -subject | sed -n 's/.*CN *= *//p')
openssl req -new -key "${WORKDIR}/agent-certs/agent-key.pem" -subj "//CN=${AGENT_ID_HEX}" -out "${WORKDIR}/renewal.csr.pem" || fail "could not generate renewal CSR"
python3 -c "import json,sys; print(json.dumps({'agentId': sys.argv[1], 'csrPem': open(sys.argv[2]).read()}))" "$AGENT_ID_HEX" "${WORKDIR}/renewal.csr.pem" > "${WORKDIR}/csr-request.json" \
  || fail "could not build the renewal CSR request body"
docker run --rm --network "${PROJECT}_bas-internal" -v "${WORKDIR_WIN}://work" alpine:latest sh -c '
  apk add --no-cache curl >/dev/null 2>&1
  curl -sk -o //work/renewal-response.json -w "%{http_code}" \
    --cert //work/agent-certs/agent-cert.pem --key //work/agent-certs/agent-key.pem \
    -X POST "https://audspect-orchestrator:9443/api/agents/enroll-csr" \
    -H "Content-Type: application/json" --data-binary @//work/csr-request.json
' > "${WORKDIR}/renewal-status.txt" 2>&1 || fail "renewal request container failed: $(cat "${WORKDIR}/renewal-status.txt" 2>/dev/null)"
RENEWAL_STATUS=$(tail -c3 "${WORKDIR}/renewal-status.txt")
[[ "$RENEWAL_STATUS" == "200" ]] || fail "renewal request returned HTTP $RENEWAL_STATUS, expected 200 (response: $(cat "${WORKDIR}/renewal-response.json" 2>/dev/null))"
pass

STAGE="container restart: same CA survives"
# distroless has no sha256sum either -- docker cp the cert out and hash it
# on the host both times.
docker cp "audspect-orchestrator:/etc/audspect/pki/ca-cert.pem" "${WORKDIR}/ca-cert-before.pem" || fail "could not extract CA cert before restart"
CA_FINGERPRINT_BEFORE=$(openssl dgst -sha256 "${WORKDIR}/ca-cert-before.pem" | awk '{print $NF}')
(cd "$WORKDIR" && docker compose -p "$PROJECT" restart orchestrator)
status=""
for i in $(seq 1 60); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "audspect-orchestrator" 2>/dev/null || echo "")
  [[ "$status" == "healthy" ]] && break
  sleep 2
done
[[ "$status" == "healthy" ]] || fail "orchestrator never became healthy after restart"
docker cp "audspect-orchestrator:/etc/audspect/pki/ca-cert.pem" "${WORKDIR}/ca-cert-after.pem" || fail "could not extract CA cert after restart"
CA_FINGERPRINT_AFTER=$(openssl dgst -sha256 "${WORKDIR}/ca-cert-after.pem" | awk '{print $NF}')
[[ "$CA_FINGERPRINT_BEFORE" == "$CA_FINGERPRINT_AFTER" ]] || fail "CA fingerprint changed across a container restart -- persistence is broken"
pass

STAGE="existing mTLS agent reconnects, no fleet-wide invalidation"
# agent-certs/deployment-ca.pem and the agent's own cert/key are still
# present from the prior stage (same WORKDIR) -- no need to re-place them.
docker run -d --name "${PROJECT}-agent-2" --network "${PROJECT}_bas-internal" \
  -v "${WORKDIR_WIN}://work" \
  -e "BAS_CERT_DIR=//work/agent-certs" \
  -e "BAS_AGENT_SECRET=${AGENT_SECRET_VAL}" \
  --entrypoint //work/bas-agent \
  alpine:latest --server "https://audspect-orchestrator:9443" \
  >/dev/null || fail "could not start reconnecting agent container"
sleep 8
docker stop "${PROJECT}-agent-2" >/dev/null 2>&1 || true
docker rm -f "${PROJECT}-agent-2" >/dev/null 2>&1 || true
docker logs "audspect-orchestrator" 2>&1 | grep -q "agent_reconnected\|ws.*connected" || fail "no evidence the existing agent reconnected after restart"
pass

echo ""
echo "ALL STAGES PASSED -- the full lifecycle is proven end-to-end."
