#!/bin/bash
# install-agent-linux.sh: installs the BAS agent on this Linux host and fetches the deployment CA
# from the orchestrator's dashboard first (the same URL the Deploy Agent page uses), so no manual
# certificate copy is needed.
#
#   sudo ./install-agent-linux.sh --agent ./bas-agent-linux-amd64 \
#     --server-host 192.168.10.78 --enroll-port 9445 --secret <agent-secret> \
#     [--env Production] [--ca-fingerprint <SHA-256 fingerprint>] [--dashboard-port 9543]
#
# The agent secret comes from the orchestrator's Deploy Agent page (or GET /api/config/connection).
# --ca-fingerprint is strongly recommended: the CA is fetched over TLS that cannot yet be verified
# against that same CA, so without it the first contact is trusted as-is (the fingerprint is printed).
set -euo pipefail

AGENT=""; HOST=""; PORT=""; SECRET=""; ENV="Production"; FINGERPRINT=""; DASH_PORT="9543"
CA_FILE="/etc/audspect-agent/deployment-ca.pem"

usage() { echo "usage: sudo $0 --agent <binary> --server-host <host> --enroll-port <port> --secret <secret> [--env <label>] [--ca-fingerprint <sha256>] [--dashboard-port <port>]" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --agent) AGENT="${2:-}"; shift 2 ;;
    --server-host) HOST="${2:-}"; shift 2 ;;
    --enroll-port) PORT="${2:-}"; shift 2 ;;
    --secret) SECRET="${2:-}"; shift 2 ;;
    --env) ENV="${2:-}"; shift 2 ;;
    --ca-fingerprint) FINGERPRINT="${2:-}"; shift 2 ;;
    --dashboard-port) DASH_PORT="${2:-}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
[ -n "$AGENT" ] && [ -n "$HOST" ] && [ -n "$PORT" ] && [ -n "$SECRET" ] || usage
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$AGENT" ] || { echo "agent binary not found: $AGENT" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

install -d -m 0755 "$(dirname "$CA_FILE")"
TMP_CA="$(mktemp)"
trap 'rm -f "$TMP_CA"' EXIT

CA_URL="https://${HOST}:${DASH_PORT}/api/config/ca-root"
echo "==> Fetching deployment CA from ${CA_URL}"
curl -sS -k --fail -o "$TMP_CA" "$CA_URL" || { echo "could not fetch the CA from ${CA_URL}" >&2; exit 1; }
grep -q "BEGIN CERTIFICATE" "$TMP_CA" || { echo "the response is not a PEM certificate" >&2; exit 1; }

ACTUAL="$(openssl x509 -in "$TMP_CA" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "    CA SHA-256 fingerprint: ${ACTUAL}"
if [ -n "$FINGERPRINT" ]; then
  [ "${ACTUAL^^}" = "${FINGERPRINT^^}" ] || { echo "fingerprint mismatch: expected ${FINGERPRINT}; nothing installed" >&2; exit 1; }
  echo "    fingerprint matches --ca-fingerprint"
else
  echo "    warning: no --ca-fingerprint given; trusting this CA on first contact" >&2
fi
install -m 0644 "$TMP_CA" "$CA_FILE"

echo "==> Installing the agent"
chmod +x "$AGENT"
"$AGENT" -install -server "https://${HOST}:9443" -enroll-port "$PORT" \
  -secret "$SECRET" -ca-root "$CA_FILE" -env "$ENV"
