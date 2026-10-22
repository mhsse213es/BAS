#!/bin/bash
# install-agent-linux.sh: installs or upgrades the BAS agent on this Linux host.
#
#   sudo ./install-agent-linux.sh --agent ./bas-agent-linux-amd64 \
#     --server-host 192.168.10.78 --enroll-port 9445 --secret <agent-secret> \
#     [--env Production] [--ca-fingerprint <SHA-256 fingerprint>] [--dashboard-port 9543]
#
# What it does:
#   1. Fetches the deployment CA from the orchestrator's dashboard (the URL the Deploy Agent page uses).
#   2. If the agent already holds an identity (certificate, key, enrollment state) issued under a
#      different CA, moves that identity aside. A certificate from another CA is never accepted, so
#      keeping it only blocks enrollment. Same CA: the identity is kept (normal upgrade).
#   3. Removes a previously installed agent service, then installs the new binary.
#
# The agent secret comes from the orchestrator's Deploy Agent page (or GET /api/config/connection).
# --ca-fingerprint is strongly recommended: without it the first contact is trusted as-is.
set -euo pipefail

AGENT=""; HOST=""; PORT=""; SECRET=""; ENV="Production"; FINGERPRINT=""; DASH_PORT="9543"
CERT_DIR="${BAS_CERT_DIR:-/etc/audspect/certs}"
CA_FILE="/etc/audspect-agent/deployment-ca.pem"
IDENTITY_FILES="agent-cert.pem agent-key.pem enrollment-state"

usage() { echo "usage: sudo $0 --agent <binary> --server-host <host> --enroll-port <port> --secret <secret> [--env <label>] [--ca-fingerprint <sha256>] [--dashboard-port <port>]" >&2; exit 2; }

# clear_stale_identity <new-ca-pem>: moves the agent's identity aside when it was issued under a different CA.
clear_stale_identity() {
  local new_ca="$1" f have=0 backup
  for f in $IDENTITY_FILES; do
    if [ -e "$CERT_DIR/$f" ]; then have=1; fi
  done
  if [ "$have" -eq 0 ]; then
    return 0
  fi
  # The identity is valid only if the agent's certificate chains to the CA we are installing now.
  # (Do not compare with the stored deployment-ca.pem: a previous install overwrites that file.)
  if [ -f "$CERT_DIR/agent-cert.pem" ] && openssl verify -CAfile "$new_ca" "$CERT_DIR/agent-cert.pem" >/dev/null 2>&1; then
    echo "    agent certificate verifies against the current CA; keeping the identity"
    return 0
  fi
  backup="${CERT_DIR}.replaced-$(date -u +%Y%m%dT%H%M%SZ)"
  echo "==> The agent's certificate was not issued by the current deployment CA."
  echo "    moving the old identity to ${backup} so the agent can enroll again"
  systemctl stop bas-agent 2>/dev/null || true
  install -d -m 0700 "$backup"
  for f in $IDENTITY_FILES; do
    if [ -e "$CERT_DIR/$f" ]; then
      mv "$CERT_DIR/$f" "$backup/"
    fi
  done
}

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

TMP_CA="$(mktemp)"
trap 'rm -f "$TMP_CA"' EXIT

CA_URL="https://${HOST}:${DASH_PORT}/api/config/ca-root"
echo "==> Fetching deployment CA from ${CA_URL}"
curl -sS -k --fail -o "$TMP_CA" "$CA_URL" || { echo "could not fetch the CA from ${CA_URL}" >&2; exit 1; }
grep -q "BEGIN CERTIFICATE" "$TMP_CA" || { echo "the response is not a PEM certificate" >&2; exit 1; }

ACTUAL="$(openssl x509 -in "$TMP_CA" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "    CA SHA-256 fingerprint: ${ACTUAL}"
if [ -n "$FINGERPRINT" ]; then
  if [ "${ACTUAL^^}" != "${FINGERPRINT^^}" ]; then
    echo "fingerprint mismatch: expected ${FINGERPRINT}; nothing installed" >&2
    exit 1
  fi
  echo "    fingerprint matches --ca-fingerprint"
else
  echo "    warning: no --ca-fingerprint given; trusting this CA on first contact" >&2
fi

echo "==> Checking the existing agent identity"
clear_stale_identity "$TMP_CA"

if systemctl cat bas-agent >/dev/null 2>&1 || [ -x /usr/local/bin/bas-agent ]; then
  echo "==> Removing the previously installed agent service"
  chmod +x "$AGENT"
  "$AGENT" -uninstall || echo "    warning: previous uninstall reported errors; continuing"
fi

install -d -m 0755 "$(dirname "$CA_FILE")"
install -m 0644 "$TMP_CA" "$CA_FILE"

echo "==> Installing the agent"
chmod +x "$AGENT"
"$AGENT" -install -server "https://${HOST}:9443" -enroll-port "$PORT" \
  -secret "$SECRET" -ca-root "$CA_FILE" -env "$ENV"
