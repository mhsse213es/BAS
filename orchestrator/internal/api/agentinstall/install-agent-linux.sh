#!/bin/bash
# install-agent-linux.sh: installs or upgrades the BAS agent on this Linux host.
#
#   sudo ./install-agent-linux.sh [--ca-file ./deployment-ca.pem] [--token-file <path> | --token-stdin]
#
# Credentials never go on a command line, where any local user can read them from the process list:
#   agent secret        asked for interactively, or BAS_AGENT_SECRET in the environment
#                       (a positional <agent-secret> is still accepted for old command lines but is discouraged)
#   enrolment token     (servers in token mode) asked for interactively, or --token-file <path> (the file is
#                       deleted once it is read), or --token-stdin (first line of stdin; then give the
#                       secret through BAS_AGENT_SECRET), or BAS_ENROLLMENT_TOKEN in the environment.
#                       The token is single use and bound to this host; never put one in a shared script.
# --ca-file uses a CA the console already embedded in the install command, so the CA is not fetched
# over the network at all.
#
# Only the agent secret is needed. The server address, ports and agent binary default to this
# server's values and can be overridden with environment variables or options:
#   BAS_SERVER_HOST (default 192.168.10.78), BAS_ENROLL_PORT (9445), BAS_DASHBOARD_PORT (9543),
#   BAS_MTLS_PORT (9443),
#   BAS_ENV_LABEL (Production), --agent <path>, --ca-fingerprint <SHA-256>.
# The agent binary is looked for as bas-agent-linux-<arch> in the current folder or the script's folder.
#
# What it does:
#   1. Fetches the deployment CA from the orchestrator's dashboard (the URL the Deploy Agent page uses).
#   2. If the agent's certificate was not issued by that CA, moves the old identity aside. A
#      certificate from another CA is never accepted, so keeping it only blocks enrollment.
#      Same CA: the identity is kept (normal upgrade).
#   3. Removes a previously installed agent service, then installs the new binary.
#
# --ca-fingerprint is strongly recommended: without it the first contact is trusted as-is.
set -euo pipefail

AGENT=""; SECRET="${BAS_AGENT_SECRET:-}"; FINGERPRINT=""; CA_SRC=""; TOKEN_FILE=""; TOKEN_STDIN=0
HOST="${BAS_SERVER_HOST:-192.168.10.78}"
PORT="${BAS_ENROLL_PORT:-9445}"
DASH_PORT="${BAS_DASHBOARD_PORT:-9543}"
MTLS_PORT="${BAS_MTLS_PORT:-9443}"
ENV="${BAS_ENV_LABEL:-Production}"
CERT_DIR="${BAS_CERT_DIR:-/etc/audspect/certs}"
CA_FILE="${BAS_CA_FILE:-/etc/audspect-agent/deployment-ca.pem}"
IDENTITY_FILES="agent-cert.pem agent-key.pem enrollment-state"

# describe_rc <exit code of the agent's -preflight>: the failure in plain words.
describe_rc() {
  case "$1" in
    20) echo "the agent rejected its inputs as invalid." ;;
    21) echo "the Audspect server could not be reached (${HOST}:${MTLS_PORT}). Check the network, the firewall and the server address; nothing was changed." ;;
    22) echo "the server rejected the agent secret. Check the secret and try again; nothing was changed." ;;
    23) echo "the server's certificate is not trusted by the deployment CA; nothing was changed." ;;
    24) echo "the deployment CA is invalid; nothing was changed." ;;
    *) echo "the pre-install check failed (exit code $1); nothing was changed." ;;
  esac
}

usage() { echo "usage: sudo $0 [--agent <binary>] [--ca-fingerprint <sha256>] [--token-file <path> | --token-stdin]" >&2; exit 2; }

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
    --ca-fingerprint) FINGERPRINT="${2:-}"; shift 2 ;;
    --ca-file) CA_SRC="${2:-}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
    --token-stdin) TOKEN_STDIN=1; shift ;;
    -h|--help) usage ;;
    -*) echo "unknown option: $1" >&2; usage ;;
    *) if [ -z "$SECRET" ]; then SECRET="$1"; shift; else echo "unexpected argument: $1" >&2; usage; fi ;;
  esac
done
if [ -z "$SECRET" ]; then
  if [ -t 0 ]; then
    read -r -s -p "Agent secret (from the Deploy Agent page): " SECRET
    echo
  fi
  [ -n "$SECRET" ] || usage
fi

# The enrolment token, if the server is in token mode. It is written to a private file (umask 077) that the
# agent reads once and deletes; it is never placed on a command line.
umask 077
TOKEN_DIR="$(mktemp -d)"
TOKEN_PATH=""
if [ "$TOKEN_STDIN" -eq 1 ] && [ -n "$TOKEN_FILE" ]; then
  echo "use --token-file or --token-stdin, not both" >&2; exit 2
fi
if [ "$TOKEN_STDIN" -eq 1 ]; then
  IFS= read -r TOKEN_VALUE || true
  [ -n "${TOKEN_VALUE:-}" ] || { echo "no enrolment token was provided on stdin" >&2; exit 2; }
  printf '%s\n' "$TOKEN_VALUE" > "$TOKEN_DIR/token"; unset TOKEN_VALUE
  TOKEN_PATH="$TOKEN_DIR/token"
elif [ -n "$TOKEN_FILE" ]; then
  [ -f "$TOKEN_FILE" ] || { echo "token file not found: $TOKEN_FILE" >&2; exit 1; }
  TOKEN_PATH="$TOKEN_FILE"
elif [ -n "${BAS_ENROLLMENT_TOKEN:-}" ]; then
  printf '%s\n' "$BAS_ENROLLMENT_TOKEN" > "$TOKEN_DIR/token"; unset BAS_ENROLLMENT_TOKEN
  TOKEN_PATH="$TOKEN_DIR/token"
elif [ -t 0 ]; then
  if [ "${BAS_TOKEN_REQUIRED:-}" = "1" ]; then
    read -r -s -p "Enrolment token (required by this server): " TOKEN_VALUE
  else
    read -r -s -p "Enrolment token (press Enter to skip if this server uses the shared secret only): " TOKEN_VALUE
  fi
  echo
  if [ -n "$TOKEN_VALUE" ]; then
    printf '%s\n' "$TOKEN_VALUE" > "$TOKEN_DIR/token"; TOKEN_PATH="$TOKEN_DIR/token"
  fi
  unset TOKEN_VALUE
fi

if [ "${BAS_TOKEN_REQUIRED:-}" = "1" ] && [ -z "$TOKEN_PATH" ]; then
  rm -rf "$TOKEN_DIR"
  echo "ERROR: this server issues single-use enrolment tokens and none was provided. Ask the administrator for a token for this host, then run the setup again (it asks for it, or use --token-file / --token-stdin)." >&2
  exit 2
fi

if [ -z "$AGENT" ]; then
  case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
  for dir in "$PWD" "$(cd "$(dirname "$0")" && pwd)"; do
    if [ -z "$AGENT" ] && [ -f "$dir/bas-agent-linux-${ARCH}" ]; then
      AGENT="$dir/bas-agent-linux-${ARCH}"
    fi
  done
  [ -n "$AGENT" ] || { echo "bas-agent-linux-${ARCH} not found in $PWD or the script's folder; use --agent" >&2; exit 1; }
fi
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$AGENT" ] || { echo "agent binary not found: $AGENT" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

TMP_CA="$(mktemp)"
trap 'rm -f "$TMP_CA"; rm -rf "$TOKEN_DIR"' EXIT

CA_URL="https://${HOST}:${DASH_PORT}/api/config/ca-root"
echo "==> Fetching deployment CA from ${CA_URL}"
if [ -n "$CA_SRC" ]; then
  [ -f "$CA_SRC" ] || { echo "CA file not found: $CA_SRC" >&2; exit 1; }
  cp "$CA_SRC" "$TMP_CA"
else
  curl -sS -k --fail -o "$TMP_CA" "$CA_URL" || { echo "could not fetch the CA from ${CA_URL}" >&2; exit 1; }
fi
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

# Check the server and the secret BEFORE anything on this host is touched: a wrong secret must not cost the host
# its working agent.
chmod +x "$AGENT"
echo "==> Checking the server and the agent secret"
set +e
printf '%s\n' "$SECRET" | "$AGENT" -preflight -server "https://${HOST}:${MTLS_PORT}" -enroll-port "$PORT" -ca-root "$TMP_CA" --secret-stdin
PRE_RC=$?
set -e
if [ "$PRE_RC" -ne 0 ]; then
  echo "ERROR: $(describe_rc "$PRE_RC")" >&2
  exit "$PRE_RC"
fi

echo "==> Checking the existing agent identity"
clear_stale_identity "$TMP_CA"

if systemctl cat bas-agent >/dev/null 2>&1 || [ -x /usr/local/bin/bas-agent ]; then
  echo "==> Removing the previously installed agent service"
  chmod +x "$AGENT"
  BAS_UNINSTALL_KEEP_DATA=1 "$AGENT" -uninstall || echo "    warning: previous uninstall reported errors; continuing"
fi

install -d -m 0755 "$(dirname "$CA_FILE")"
install -m 0644 "$TMP_CA" "$CA_FILE"

echo "==> Installing the agent"
chmod +x "$AGENT"
AGENT_ARGS=(-install -server "https://${HOST}:${MTLS_PORT}" -enroll-port "$PORT" -ca-root "$CA_FILE" -env "$ENV" --secret-stdin)
if [ -n "$TOKEN_PATH" ]; then AGENT_ARGS+=(--enrollment-token-file "$TOKEN_PATH"); fi
# The secret goes in on stdin (printf is a shell builtin, so it never appears in a process list).
set +e
printf '%s\n' "$SECRET" | "$AGENT" "${AGENT_ARGS[@]}"
RC=$?
set -e
unset SECRET
case "$RC" in
  0) ;;
  26) echo "ERROR: the server refused the enrolment token (invalid, expired, already used, or issued for a different host). Ask the administrator for a new token for this host." >&2; exit 26 ;;
  27) echo "ERROR: could not reach the server to enrol (${HOST}, enrolment port ${PORT}). This is a connection problem, not a token problem: check the network, firewall and port." >&2; exit 27 ;;
  *) exit "$RC" ;;
esac
