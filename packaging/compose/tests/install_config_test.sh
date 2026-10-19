#!/usr/bin/env bash
# setup.conf keys through install.sh (BAS_SERVER_SANS, BAS_CSP_MODE):
# setup.conf -> load_config (default, validation) -> _write_env -> .env.
# Runs the real functions, extracted from install.sh, under install.sh's own
# set -u, against a temporary DATA_DIR. Usage: bash install_config_test.sh
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_sh="${here}/../install.sh"
fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }

# Prints the named top-level function from install.sh.
extract() { awk -v f="$1" '$0 ~ "^"f"\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$install_sh"; }

# run_case <setup.conf body> -> prints "rc=<n>" then the .env (or the error).
run_case() {
  local tmp; tmp="$(mktemp -d)"
  printf 'DATA_DIR=%s\nDNS_SINK_BIND_IP=10.0.0.1\nDB_PASSWORD=db-pw-test-only\nADMIN_EMAIL=admin@example.com\nADMIN_PASSWORD=admin-pw-test-only-1\nLIC_PATH=/dev/null\n%s\n' \
    "$tmp" "$1" > "$tmp/setup.conf"
  (
    err() { echo "ERR: $*"; }; log() { :; }; warn() { :; }
    DEFAULT_DATA_DIR="$tmp"; DEFAULT_PORT=9443; DEFAULT_ENROLL_PORT=9444
    DEFAULT_LEGACY_PORT=9000; DEFAULT_DASHBOARD_PORT=9543
    BAS_VERSION=test; COMPOSE_PROJECT=audspect
    eval "$(grep -E '^[A-Z_][A-Z0-9_]*=""$' "$install_sh")"
    eval "$(extract load_config)"
    eval "$(extract _write_env)"
    eval "$(extract validate_phish_scope)"
    load_config "$tmp/setup.conf" && validate_phish_scope && _write_env && cat "$tmp/.env"
  ) 2>&1
  echo "rc=$?"
  rm -rf "$tmp"
}

out="$(run_case '')"
grep -q '^BAS_SERVER_SANS=10.0.0.1$' <<<"$out" && pass "BAS_SERVER_SANS blank -> DNS_SINK_BIND_IP" || fail "BAS_SERVER_SANS default: $out"

out="$(run_case 'BAS_SERVER_SANS=10.0.0.1,bas.example.com   # SANs')"
grep -q '^BAS_SERVER_SANS=10.0.0.1,bas.example.com$' <<<"$out" && pass "BAS_SERVER_SANS from setup.conf reaches .env" || fail "BAS_SERVER_SANS set: $out"

out="$(run_case '')"
grep -q '^BAS_CSP_MODE=enforce$' <<<"$out" && pass "unset -> enforce written to .env" || fail "unset -> enforce: $out"

out="$(run_case 'BAS_CSP_MODE=report-only     # escape hatch')"
grep -q '^BAS_CSP_MODE=report-only$' <<<"$out" && pass "report-only (with inline comment) written to .env" || fail "report-only: $out"

out="$(run_case 'BAS_CSP_MODE=Enforce')"
grep -q '^BAS_CSP_MODE=enforce$' <<<"$out" && pass "case-insensitive value normalised" || fail "Enforce: $out"

for bad in off none reportonly; do
  out="$(run_case "BAS_CSP_MODE=${bad}")"
  if grep -q 'ERR: .*BAS_CSP_MODE' <<<"$out" && ! grep -q '^rc=0$' <<<"$out"; then
    pass "BAS_CSP_MODE=${bad} refused"
  else
    fail "BAS_CSP_MODE=${bad} not refused: $out"
  fi
done

# Staging (zain@audspecterver 192.168.10.78) overrides BAS_ENROLL_PORT/
# BAS_LEGACY_PORT in packaging/compose/setup.conf because install.sh's own
# defaults (9444/9000) conflict there with apache2 and docker-proxy.
out="$(run_case 'BAS_ENROLL_PORT=9441
BAS_LEGACY_PORT=9005')"
grep -q '^BAS_ENROLL_PORT=9441$' <<<"$out" && pass "BAS_ENROLL_PORT override reaches .env" || fail "BAS_ENROLL_PORT override: $out"
grep -q '^BAS_LEGACY_PORT=9005$' <<<"$out" && pass "BAS_LEGACY_PORT override reaches .env" || fail "BAS_LEGACY_PORT override: $out"

out="$(run_case '')"
grep -q '^BAS_ENROLL_PORT=9444$' <<<"$out" && pass "BAS_ENROLL_PORT blank -> install.sh default (9444)" || fail "BAS_ENROLL_PORT default: $out"
grep -q '^BAS_LEGACY_PORT=9000$' <<<"$out" && pass "BAS_LEGACY_PORT blank -> install.sh default (9000)" || fail "BAS_LEGACY_PORT default: $out"

# TCF Phase 6 validation lab: the agent ID and poll interval must flow from
# setup.conf through to .env so docker-compose can forward them to the
# orchestrator (which otherwise logs "[validationlab] disabled").
out="$(run_case 'VALIDATION_LAB_AGENT_ID=agent-abc-123')"
grep -q '^VALIDATION_LAB_AGENT_ID=agent-abc-123$' <<<"$out" && pass "VALIDATION_LAB_AGENT_ID reaches .env" || fail "VALIDATION_LAB_AGENT_ID set: $out"

out="$(run_case '')"
grep -q '^VALIDATION_LAB_AGENT_ID=$' <<<"$out" && pass "VALIDATION_LAB_AGENT_ID blank -> empty (lab stays disabled)" || fail "VALIDATION_LAB_AGENT_ID default: $out"

out="$(run_case 'VALIDATION_LAB_POLL_MINUTES=10')"
grep -q '^VALIDATION_LAB_POLL_MINUTES=10$' <<<"$out" && pass "VALIDATION_LAB_POLL_MINUTES reaches .env" || fail "poll set: $out"

# Installation-wide phishing target allowlists (see orchestrator phishscope).
# Empty means unconfigured. A malformed value refuses the install.
out="$(run_case '')"
grep -q '^AUDSPECT_PHISH_IDENTITY_TARGET_USERS=$' <<<"$out" && grep -q '^AUDSPECT_PHISH_OAUTH_CLIENT_IDS=$' <<<"$out" && pass "phish allowlists blank -> empty (unconfigured)" || fail "phish allowlists default: $out"

out="$(run_case 'AUDSPECT_PHISH_IDENTITY_TARGET_USERS=alice@contoso.example, bob@contoso.example')"
grep -q '^AUDSPECT_PHISH_IDENTITY_TARGET_USERS=alice@contoso.example, bob@contoso.example$' <<<"$out" && pass "phish user allowlist reaches .env" || fail "phish user allowlist: $out"

out="$(run_case 'AUDSPECT_PHISH_OAUTH_CLIENT_IDS=8f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b')"
grep -q '^AUDSPECT_PHISH_OAUTH_CLIENT_IDS=8f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b$' <<<"$out" && pass "phish client allowlist reaches .env" || fail "phish client allowlist: $out"

out="$(run_case 'AUDSPECT_PHISH_OAUTH_CLIENT_IDS=*')"
grep -q 'rc=1' <<<"$out" && grep -q 'AUDSPECT_PHISH_OAUTH_CLIENT_IDS' <<<"$out" && pass "wildcard client allowlist refuses the install" || fail "wildcard client accepted: $out"

out="$(run_case 'AUDSPECT_PHISH_IDENTITY_TARGET_USERS=alice')"
grep -q 'rc=1' <<<"$out" && pass "user allowlist without a domain refuses the install" || fail "bad user accepted: $out"

out="$(run_case 'AUDSPECT_PHISH_IDENTITY_TARGET_USERS=*')"
grep -q 'rc=1' <<<"$out" && pass "wildcard user allowlist refuses the install" || fail "wildcard user accepted: $out"

out="$(run_case '')"
grep -q 'AUDSPECT_PHISH_OAUTH_CLIENT_IDS: ${AUDSPECT_PHISH_OAUTH_CLIENT_IDS:-}' "${here}/../docker-compose.yml" && pass "compose passes the client allowlist to the orchestrator" || fail "compose passthrough missing"

echo
[[ $fails -eq 0 ]] && echo "ALL PASS" || { echo "${fails} FAILED"; exit 1; }
