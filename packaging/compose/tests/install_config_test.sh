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
    load_config "$tmp/setup.conf" && _write_env && cat "$tmp/.env"
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

echo
[[ $fails -eq 0 ]] && echo "ALL PASS" || { echo "${fails} FAILED"; exit 1; }
