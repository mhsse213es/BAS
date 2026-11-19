#!/usr/bin/env bash
# packaging/compose/tests/db_tls_test.sh
# Exercises db-tls.sh: generation, idempotence, and refusal to overwrite a broken pair.
set -euo pipefail
# Git Bash on Windows rewrites "/CN=..." arguments as paths; this stops that. No effect on Linux.
export MSYS2_ARG_CONV_EXCL="*"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
TESTDIR="$(mktemp -d)"
# openssl on Windows needs native paths; Git Bash /tmp paths are not resolved by it. No effect on Linux.
if command -v cygpath >/dev/null 2>&1; then TESTDIR="$(cygpath -m "$TESTDIR")"; fi
trap 'rm -rf "$TESTDIR"' EXIT

# Test as this user: no chown, so the checks run without root.
export DB_TLS_KEY_UID="$(id -u)"
export DB_TLS_KEY_GID="$(id -g)"

# shellcheck source=../db-tls.sh
source "$HERE/db-tls.sh"

pass=0
fail=0
skip=0
ok()   { echo "PASS: $1"; pass=$((pass + 1)); }
bad()  { echo "FAIL: $1"; fail=$((fail + 1)); }
note_skip() { echo "SKIP: $1"; skip=$((skip + 1)); }

probe="$TESTDIR/mode-probe"
: > "$probe"
chmod 0640 "$probe"
if [[ "$(stat -c %a "$probe")" == "640" ]]; then MODE_ENFORCED=1; else MODE_ENFORCED=0; fi

fresh() { DB_TLS_DIR="$TESTDIR/$1/dbtls"; }

# --- fresh install generates a pair ---
fresh fresh
if db_tls_ensure >/dev/null 2>&1; then ok "fresh directory generates the pair"; else bad "fresh generation failed"; fi
if [[ -f "$DB_TLS_DIR/server.key" && -f "$DB_TLS_DIR/server.crt" ]]; then ok "both files exist"; else bad "a file is missing"; fi
if openssl x509 -in "$DB_TLS_DIR/server.crt" -noout -text | grep -q "DNS:postgres"; then ok "SAN includes DNS:postgres"; else bad "SAN lacks DNS:postgres"; fi
if openssl x509 -in "$DB_TLS_DIR/server.crt" -noout -text | grep -q "CA:TRUE"; then bad "leaf must not be a CA"; else ok "certificate is not a CA"; fi
if [[ "$MODE_ENFORCED" == 1 ]]; then
  if [[ "$(stat -c %a "$DB_TLS_DIR/server.key")" == "600" ]]; then ok "server.key is mode 0600"; else bad "server.key mode is not 0600"; fi
  if [[ "$(stat -c %a "$DB_TLS_DIR/server.crt")" == "644" ]]; then ok "server.crt is mode 0644"; else bad "server.crt mode is not 0644"; fi
else
  note_skip "mode bits are not enforced on this filesystem; run on Linux to check 0600/0644"
fi

# --- second run is idempotent: nothing is regenerated ---
before=$(sha256sum "$DB_TLS_DIR/server.key" | cut -d' ' -f1)
if db_tls_ensure >/dev/null 2>&1; then ok "second run succeeds"; else bad "second run failed"; fi
after=$(sha256sum "$DB_TLS_DIR/server.key" | cut -d' ' -f1)
if [[ "$before" == "$after" ]]; then ok "second run does not regenerate the key"; else bad "second run regenerated the key"; fi

# --- mismatched pair is refused and left untouched ---
fresh mismatch
db_tls_ensure >/dev/null 2>&1
other="$TESTDIR/other"
mkdir -p "$other"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$other/k.pem" -out "$other/c.pem" \
  -days 30 -subj "/CN=other" >/dev/null 2>&1
cp "$other/k.pem" "$DB_TLS_DIR/server.key"
crt_before=$(sha256sum "$DB_TLS_DIR/server.crt" | cut -d' ' -f1)
if db_tls_ensure >/dev/null 2>&1; then bad "mismatched pair was accepted"; else ok "mismatched pair is refused"; fi
crt_after=$(sha256sum "$DB_TLS_DIR/server.crt" | cut -d' ' -f1)
if [[ "$crt_before" == "$crt_after" ]]; then ok "refused pair is left untouched"; else bad "refused pair was overwritten"; fi

# --- incomplete material is refused ---
fresh incomplete
mkdir -p "$DB_TLS_DIR"
: > "$DB_TLS_DIR/server.key"
if db_tls_ensure >/dev/null 2>&1; then bad "incomplete material was accepted"; else ok "incomplete material is refused"; fi
if [[ ! -s "$DB_TLS_DIR/server.key" && ! -e "$DB_TLS_DIR/server.crt" ]]; then ok "incomplete material is not completed silently"; else bad "incomplete material was modified"; fi

# --- garbage key is refused ---
fresh garbage
mkdir -p "$DB_TLS_DIR"
echo "not a key" > "$DB_TLS_DIR/server.key"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$other/k2.pem" -out "$DB_TLS_DIR/server.crt" \
  -days 30 -subj "/CN=g" >/dev/null 2>&1
if db_tls_ensure >/dev/null 2>&1; then bad "garbage key was accepted"; else ok "garbage key is refused"; fi

echo "---"
echo "passed: $pass  failed: $fail  skipped: $skip  (mode bits enforced: $MODE_ENFORCED)"
[[ "$fail" -eq 0 ]]
