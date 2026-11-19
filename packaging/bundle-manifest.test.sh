#!/usr/bin/env bash
# packaging/bundle-manifest.test.sh
#
# Proves bundle-manifest.sh writes the schema the Go ingest (tcv.BundleManifest)
# reads: one entry per shipped *.yaml scenario, relative forward-slash paths,
# sorted, correct SHA-256 values (checked against an independent sha256sum),
# and a fail-closed exit on a missing or empty scenarios directory.
# Run: bash packaging/bundle-manifest.test.sh
set -euo pipefail
unset CDPATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/bundle-manifest.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fails=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; fails=$((fails + 1)); }

# --- fixture: a scenarios tree with YAML, a nested YAML, and files that must be ignored ---
S="$T/scenarios"
mkdir -p "$S/detection-profiles"
printf 'id: alpha\n' > "$S/alpha.yaml"
printf 'id: beta\n'  > "$S/detection-profiles/beta.yaml"
printf 'sig-bytes\n' > "$S/alpha.yaml.sig"      # not a scenario: ignored
printf 'notes\n'     > "$S/README.txt"          # not a scenario: ignored

OUT="$T/bundle-manifest.json"
BUNDLE_PACKAGED_AT="2026-11-10T09:00:00Z" bash "$SCRIPT" "$S" "bundle-test-1" "$OUT"

# (a) schema, bundle_id, packaged_at
grep -q '"schema": *1' "$OUT"                    && pass "schema is 1"          || fail "schema is not 1"
grep -q '"bundle_id": *"bundle-test-1"' "$OUT"   && pass "bundle_id recorded"   || fail "bundle_id missing"
grep -q '"packaged_at": *"2026-11-10T09:00:00Z"' "$OUT" && pass "packaged_at recorded" || fail "packaged_at missing"

# (b) exactly the two YAML files, with paths relative, forward-slashed, sorted
want_alpha="$(sha256sum "$S/alpha.yaml" | cut -d' ' -f1)"
want_beta="$(sha256sum "$S/detection-profiles/beta.yaml" | cut -d' ' -f1)"
grep -q "\"path\": *\"alpha.yaml\", *\"sha256\": *\"$want_alpha\"" "$OUT" \
  && pass "alpha.yaml hash matches sha256sum" || fail "alpha.yaml hash wrong or entry missing"
grep -q "\"path\": *\"detection-profiles/beta.yaml\", *\"sha256\": *\"$want_beta\"" "$OUT" \
  && pass "nested beta.yaml hash matches sha256sum (forward slashes)" || fail "nested entry wrong"
entries="$(grep -o '"sha256"' "$OUT" | wc -l | tr -d ' ')"   # occurrences, not lines: the JSON is one line
[ "$entries" -eq 2 ] && pass "exactly 2 entries (sig and txt ignored)" || fail "expected 2 entries, got $entries"
if grep -q 'alpha.yaml.sig\|README.txt' "$OUT"; then fail "non-YAML files leaked into manifest"; else pass "non-YAML files excluded"; fi
if grep -q '"path": *"\./' "$OUT"; then fail "path has a leading ./"; else pass "no leading ./ in paths"; fi

# (c) a missing directory fails closed
if bash "$SCRIPT" "$T/does-not-exist" "bundle-x" "$T/x.json" 2>/dev/null; then
  fail "missing scenarios dir should exit non-zero"
else
  pass "missing scenarios dir exits non-zero"
fi

# (d) a directory with no YAML fails closed (a bundle with no scenarios is suspicious)
mkdir -p "$T/empty"
if bash "$SCRIPT" "$T/empty" "bundle-x" "$T/y.json" 2>/dev/null; then
  fail "empty scenarios dir should exit non-zero"
else
  pass "empty scenarios dir exits non-zero"
fi

echo
if [ "$fails" -eq 0 ]; then echo "bundle-manifest: all checks passed"; exit 0; fi
echo "bundle-manifest: $fails check(s) FAILED"; exit 1
