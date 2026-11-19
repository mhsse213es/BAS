#!/usr/bin/env bash
# packaging/carry-revoked.test.sh
#
# Proves carry-previous-manifest.sh carries "#revoked" lines forward: a revocation in release N stays in release N+1,
# is not repeated, and "verify" fails closed when a previous revocation is missing from the new manifest.
# Run: bash packaging/carry-revoked.test.sh
set -euo pipefail
unset CDPATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/carry-previous-manifest.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fails=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; fails=$((fails + 1)); }
h() { printf '%064d' "$1"; }

# Previous release P: hash 1 is a current binary, hash 2 was revoked in P.
printf '%s  bas-agent-linux-amd64\n#revoked %s  bas-agent-darwin-arm64\n' "$(h 1)" "$(h 2)" > "$T/p"
# New release N: all three entries are new hashes.
printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n%s  bas-agent-windows-amd64.exe\n' "$(h 11)" "$(h 12)" "$(h 13)" > "$T/m"

echo "carry"
sh "$SCRIPT" carry "$T/m" "$T/p" >/dev/null 2>"$T/err"
grep -qx "#revoked $(h 2)  bas-agent-darwin-arm64" "$T/m" && pass "the revocation is carried into the new release" || fail "revocation not carried"

echo "idempotent"
before="$(cat "$T/m")"
sh "$SCRIPT" carry "$T/m" "$T/p" >/dev/null 2>&1
[ "$(cat "$T/m")" = "$before" ] && pass "a second carry adds nothing" || fail "second carry changed the manifest"

echo "a revocation carried through two releases is still there"
printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n%s  bas-agent-windows-amd64.exe\n' "$(h 21)" "$(h 22)" "$(h 23)" > "$T/m2"
sh "$SCRIPT" carry "$T/m2" "$T/m" >/dev/null 2>&1
grep -qx "#revoked $(h 2)  bas-agent-darwin-arm64" "$T/m2" && pass "N2 still revokes the hash revoked in P" || fail "revocation lost on second upgrade"

echo "verify fails closed when a revocation is missing"
printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n%s  bas-agent-windows-amd64.exe\n' "$(h 31)" "$(h 32)" "$(h 33)" > "$T/m3"
if sh "$SCRIPT" verify "$T/m3" "$T/p" >/dev/null 2>&1; then fail "verify passed without the carried revocation"; else pass "verify refuses a manifest missing a revocation"; fi
if sh "$SCRIPT" verify "$T/m" "$T/p" >/dev/null 2>&1; then pass "verify accepts a manifest that carries it"; else fail "verify rejected a correct manifest"; fi

echo
if [ "$fails" -eq 0 ]; then echo "PASS: all checks passed"; else echo "FAIL: $fails check(s) failed"; exit 1; fi
