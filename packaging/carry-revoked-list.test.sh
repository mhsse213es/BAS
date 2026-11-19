#!/usr/bin/env bash
# packaging/carry-revoked-list.test.sh
#
# Proves a release engineer can revoke a binary in the signed release by listing it in packaging/revoked-binaries.txt:
# the carry step writes it as a "#revoked" line, not repeated, ignoring comments and malformed lines, and "verify" fails
# closed when a listed hash is not revoked in the manifest.
# Run: bash packaging/carry-revoked-list.test.sh
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

printf '%s  bas-agent-linux-amd64\n' "$(h 1)" > "$T/p"
printf '%s  bas-agent-linux-amd64\n' "$(h 11)" > "$T/m"
cat > "$T/list" <<LIST
# comments and blanks are ignored

$(h 7)  bas-agent-windows-amd64.exe  leaked signing key
not-a-hash  whatever
$(h 8)
LIST

echo "carry"
BAS_REVOKED_LIST="$T/list" sh "$SCRIPT" carry "$T/m" "$T/p" >/dev/null 2>&1
grep -qx "#revoked $(h 7)  bas-agent-windows-amd64.exe" "$T/m" && pass "the listed hash is revoked in the manifest" || fail "listed hash not written"
grep -qx "#revoked $(h 8)  revoked" "$T/m" && pass "a hash with no file name gets a placeholder name" || fail "bare hash not written"
[ "$(grep -c '^#revoked' "$T/m")" = "2" ] && pass "the malformed line was skipped" || fail "wrong number of #revoked lines"

echo "idempotent"
before="$(cat "$T/m")"
BAS_REVOKED_LIST="$T/list" sh "$SCRIPT" carry "$T/m" "$T/p" >/dev/null 2>&1
[ "$(cat "$T/m")" = "$before" ] && pass "a second carry adds nothing" || fail "second carry changed the manifest"

echo "it is carried to the next release even when the list is gone"
printf '%s  bas-agent-linux-amd64\n' "$(h 21)" > "$T/m2"
BAS_REVOKED_LIST="$T/none" sh "$SCRIPT" carry "$T/m2" "$T/m" >/dev/null 2>&1
grep -qx "#revoked $(h 7)  bas-agent-windows-amd64.exe" "$T/m2" && pass "still revoked in the next release" || fail "revocation lost"

echo "verify fails closed when a listed hash is not revoked"
printf '%s  bas-agent-linux-amd64\n' "$(h 31)" > "$T/m3"
if BAS_REVOKED_LIST="$T/list" sh "$SCRIPT" verify "$T/m3" "$T/p" >/dev/null 2>&1; then fail "verify passed without the listed revocation"; else pass "verify refuses it"; fi
BAS_REVOKED_LIST="$T/list" sh "$SCRIPT" verify "$T/m" "$T/p" >/dev/null 2>&1 && pass "verify accepts a manifest that has it" || fail "verify rejected a correct manifest"

echo
if [ "$fails" -eq 0 ]; then echo "PASS: all checks passed"; else echo "FAIL: $fails check(s) failed"; exit 1; fi
