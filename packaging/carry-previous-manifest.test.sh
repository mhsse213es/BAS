#!/usr/bin/env bash
# packaging/carry-previous-manifest.test.sh
#
# Proves carry-previous-manifest.sh keeps the previous release's hashes in BINARIES.sha256 as "#prev" lines, never
# repeats a hash, keeps the chain, copes with CRLF and a missing trailing newline, and that "verify" fails closed
# when a previous hash is missing or a #prev line is malformed. Also checks that `sha256sum --check --strict`
# (what setup.sh runs on the manifest) still accepts a manifest with #prev lines.
# Run: bash packaging/carry-previous-manifest.test.sh
set -euo pipefail
unset CDPATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/carry-previous-manifest.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fails=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; fails=$((fails + 1)); }
h() { printf '%064d' "$1"; }   # a distinct 64-hex hash per number

# --- fixtures: previous release P1 (3 files) and the new release N (same names, new hashes) ---
mk_prev()    { printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n%s  bas-agent-windows-amd64.exe\n' "$(h 1)" "$(h 2)" "$(h 3)" > "$1"; }
mk_current() { printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n%s  bas-agent-windows-amd64.exe\n' "$(h 11)" "$(h 12)" "$(h 13)" > "$1"; }

echo "carry"
mk_prev "$T/p"; mk_current "$T/m"
n="$(sh "$SCRIPT" carry "$T/m" "$T/p")"
[ "$n" = "3" ] && pass "carries all 3 previous hashes" || fail "carried $n, want 3"
[ "$(grep -c '^#prev ' "$T/m")" = "3" ] && pass "3 #prev lines written" || fail "#prev line count"
grep -qx "#prev $(h 2)  bas-agent-darwin-arm64" "$T/m" && pass "Mac hash carried with its file name" || fail "Mac #prev line missing"
grep -qx "#prev $(h 1)  bas-agent-linux-amd64" "$T/m" && pass "Linux hash carried with its file name" || fail "Linux #prev line missing"
[ "$(grep -vc '^#' "$T/m")" = "3" ] && pass "the 3 current entries are untouched" || fail "current entries changed"

echo "idempotent"
n="$(sh "$SCRIPT" carry "$T/m" "$T/p")"
[ "$n" = "0" ] && pass "a second run adds nothing" || fail "second run added $n"

echo "a hash that is still current is not repeated"
mk_prev "$T/p"; printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n%s  bas-agent-windows-amd64.exe\n' "$(h 1)" "$(h 12)" "$(h 13)" > "$T/m"
n="$(sh "$SCRIPT" carry "$T/m" "$T/p")"
[ "$n" = "2" ] && pass "only the 2 hashes that are no longer current are carried" || fail "carried $n, want 2"

echo "the chain keeps growing"
mk_current "$T/m1"; sh "$SCRIPT" carry "$T/m1" "$T/p" >/dev/null           # N1 carries P1
printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n%s  bas-agent-windows-amd64.exe\n' "$(h 21)" "$(h 22)" "$(h 23)" > "$T/m2"
n="$(sh "$SCRIPT" carry "$T/m2" "$T/m1")"                                   # N2 carries N1 (entries) and P1 (#prev)
[ "$n" = "6" ] && pass "N2 carries N1's 3 entries and P1's 3 #prev lines" || fail "carried $n, want 6"
grep -qx "#prev $(h 1)  bas-agent-linux-amd64" "$T/m2" && pass "an older release's hash survives a second upgrade" || fail "chain broken"

echo "robustness"
mk_prev "$T/p"; mk_current "$T/m"; printf '%s  bas-agent-extra' "$(h 99)" >> "$T/m"      # no trailing newline
sh "$SCRIPT" carry "$T/m" "$T/p" >/dev/null
grep -qx "$(h 99)  bas-agent-extra" "$T/m" && pass "a manifest without a trailing newline keeps its last entry intact" || fail "last entry was glued to a #prev line"
mk_current "$T/m"; sed 's/$/\r/' "$T/p" > "$T/p_crlf"
n="$(sh "$SCRIPT" carry "$T/m" "$T/p_crlf")"
[ "$n" = "3" ] && pass "a CRLF previous manifest is read correctly" || fail "CRLF previous: carried $n"
! grep -q $'\r' "$T/m" && pass "no CR is written into the manifest" || fail "CR written into the manifest"

echo "verify"
mk_prev "$T/p"; mk_current "$T/m"
sh "$SCRIPT" verify "$T/m" "$T/p" >/dev/null 2>&1 && fail "verify passed with nothing carried" || pass "fails when previous hashes are not carried"
sh "$SCRIPT" carry "$T/m" "$T/p" >/dev/null
sh "$SCRIPT" verify "$T/m" "$T/p" >/dev/null 2>&1 && pass "passes once they are carried" || fail "verify failed after carry"
grep -v "^#prev $(h 2) " "$T/m" > "$T/m_dropped"
sh "$SCRIPT" verify "$T/m_dropped" "$T/p" >/dev/null 2>&1 && fail "verify passed with the Mac hash dropped" || pass "fails closed when one #prev line is dropped"
printf '#prev nothex  file\n' >> "$T/m"
sh "$SCRIPT" verify "$T/m" "$T/p" >/dev/null 2>&1 && fail "verify passed with a malformed #prev line" || pass "fails closed on a malformed #prev line"
sh "$SCRIPT" bogus "$T/m" "$T/p" >/dev/null 2>&1 && fail "unknown mode accepted" || pass "unknown mode is rejected"
sh "$SCRIPT" carry "$T/nope" "$T/p" >/dev/null 2>&1 && fail "missing manifest accepted" || pass "missing manifest is rejected"

echo "sha256sum --check --strict (setup.sh) accepts a manifest with #prev lines"
mkdir "$T/bin"; printf 'agent-linux' > "$T/bin/bas-agent-linux-amd64"; printf 'agent-mac' > "$T/bin/bas-agent-darwin-arm64"
( cd "$T/bin" && sha256sum bas-agent-linux-amd64 bas-agent-darwin-arm64 > BINARIES.sha256 )
printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n' "$(h 5)" "$(h 6)" > "$T/p_real"
sh "$SCRIPT" carry "$T/bin/BINARIES.sha256" "$T/p_real" >/dev/null
( cd "$T/bin" && sha256sum --check --strict --quiet BINARIES.sha256 ) >/dev/null 2>&1 && pass "setup.sh's check still passes" || fail "sha256sum --strict rejects #prev lines"

echo
if [ "$fails" -eq 0 ]; then echo "PASS: all checks passed"; else echo "FAIL: $fails check(s) failed"; exit 1; fi
