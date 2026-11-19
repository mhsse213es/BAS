#!/usr/bin/env bash
# packaging/carry-prev-version.test.sh
#
# Proves carry-previous-manifest.sh records the previous release's version as a "#prev-version" line, taken from the
# bas-install-<version> folder the previous manifest sits in. The server defaults the fleet minimum agent version to it.
# Run: bash packaging/carry-prev-version.test.sh
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

mkdir -p "$T/dist/bas-install-1.9.9.3" "$T/elsewhere"
printf '%s  bas-agent-linux-amd64\n' "$(h 1)" > "$T/dist/bas-install-1.9.9.3/BINARIES.sha256"
printf '%s  bas-agent-linux-amd64\n' "$(h 1)" > "$T/elsewhere/BINARIES.sha256"
newm() { printf '%s  bas-agent-linux-amd64\n' "$(h "$1")" > "$2"; }

echo "the version comes from the previous release folder"
newm 11 "$T/m"
sh "$SCRIPT" carry "$T/m" "$T/dist/bas-install-1.9.9.3/BINARIES.sha256" >/dev/null 2>&1
grep -qx "#prev-version 1.9.9.3" "$T/m" && pass "#prev-version 1.9.9.3 written" || fail "no #prev-version line"
grep -qx "#prev $(h 1)  bas-agent-linux-amd64" "$T/m" && pass "the #prev hash is still carried" || fail "#prev hash lost"

echo "idempotent"
before="$(cat "$T/m")"
sh "$SCRIPT" carry "$T/m" "$T/dist/bas-install-1.9.9.3/BINARIES.sha256" >/dev/null 2>&1
[ "$(cat "$T/m")" = "$before" ] && pass "a second carry adds nothing" || fail "second carry changed the manifest"

echo "an existing version line is never overwritten or doubled"
newm 12 "$T/m2"; printf '#prev-version 1.9.0\n' >> "$T/m2"
sh "$SCRIPT" carry "$T/m2" "$T/dist/bas-install-1.9.9.3/BINARIES.sha256" >/dev/null 2>&1
[ "$(grep -c '^#prev-version' "$T/m2")" = "1" ] && grep -qx "#prev-version 1.9.0" "$T/m2" && pass "kept the one that was there" || fail "version line changed or doubled"

echo "no version is invented when the folder does not say"
newm 13 "$T/m3"
sh "$SCRIPT" carry "$T/m3" "$T/elsewhere/BINARIES.sha256" >/dev/null 2>&1
grep -q '^#prev-version' "$T/m3" && fail "wrote a version from a folder with no version" || pass "no #prev-version line"

echo "verify accepts the version line, and the line is not read as a hash"
sh "$SCRIPT" verify "$T/m" "$T/dist/bas-install-1.9.9.3/BINARIES.sha256" >/dev/null 2>&1 && pass "verify passes with a #prev-version line" || fail "verify rejected #prev-version"
sh "$SCRIPT" carry "$T/m" "$T/m" >/dev/null 2>&1
[ "$(grep -c '^#prev ' "$T/m")" = "1" ] && pass "still exactly one #prev hash line" || fail "version line leaked into the hash lines"

echo
if [ "$fails" -eq 0 ]; then echo "PASS: all checks passed"; else echo "FAIL: $fails check(s) failed"; exit 1; fi
