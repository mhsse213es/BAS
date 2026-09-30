#!/usr/bin/env bash
# packaging/signing/sign-macos.test.sh
set -euo pipefail

TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

# Mock codesign and xcrun as functions that log their invocation instead of
# doing real work -- this proves the script calls them correctly, not that
# Apple's real tools would accept the call (no macOS host in this session).
CALL_LOG="$TESTDIR/calls.log"
codesign() { echo "codesign $*" >> "$CALL_LOG"; return 0; }
xcrun() { echo "xcrun $*" >> "$CALL_LOG"; return 0; }
export -f codesign xcrun

# shellcheck disable=SC1091
source "$(dirname "$0")/sign-macos.sh"
# shellcheck disable=SC1091
source "$(dirname "$0")/verify-macos-signature.sh"

touch "$TESTDIR/bas-agent-darwin-amd64"

echo "TEST: sign_macos calls codesign, then notarytool submit, then stapler staple, in order"
sign_macos "$TESTDIR/bas-agent-darwin-amd64" "Developer ID Application: Audspect (TEAMID)" "TEAMID" "notary-profile"
mapfile -t calls < "$CALL_LOG"
[ "${#calls[@]}" -eq 3 ] || { echo "FAIL: expected 3 calls, got ${#calls[@]}"; exit 1; }
[[ "${calls[0]}" == codesign* ]] || { echo "FAIL: call 1 was not codesign: ${calls[0]}"; exit 1; }
[[ "${calls[1]}" == *"notarytool submit"* ]] || { echo "FAIL: call 2 was not notarytool submit: ${calls[1]}"; exit 1; }
[[ "${calls[2]}" == *"stapler staple"* ]] || { echo "FAIL: call 3 was not stapler staple: ${calls[2]}"; exit 1; }
echo "PASS"

echo "TEST: sign_macos returns non-zero and skips later steps if codesign fails"
: > "$CALL_LOG"
codesign() { echo "codesign $*" >> "$CALL_LOG"; return 1; }
export -f codesign
if sign_macos "$TESTDIR/bas-agent-darwin-amd64" "Developer ID Application: Audspect (TEAMID)" "TEAMID" "notary-profile"; then
    echo "FAIL: sign_macos should have returned non-zero when codesign fails"
    exit 1
fi
mapfile -t calls < "$CALL_LOG"
[ "${#calls[@]}" -eq 1 ] || { echo "FAIL: expected sign_macos to stop after the failed codesign call, got ${#calls[@]} calls"; exit 1; }
echo "PASS"

echo "TEST: verify_macos_signature passes when both codesign --verify and spctl --assess succeed"
: > "$CALL_LOG"
codesign() { echo "codesign $*" >> "$CALL_LOG"; return 0; }
spctl() { echo "spctl $*" >> "$CALL_LOG"; return 0; }
export -f codesign spctl
if ! verify_macos_signature "$TESTDIR/bas-agent-darwin-amd64"; then
    echo "FAIL: verify_macos_signature should have passed"
    exit 1
fi
echo "PASS"

echo "TEST: verify_macos_signature fails when codesign --verify fails"
: > "$CALL_LOG"
codesign() { echo "codesign $*" >> "$CALL_LOG"; return 1; }
export -f codesign
if verify_macos_signature "$TESTDIR/bas-agent-darwin-amd64"; then
    echo "FAIL: verify_macos_signature should have failed when codesign --verify fails"
    exit 1
fi
echo "PASS"

echo "TEST: verify_macos_signature fails when spctl --assess fails (not notarized/stapled)"
: > "$CALL_LOG"
codesign() { echo "codesign $*" >> "$CALL_LOG"; return 0; }
spctl() { echo "spctl $*" >> "$CALL_LOG"; return 1; }
export -f codesign spctl
if verify_macos_signature "$TESTDIR/bas-agent-darwin-amd64"; then
    echo "FAIL: verify_macos_signature should have failed when spctl --assess fails"
    exit 1
fi
echo "PASS"

echo "ALL TESTS PASSED"
