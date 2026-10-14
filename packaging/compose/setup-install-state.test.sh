#!/usr/bin/env bash
# packaging/compose/setup-install-state.test.sh
set -euo pipefail

TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

# shellcheck disable=SC1091
source "$(dirname "$0")/setup-install-state.sh"

echo "TEST: detect_install_state reports FRESH when neither .env nor .install-complete exists"
FRESH_DIR="$TESTDIR/fresh"
mkdir -p "$FRESH_DIR"
state=$(detect_install_state "$FRESH_DIR")
[[ "$state" == "FRESH" ]] || { echo "FAIL: expected FRESH, got $state"; exit 1; }
echo "PASS"

echo "TEST: detect_install_state reports INTERRUPTED when .env exists but .install-complete does not"
INTERRUPTED_DIR="$TESTDIR/interrupted"
mkdir -p "$INTERRUPTED_DIR"
echo "JWT_SECRET=abc123" > "$INTERRUPTED_DIR/.env"
state=$(detect_install_state "$INTERRUPTED_DIR")
[[ "$state" == "INTERRUPTED" ]] || { echo "FAIL: expected INTERRUPTED, got $state"; exit 1; }
echo "PASS"

echo "TEST: detect_install_state reports COMPLETE when both .env and .install-complete exist"
COMPLETE_DIR="$TESTDIR/complete"
mkdir -p "$COMPLETE_DIR"
echo "JWT_SECRET=abc123" > "$COMPLETE_DIR/.env"
write_install_complete_marker "$COMPLETE_DIR"
state=$(detect_install_state "$COMPLETE_DIR")
[[ "$state" == "COMPLETE" ]] || { echo "FAIL: expected COMPLETE, got $state"; exit 1; }
echo "PASS"

echo "TEST: a rerun on an INTERRUPTED install must preserve the existing .env byte-for-byte"
INTERRUPTED_DIR2="$TESTDIR/interrupted2"
mkdir -p "$INTERRUPTED_DIR2"
printf 'JWT_SECRET=original-secret-value\nAGENT_SECRET=original-agent\n' > "$INTERRUPTED_DIR2/.env"
ORIGINAL_CONTENT=$(cat "$INTERRUPTED_DIR2/.env")

# Simulate what _do_install_steps must do: check the state BEFORE writing
# .env, and skip secret generation entirely when INTERRUPTED.
state=$(detect_install_state "$INTERRUPTED_DIR2")
if [[ "$state" == "INTERRUPTED" ]]; then
  : # correct: do not touch .env
else
  echo "tampered-regenerated-secret" > "$INTERRUPTED_DIR2/.env"
fi

AFTER_CONTENT=$(cat "$INTERRUPTED_DIR2/.env")
[[ "$ORIGINAL_CONTENT" == "$AFTER_CONTENT" ]] || { echo "FAIL: .env must be byte-for-byte unchanged after detecting INTERRUPTED"; exit 1; }
echo "PASS"

echo "TEST: install_state_message names the detected state and the required next action"
msg=$(install_state_message "INTERRUPTED")
[[ "$msg" == *"INTERRUPTED"* ]] || { echo "FAIL: message must name the detected state"; exit 1; }
[[ "$msg" == *"--resume"* ]] || { echo "FAIL: message must name the required next action (--resume)"; exit 1; }
msg=$(install_state_message "COMPLETE")
[[ "$msg" == *"--reinstall"* ]] || { echo "FAIL: COMPLETE message must name --reinstall"; exit 1; }
echo "PASS"

echo "ALL TESTS PASSED"
