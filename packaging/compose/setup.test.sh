#!/usr/bin/env bash
# packaging/compose/setup.test.sh
#
# Unit tests for functions defined directly in setup.sh. Safe to source
# because setup.sh guards its own `main "$@"` call behind a
# BASH_SOURCE-vs-$0 check -- sourcing it defines functions and readonly
# constants only, it never launches the installer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/setup.sh"

echo "TEST: check_install_state reports PASS for a fresh install directory"
INSTALL_DIR="$TESTDIR/fresh"
RESUME=false
REINSTALL=false
mkdir -p "$INSTALL_DIR"
result=$(check_install_state)
[[ "$result" == PASS:* ]] || { echo "FAIL: expected PASS, got: $result"; exit 1; }
echo "PASS"

echo "TEST: check_install_state reports FAIL (naming --resume) for an interrupted install without --resume"
INSTALL_DIR="$TESTDIR/interrupted"
RESUME=false
REINSTALL=false
mkdir -p "$INSTALL_DIR"
echo "JWT_SECRET=abc" > "$INSTALL_DIR/.env"
result=$(check_install_state)
[[ "$result" == FAIL:* ]] || { echo "FAIL: expected FAIL, got: $result"; exit 1; }
[[ "$result" == *"--resume"* ]] || { echo "FAIL: expected the message to name --resume, got: $result"; exit 1; }
echo "PASS"

echo "TEST: check_install_state reports PASS for an interrupted install when --resume was passed"
INSTALL_DIR="$TESTDIR/interrupted2"
RESUME=true
REINSTALL=false
mkdir -p "$INSTALL_DIR"
echo "JWT_SECRET=abc" > "$INSTALL_DIR/.env"
result=$(check_install_state)
[[ "$result" == PASS:* ]] || { echo "FAIL: expected PASS, got: $result"; exit 1; }
echo "PASS"

echo "TEST: check_install_state reports FAIL (naming --reinstall) for a completed install without --reinstall"
INSTALL_DIR="$TESTDIR/complete"
RESUME=false
REINSTALL=false
mkdir -p "$INSTALL_DIR"
echo "JWT_SECRET=abc" > "$INSTALL_DIR/.env"
write_install_complete_marker "$INSTALL_DIR"
result=$(check_install_state)
[[ "$result" == FAIL:* ]] || { echo "FAIL: expected FAIL, got: $result"; exit 1; }
[[ "$result" == *"--reinstall"* ]] || { echo "FAIL: expected the message to name --reinstall, got: $result"; exit 1; }
echo "PASS"

echo "TEST: check_install_state reports PASS for a completed install when --reinstall was passed"
INSTALL_DIR="$TESTDIR/complete2"
RESUME=false
REINSTALL=true
mkdir -p "$INSTALL_DIR"
echo "JWT_SECRET=abc" > "$INSTALL_DIR/.env"
write_install_complete_marker "$INSTALL_DIR"
result=$(check_install_state)
[[ "$result" == PASS:* ]] || { echo "FAIL: expected PASS, got: $result"; exit 1; }
echo "PASS"

echo "TEST: page_prereqs's check loop and the --no-wizard check loop both call check_install_state"
NOWIZ_COUNT=$(grep -c 'check_install_state' "${SCRIPT_DIR}/setup.sh")
[[ "$NOWIZ_COUNT" -ge 2 ]] || { echo "FAIL: expected check_install_state wired into both prereq-check blocks, found $NOWIZ_COUNT references"; exit 1; }
echo "PASS"

echo "ALL TESTS PASSED"
