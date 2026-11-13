#!/usr/bin/env bash
# packaging/build-prev-guard.test.sh
#
# Proves build.sh refuses to build when no earlier release is under dist/ (the agents on that release would be
# quarantined after the upgrade), that BAS_ALLOW_NO_PREVIOUS=1 overrides it, and that an earlier release is used.
# It runs the real block from build.sh, copied out, so the test cannot drift from the script.
# Run: bash packaging/build-prev-guard.test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# The block runs from the line that starts the previous-release search to the export.
awk '/^PREV_MANIFEST=""/{on=1} on{print} /^export BAS_PREVIOUS_MANIFEST=/{exit}' "$HERE/build.sh" > "$T/block.sh"
[[ -s "$T/block.sh" ]] || { echo "FAIL could not extract the guard block from build.sh"; exit 1; }

run() { # run <dist> [env assignments...]; prints the exit code
  local dist="$1"; shift
  ( env -i PATH="$PATH" "$@" bash -c '
      GREEN=""; YELLOW=""; RED=""; NC=""
      log()  { echo "[+] $*"; }; warn() { echo "[!] $*"; }; err() { echo "[x] $*" >&2; }
      VERSION=1.9.9.3; DIST_DIR="$1"
      source "$2"' _ "$dist" "$T/block.sh" ) >/dev/null 2>&1
  echo $?
}

fails=0
check() { if [[ "$2" == "$3" ]]; then echo "  ok   $1"; else echo "  FAIL $1 (exit $2, want $3)"; fails=$((fails+1)); fi; }

empty="$T/dist-empty"; mkdir -p "$empty"
check "no earlier release refuses the build" "$(run "$empty")" 1
check "BAS_ALLOW_NO_PREVIOUS=1 builds without one" "$(run "$empty" BAS_ALLOW_NO_PREVIOUS=1)" 0

withprev="$T/dist-prev"; mkdir -p "$withprev/bas-install-1.9.9.2"
echo "0000 x" > "$withprev/bas-install-1.9.9.2/BINARIES.sha256"
check "an earlier release is used" "$(run "$withprev")" 0

if (( fails > 0 )); then echo "$fails failure(s)"; exit 1; fi
echo "all passed"
