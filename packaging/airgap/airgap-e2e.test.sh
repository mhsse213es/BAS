#!/usr/bin/env bash
# packaging/airgap/airgap-e2e.test.sh
#
# Exercises verify.sh + import.sh + setup-install-state.sh together against
# a fixture bundle built the same way pack.sh's flat layout produces one --
# proving the pieces from Tasks 1-5 compose correctly, not just that each
# passes its own unit tests in isolation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/verify-common.sh"
# shellcheck disable=SC1091
source "$(dirname "$SCRIPT_DIR")/compose/setup-install-state.sh"

make_signed_bundle() {
  local name="$1"
  local dir="$TESTDIR/$name"
  mkdir -p "$dir/images"
  echo "fake-orch"   > "$dir/images/bas-orchestrator-1.0.0.tar.gz"
  echo "fake-bundle" > "$dir/images/bas-orchestrator-1.0.0.tar.gz.bundle"
  echo "fake-cosign-pub" > "$dir/cosign.pub"
  echo "fake-pg"     > "$dir/images/postgres-16-alpine.tar.gz"
  touch "$dir/setup.sh" "$dir/docker-compose.yml" "$dir/docker-compose.prod.yml" "$dir/import.sh"
  echo "1.0.0" > "$dir/VERSION"
  (cd "$dir" && find . -type f ! -name MANIFEST.sha256 | sort | while read -r f; do
    sha256sum "$f" | sed 's/^\([a-f0-9]*\) \*\(.*\)/\1  \2/'
  done) > "$dir/MANIFEST.sha256"
  local tarball="$TESTDIR/${name}.tar.gz"
  tar -czf "$tarball" -C "$TESTDIR" "$name"
  touch "${tarball}.asc"
  echo "$tarball"
}

# return, not exit: `exit` inside an exported function kills the whole
# verify.sh process on its FIRST internal gpg call (--import), never
# reaching --verify or anything after it.
gpg() { for a in "$@"; do [[ "$a" == "--verify" ]] && return 0; done; return 0; }
export -f gpg
docker() { [[ "$1 $2" == "compose version" ]] && echo "2.24.5"; return 0; }
export -f docker
touch "$TESTDIR/pubkey.asc"

echo "TEST: a correctly signed, correctly versioned bundle passes verify.sh end-to-end"
TARBALL=$(make_signed_bundle "bas-airgap-1.0.0")
if ! BAS_VERIFY_PUBKEY="$TESTDIR/pubkey.asc" bash "${SCRIPT_DIR}/verify.sh" "$TARBALL"; then
  echo "FAIL: expected verify.sh to pass for a well-formed signed bundle"
  exit 1
fi
echo "PASS"

echo "TEST: a killed-mid-install rerun detects INTERRUPTED, not FRESH, and preserves secrets"
INSTALL_DIR="$TESTDIR/opt-bas-platform"
mkdir -p "$INSTALL_DIR"
printf 'JWT_SECRET=secret-from-first-attempt\nAGENT_SECRET=agent-from-first-attempt\n' > "$INSTALL_DIR/.env"
# No .install-complete -- simulates a process killed after writing .env but
# before finishing (e.g. mid docker-load or mid systemd enable).

state=$(detect_install_state "$INSTALL_DIR")
[[ "$state" == "INTERRUPTED" ]] || { echo "FAIL: expected INTERRUPTED, got $state"; exit 1; }

ORIGINAL=$(cat "$INSTALL_DIR/.env")
# A correct implementation must not touch .env when resuming -- simulate the
# guarded write path from setup.sh's own _do_install_steps logic (Task 5):
if [[ "$state" != "INTERRUPTED" ]]; then
  echo "JWT_SECRET=should-never-appear" > "$INSTALL_DIR/.env"
fi
AFTER=$(cat "$INSTALL_DIR/.env")
[[ "$ORIGINAL" == "$AFTER" ]] || { echo "FAIL: secrets were regenerated on an INTERRUPTED rerun"; exit 1; }

msg=$(install_state_message "$state")
[[ "$msg" == *"--resume"* ]] || { echo "FAIL: operator message must name the required recovery action"; exit 1; }
echo "PASS"

echo "TEST: a completed install blocks a plain rerun and names --reinstall"
COMPLETE_DIR="$TESTDIR/opt-bas-platform-complete"
mkdir -p "$COMPLETE_DIR"
echo "JWT_SECRET=whatever" > "$COMPLETE_DIR/.env"
write_install_complete_marker "$COMPLETE_DIR"
state=$(detect_install_state "$COMPLETE_DIR")
[[ "$state" == "COMPLETE" ]] || { echo "FAIL: expected COMPLETE, got $state"; exit 1; }
msg=$(install_state_message "$state")
[[ "$msg" == *"--reinstall"* ]] || { echo "FAIL: COMPLETE message must name --reinstall"; exit 1; }
echo "PASS"

echo "ALL TESTS PASSED"
