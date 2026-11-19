#!/usr/bin/env bash
# packaging/compose/tests/db_encryption_key_test.sh
# Exercises db-encryption-key.sh. The expected owner and group are set to this user's IDs, so the checks run without root.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

export DB_KEY_UID="$(id -u)"
export DB_KEY_GID="$(id -g)"
export BAS_DB_KEY_PASSPHRASE="correct horse battery"

pass=0
fail=0
skip=0
ok()   { echo "PASS: $1"; pass=$((pass + 1)); }
bad()  { echo "FAIL: $1"; fail=$((fail + 1)); }
note_skip() { echo "SKIP: $1"; skip=$((skip + 1)); }

# Mode bits are enforced only on a POSIX filesystem. Probe once: if chmod does not stick (for example on NTFS under Git Bash),
# assertions about the mode are skipped and reported as skipped, never as passed. Run the suite on Linux to cover them.
probe="$TESTDIR/mode-probe"
: > "$probe"
chmod 0640 "$probe"
if [[ "$(stat -c %a "$probe")" == "640" ]]; then MODE_ENFORCED=1; else MODE_ENFORCED=0; fi

# fresh_env NAME: a new key directory for one test, and the helper sourced against it.
fresh_env() {
  DB_KEY_DIR="$TESTDIR/$1/secrets"
  export DB_KEY_DIR
  # shellcheck disable=SC1091
  source "$HERE/db-encryption-key.sh"
}

# --- fresh install generates a valid key ---
fresh_env fresh
if db_key_provision fresh >/dev/null 2>&1 && db_key_content_ok "$DB_KEY_FILE" && { [[ $MODE_ENFORCED -eq 0 ]] || db_key_perms_ok "$DB_KEY_FILE"; }; then
  ok "fresh install generates a 32-byte key with the expected owner and mode"
else
  bad "fresh install did not generate a valid key"
fi

# --- reuse: a second fresh provision keeps the same key ---
before=$(sha256sum "$DB_KEY_FILE" | cut -d' ' -f1)
db_key_provision fresh >/dev/null 2>&1
after=$(sha256sum "$DB_KEY_FILE" | cut -d' ' -f1)
[[ "$before" == "$after" ]] && ok "re-running provisioning keeps the existing key" || bad "provisioning replaced an existing key"

# --- upgrade with a missing key refuses and creates nothing, once a key has been issued before (marker present) ---
fresh_env upgrade_missing
mkdir -p "$TESTDIR/upgrade_missing"
export DB_KEY_MARKER="$TESTDIR/upgrade_missing/marker"
: > "$DB_KEY_MARKER"
if db_key_provision upgrade >/dev/null 2>&1; then
  bad "upgrade generated a key where none existed"
elif [[ -e "$DB_KEY_FILE" ]]; then
  bad "upgrade left a file behind"
else
  ok "upgrade refuses to generate a key when none exists"
fi

# --- upgrade of an install that was never issued a key (no marker) generates one and records the marker ---
fresh_env upgrade_first
mkdir -p "$TESTDIR/upgrade_first"
export DB_KEY_MARKER="$TESTDIR/upgrade_first/marker"
if db_key_provision upgrade >/dev/null 2>&1 && db_key_content_ok "$DB_KEY_FILE" && [[ -e "$DB_KEY_MARKER" ]]; then
  ok "first upgrade of an install with no key generates one and records the marker"
else
  bad "first upgrade did not generate a key and marker"
fi
# --- after that, losing the key is refused: the marker proves one was issued ---
rm -f "$DB_KEY_FILE"
if db_key_provision upgrade >/dev/null 2>&1; then
  bad "upgrade regenerated a key that had been issued before"
else
  ok "upgrade refuses to regenerate a key once the marker exists"
fi
unset DB_KEY_MARKER

# --- upgrade with a valid key succeeds ---
fresh_env upgrade_present
db_key_provision fresh >/dev/null 2>&1
db_key_provision upgrade >/dev/null 2>&1 && ok "upgrade accepts an existing valid key" || bad "upgrade rejected a valid key"

# --- drifted mode is repaired when the content is valid ---
fresh_env repair
db_key_provision fresh >/dev/null 2>&1
chmod 0644 "$DB_KEY_FILE"
if [[ $MODE_ENFORCED -eq 0 ]]; then
  note_skip "drifted mode repair (mode bits not enforced on this filesystem)"
elif db_key_provision fresh >/dev/null 2>&1 && db_key_perms_ok "$DB_KEY_FILE"; then
  ok "a key with drifted mode is repaired"
else
  bad "a key with drifted mode was not repaired"
fi

# --- corrupt content is refused and left unchanged ---
fresh_env corrupt
mkdir -p "$DB_KEY_DIR"
printf 'not-a-key' > "$DB_KEY_FILE"
before=$(sha256sum "$DB_KEY_FILE" | cut -d' ' -f1)
if db_key_provision fresh >/dev/null 2>&1; then
  bad "a corrupt key was accepted"
else
  after=$(sha256sum "$DB_KEY_FILE" | cut -d' ' -f1)
  [[ "$before" == "$after" ]] && ok "a corrupt key is refused and left unchanged" || bad "a corrupt key was overwritten"
fi

# --- a key with two lines is refused ---
fresh_env twolines
mkdir -p "$DB_KEY_DIR"
k=$(head -c 32 /dev/urandom | base64 -w0)
printf '%s\n%s\n' "$k" "$k" > "$DB_KEY_FILE"
db_key_content_ok "$DB_KEY_FILE" && bad "a two-line key passed the content check" || ok "a two-line key fails the content check"

# --- export then import restores the same key ---
fresh_env roundtrip
db_key_provision fresh >/dev/null 2>&1
original=$(cat "$DB_KEY_FILE")
recovery="$TESTDIR/recovery.enc"
db_key_export "$recovery" >/dev/null 2>&1
if [[ ! -f "$recovery" ]] || grep -q "$original" "$recovery"; then
  bad "the recovery copy is missing or contains the plaintext key"
else
  rm -f "$DB_KEY_FILE"
  if db_key_import "$recovery" >/dev/null 2>&1 && [[ "$(cat "$DB_KEY_FILE")" == "$original" ]]; then
    ok "export then import restores the same key, and the recovery copy holds no plaintext"
  else
    bad "import did not restore the key"
  fi
fi

# --- import with the wrong passphrase writes nothing ---
fresh_env wrongpass
db_key_provision fresh >/dev/null 2>&1
recovery2="$TESTDIR/recovery2.enc"
db_key_export "$recovery2" >/dev/null 2>&1
rm -f "$DB_KEY_FILE"
if BAS_DB_KEY_PASSPHRASE="a wrong passphrase" db_key_import "$recovery2" >/dev/null 2>&1; then
  bad "import accepted a wrong passphrase"
elif [[ -e "$DB_KEY_FILE" ]]; then
  bad "a failed import left a key behind"
else
  ok "import with a wrong passphrase writes nothing"
fi

# --- import refuses to replace an existing key ---
fresh_env noreplace
db_key_provision fresh >/dev/null 2>&1
recovery3="$TESTDIR/recovery3.enc"
db_key_export "$recovery3" >/dev/null 2>&1
if db_key_import "$recovery3" >/dev/null 2>&1; then
  bad "import replaced an existing key"
else
  ok "import refuses to replace an existing key"
fi

# --- export refuses to overwrite ---
if db_key_export "$recovery3" >/dev/null 2>&1; then
  bad "export overwrote an existing recovery copy"
else
  ok "export refuses to overwrite an existing recovery copy"
fi

echo "---"
echo "passed: $pass  failed: $fail  skipped: $skip  (mode bits enforced: $MODE_ENFORCED)"
[[ "$fail" -eq 0 ]]
