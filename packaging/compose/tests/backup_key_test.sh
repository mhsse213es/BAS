#!/usr/bin/env bash
# packaging/compose/tests/backup_key_test.sh
# Exercises backup-key.sh: archive encryption uses a key outside the backup directory, with no fallback to the
# co-located legacy key for new archives, and explicit fallback only when restoring a legacy archive.
set -euo pipefail

# Git Bash on Windows rewrites "/CN=..." arguments as paths; this stops that. No effect on Linux.
export MSYS2_ARG_CONV_EXCL="*"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
TESTDIR="$(mktemp -d)"
if command -v cygpath >/dev/null 2>&1; then TESTDIR="$(cygpath -m "$TESTDIR")"; fi
trap 'rm -rf "$TESTDIR"' EXIT

# shellcheck source=../backup-key.sh
source "$HERE/backup-key.sh"

pass=0
fail=0
skip=0
ok()  { echo "PASS: $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; fail=$((fail + 1)); }

DATA="$TESTDIR/data"
mkdir -p "$DATA"
NEW_KEY="$TESTDIR/secrets/backup-encryption.key"
export BACKUP_KEY_FILE="$NEW_KEY"
export BACKUP_KEY_LEGACY="$DATA/.backup_key"
export DATA_DIR="$DATA"

echo "backup archive plaintext for the tests" > "$TESTDIR/archive.tar"

# --- provisioning creates a key outside DATA_DIR ---
if backup_key_provision >/dev/null 2>&1; then ok "provision creates the key"; else bad "provision failed"; fi
if [[ -s "$NEW_KEY" ]]; then ok "key file is non-empty"; else bad "key file missing or empty"; fi
case "$NEW_KEY" in "$DATA"/*) bad "key lives inside DATA_DIR";; *) ok "key lives outside DATA_DIR";; esac
probe="$TESTDIR/mode-probe"; : > "$probe"; chmod 0640 "$probe"
if [[ "$(stat -c %a "$probe")" == "640" ]]; then
  if [[ "$(stat -c %a "$NEW_KEY")" == "600" ]]; then ok "key is mode 0600"; else bad "key mode is not 0600"; fi
else
  echo "SKIP: mode bits are not enforced on this filesystem; run on Linux to check 0600"; skip=$((skip + 1))
fi

# provisioning again must not regenerate the key
before=$(sha256sum "$NEW_KEY" | cut -d' ' -f1)
backup_key_provision >/dev/null 2>&1 || true
after=$(sha256sum "$NEW_KEY" | cut -d' ' -f1)
if [[ "$before" == "$after" ]]; then ok "second provision keeps the key"; else bad "second provision regenerated the key"; fi

# --- new archives: round trip with the new key ---
if backup_key_encrypt "$TESTDIR/archive.tar" "$TESTDIR/new.tar.enc" >/dev/null 2>&1; then ok "encrypt with the new key"; else bad "encrypt failed"; fi
if backup_key_decrypt "$TESTDIR/new.tar.enc" "$TESTDIR/new.out" >/dev/null 2>&1 && cmp -s "$TESTDIR/archive.tar" "$TESTDIR/new.out"; then
  ok "new archive round-trips"
else
  bad "new archive does not round-trip"
fi

# --- separation: the key in DATA_DIR does not decrypt a new archive ---
# Simulate the exposure this change closes: a copy of DATA_DIR holding the legacy key, with the new key absent.
openssl rand -base64 48 > "$DATA/.backup_key"
if BACKUP_KEY_FILE="$TESTDIR/absent.key" backup_key_decrypt "$TESTDIR/new.tar.enc" "$TESTDIR/leak.out" >/dev/null 2>&1; then
  bad "a DATA_DIR-only copy decrypted a new archive"
else
  ok "a DATA_DIR-only copy cannot decrypt a new archive"
fi

# --- no fallback for new archives: a missing new key fails encryption, even with the legacy key present ---
if BACKUP_KEY_FILE="$TESTDIR/absent.key" backup_key_encrypt "$TESTDIR/archive.tar" "$TESTDIR/fallback.tar.enc" >/dev/null 2>&1; then
  bad "encryption fell back to the legacy key"
elif [[ ! -e "$TESTDIR/fallback.tar.enc" ]]; then
  ok "missing new key fails encryption; no output and no fallback"
else
  bad "a partial archive was written"
fi

# --- legacy archives still restore, with an explicit notice ---
openssl enc -aes-256-cbc -pbkdf2 -salt -in "$TESTDIR/archive.tar" -out "$TESTDIR/legacy.tar.enc" -pass "file:$DATA/.backup_key" 2>/dev/null
if backup_key_decrypt "$TESTDIR/legacy.tar.enc" "$TESTDIR/legacy.out" >$TESTDIR/bk_notice 2>&1 && cmp -s "$TESTDIR/archive.tar" "$TESTDIR/legacy.out"; then
  ok "legacy archive restores with the legacy key"
else
  bad "legacy archive did not restore"
fi
if grep -qi "legacy" $TESTDIR/bk_notice; then ok "legacy restore prints an explicit notice"; else bad "legacy restore gave no notice"; fi
rm -f $TESTDIR/bk_notice

# --- a wrong key is refused and writes nothing ---
if BACKUP_KEY_FILE="$TESTDIR/wrong.key" backup_key_decrypt "$TESTDIR/new.tar.enc" "$TESTDIR/wrong.out" >/dev/null 2>&1; then
  bad "wrong key decrypted the archive"
else
  ok "wrong key is refused"
fi

# --- legacy key reporting ---
if backup_key_legacy_present; then ok "legacy key is reported while it exists"; else bad "legacy key not reported"; fi
rm -f "$DATA/.backup_key"
if ! backup_key_legacy_present; then ok "legacy key is not reported once removed"; else bad "removed legacy key still reported"; fi

echo "---"
echo "passed: $pass  failed: $fail  skipped: $skip"
[[ "$fail" -eq 0 ]]
