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

# --- recovery copy: export, verify, and the gate that blocks backups until one is confirmed ---
PASSPHRASE="correct horse battery staple"
RECOV_DIR="$TESTDIR/recovery"; mkdir -p "$RECOV_DIR"
RECOV="$RECOV_DIR/backup-key.enc"
export BACKUP_KEY_MARKER="$DATA/.backup-key-recovery-verified"
unset BAS_BACKUP_KEY_PASSPHRASE BAS_BACKUP_KEY_RECOVERY_PATH

if BAS_BACKUP_KEY_PASSPHRASE="short" backup_key_export "$RECOV_DIR/short.enc" >/dev/null 2>&1; then
  bad "export accepted a short passphrase"
else
  ok "export refuses a short passphrase"
fi
if backup_key_export "$RECOV_DIR/nopass.enc" >/dev/null 2>&1; then
  bad "export ran without a passphrase"
else
  ok "export refuses to run without a passphrase"
fi
if BAS_BACKUP_KEY_PASSPHRASE="$PASSPHRASE" backup_key_export "$DATA/inside.enc" >/dev/null 2>&1; then
  bad "export wrote a recovery copy inside DATA_DIR"
else
  ok "export refuses a path inside DATA_DIR"
fi
if BAS_BACKUP_KEY_PASSPHRASE="$PASSPHRASE" backup_key_export "$RECOV" >/dev/null 2>&1 && [[ -s "$RECOV" ]]; then
  ok "export writes the recovery copy"
else
  bad "export failed"
fi
if [[ "$(stat -c %a "$RECOV" 2>/dev/null)" == "600" ]]; then ok "recovery copy is mode 0600"; elif [[ ! -e "$probe" || "$(stat -c %a "$probe")" != "640" ]]; then echo "SKIP: mode bits not enforced here"; skip=$((skip + 1)); else bad "recovery copy mode is not 0600"; fi
if BAS_BACKUP_KEY_PASSPHRASE="$PASSPHRASE" backup_key_export "$RECOV" >/dev/null 2>&1; then
  bad "export overwrote an existing recovery copy"
else
  ok "export refuses to overwrite an existing recovery copy"
fi
if cmp -s "$RECOV" "$NEW_KEY"; then bad "recovery copy is plaintext"; else ok "recovery copy is not plaintext"; fi

if BAS_BACKUP_KEY_PASSPHRASE="$PASSPHRASE" backup_key_verify_recovery "$RECOV" >/dev/null 2>&1; then
  ok "verify accepts the right passphrase and matching key"
else
  bad "verify rejected a good recovery copy"
fi
if BAS_BACKUP_KEY_PASSPHRASE="wrong passphrase value" backup_key_verify_recovery "$RECOV" >/dev/null 2>&1; then
  bad "verify accepted the wrong passphrase"
else
  ok "verify refuses the wrong passphrase"
fi
openssl rand -base64 48 > "$TESTDIR/other.key"
BAS_BACKUP_KEY_PASSPHRASE="$PASSPHRASE" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BAS_BACKUP_KEY_PASSPHRASE -in "$TESTDIR/other.key" -out "$RECOV_DIR/other.enc"
if BAS_BACKUP_KEY_PASSPHRASE="$PASSPHRASE" backup_key_verify_recovery "$RECOV_DIR/other.enc" >/dev/null 2>&1; then
  bad "verify accepted a recovery copy of a different key"
else
  ok "verify refuses a recovery copy of a different key"
fi

# gate: no marker and no non-interactive inputs -> refused, with the command to run
if backup_key_recovery_confirm >/dev/null 2>&1; then
  bad "backups were allowed without a confirmed recovery copy"
else
  ok "gate refuses until a recovery copy is confirmed"
fi
gate_msg=$(backup_key_recovery_confirm 2>&1 || true)
if grep -q "export-backup-key" <<<"$gate_msg"; then ok "gate names the command to run"; else bad "gate gives no command: $gate_msg"; fi

# non-interactive confirmation: exports, verifies, writes the marker
rm -f "$RECOV"
if BAS_BACKUP_KEY_RECOVERY_PATH="$RECOV" BAS_BACKUP_KEY_PASSPHRASE="$PASSPHRASE" backup_key_recovery_confirm >/dev/null 2>&1 && [[ -s "$BACKUP_KEY_MARKER" ]]; then
  ok "non-interactive confirmation exports, verifies and records the marker"
else
  bad "non-interactive confirmation failed"
fi
if grep -q "$(sha256sum "$NEW_KEY" | cut -d' ' -f1)" "$BACKUP_KEY_MARKER" 2>/dev/null; then ok "marker holds a hash, not the key"; else bad "marker does not match the key hash"; fi
if cmp -s "$BACKUP_KEY_MARKER" "$NEW_KEY"; then bad "marker is the key"; fi
if backup_key_recovery_confirm >/dev/null 2>&1; then ok "a recorded confirmation is accepted"; else bad "recorded confirmation rejected"; fi

# a replaced key invalidates the confirmation
cp "$NEW_KEY" "$TESTDIR/key.bak"
openssl rand -base64 48 > "$NEW_KEY"
if backup_key_recovery_confirm >/dev/null 2>&1; then bad "confirmation survived a key change"; else ok "a key change invalidates the confirmation"; fi
cp "$TESTDIR/key.bak" "$NEW_KEY"

echo "---"
echo "passed: $pass  failed: $fail  skipped: $skip"
[[ "$fail" -eq 0 ]]
