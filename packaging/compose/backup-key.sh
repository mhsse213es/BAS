#!/usr/bin/env bash
# packaging/compose/backup-key.sh
#
# Backup archive encryption key (P0.3). New archives are encrypted with a key outside the backup directory, in the
# secrets directory that also holds the database encryption key. Before this, the key was DATA_DIR/.backup_key, next
# to the archives: anyone with a copy of the archive and that file could read the archive.
#
# Rules:
#   - New archives use only the new key. If it is missing, encryption fails. There is no fallback to the legacy key.
#   - Restore tries the new key first. The legacy co-located key is tried only when the archive does not open with the
#     new key, and the restore says so, because that archive still has the exposure.
#   - The legacy key is never deleted automatically. Its removal is the last step of the historical-backup cleanup
#     (docs/security/req-039-customer-managed-keys.md), after a new archive has been restored successfully.
#
# Recovery: keep an offline copy of BACKUP_KEY_FILE. Without it, archives made with that key cannot be read.
#
# This file is sourced by install.sh. Functions return non-zero on failure and print a reason to stderr.

BACKUP_KEY_FILE="${BACKUP_KEY_FILE:-/etc/audspect/secrets/backup-encryption.key}"
BACKUP_KEY_LEGACY="${BACKUP_KEY_LEGACY:-${DATA_DIR:-}/.backup_key}"

_bk_err()  { echo "ERROR: $*" >&2; }
BACKUP_KEY_MARKER="${BACKUP_KEY_MARKER:-${DATA_DIR:-}/.backup-key-recovery-verified}"
BACKUP_KEY_MIN_PASSPHRASE=16
BACKUP_KEY_PBKDF2_ITER=600000
_bk_note() { echo "NOTICE: $*" >&2; }

# backup_key_provision: create the new key if absent. An existing key is never replaced.
backup_key_provision() {
  if [[ -s "$BACKUP_KEY_FILE" ]]; then
    return 0
  fi
  local dir tmp
  dir=$(dirname "$BACKUP_KEY_FILE")
  mkdir -p "$dir" || { _bk_err "cannot create ${dir}"; return 1; }
  tmp="${BACKUP_KEY_FILE}.tmp.$$"
  local old_umask
  old_umask=$(umask); umask 077
  if ! openssl rand -base64 48 > "$tmp" 2>/dev/null; then
    umask "$old_umask"; rm -f "$tmp"; _bk_err "could not generate the backup encryption key"; return 1
  fi
  umask "$old_umask"
  chmod 600 "$tmp" || { rm -f "$tmp"; _bk_err "could not set mode on the backup key"; return 1; }
  if [[ "$(id -u)" == "0" ]]; then chown root:root "$tmp" || { rm -f "$tmp"; _bk_err "could not set owner on the backup key"; return 1; }; fi
  mv -f "$tmp" "$BACKUP_KEY_FILE" || { rm -f "$tmp"; _bk_err "could not place the backup key at ${BACKUP_KEY_FILE}"; return 1; }
  return 0
}

# backup_key_legacy_present: the co-located legacy key still exists.
backup_key_legacy_present() {
  [[ -e "$BACKUP_KEY_LEGACY" ]]
}

# backup_key_encrypt IN OUT: encrypt with the new key only.
backup_key_encrypt() {
  local in="$1" out="$2"
  if [[ ! -s "$BACKUP_KEY_FILE" ]]; then
    _bk_err "backup encryption key ${BACKUP_KEY_FILE} is missing; the archive was not written. Restore the key from its offline copy, or run the installer to provision a new one."
    return 1
  fi
  if ! openssl enc -aes-256-cbc -pbkdf2 -salt -in "$in" -out "$out" -pass "file:${BACKUP_KEY_FILE}" 2>/dev/null; then
    rm -f "$out"; _bk_err "archive encryption failed"; return 1
  fi
  return 0
}

# backup_key_decrypt IN OUT: decrypt with the new key; fall back to the legacy key only for a legacy archive, with a notice.
backup_key_decrypt() {
  local in="$1" out="$2"
  if [[ -s "$BACKUP_KEY_FILE" ]] && openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$out" -pass "file:${BACKUP_KEY_FILE}" 2>/dev/null; then
    return 0
  fi
  rm -f "$out"
  if backup_key_legacy_present && openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$out" -pass "file:${BACKUP_KEY_LEGACY}" 2>/dev/null; then
    _bk_note "this archive was made with the legacy co-located backup key (${BACKUP_KEY_LEGACY}). Re-create backups so new archives use ${BACKUP_KEY_FILE}."
    return 0
  fi
  rm -f "$out"
  _bk_err "archive decryption failed: no available backup key opens this archive"
  return 1
}

# _bk_passphrase: the recovery passphrase from BAS_BACKUP_KEY_PASSPHRASE. Refuses a short one.
_bk_passphrase() {
  local p="${BAS_BACKUP_KEY_PASSPHRASE:-}"
  [[ -n "$p" ]] || { _bk_err "recovery passphrase is not set (BAS_BACKUP_KEY_PASSPHRASE)"; return 1; }
  (( ${#p} >= BACKUP_KEY_MIN_PASSPHRASE )) || { _bk_err "recovery passphrase must be at least ${BACKUP_KEY_MIN_PASSPHRASE} characters"; return 1; }
  return 0
}

# _bk_key_hash: SHA-256 of the live key. The marker stores this, never the key.
_bk_key_hash() { sha256sum "$BACKUP_KEY_FILE" 2>/dev/null | cut -d' ' -f1; }

# backup_key_export DEST: write the key encrypted under BAS_BACKUP_KEY_PASSPHRASE. Never overwrites DEST.
backup_key_export() {
  local dest="$1"
  [[ -n "$dest" ]] || { _bk_err "usage: install.sh --export-backup-key <recovery file>"; return 1; }
  [[ -s "$BACKUP_KEY_FILE" ]] || { _bk_err "no backup key at ${BACKUP_KEY_FILE}"; return 1; }
  [[ ! -e "$dest" ]] || { _bk_err "refusing to overwrite ${dest}"; return 1; }
  if [[ -n "${DATA_DIR:-}" && "$dest" == "${DATA_DIR}"* ]]; then _bk_err "the recovery copy must not be inside ${DATA_DIR} (the backup directory)"; return 1; fi
  _bk_passphrase || return 1
  local old_umask
  old_umask=$(umask); umask 077
  if ! BAS_BACKUP_KEY_PASSPHRASE_ENC="$BAS_BACKUP_KEY_PASSPHRASE" openssl enc -aes-256-cbc -pbkdf2 -iter "$BACKUP_KEY_PBKDF2_ITER" -salt         -pass env:BAS_BACKUP_KEY_PASSPHRASE_ENC -in "$BACKUP_KEY_FILE" -out "$dest" 2>/dev/null; then
    umask "$old_umask"; rm -f "$dest"; _bk_err "export failed"; return 1
  fi
  umask "$old_umask"
  chmod 600 "$dest" 2>/dev/null || true
  echo "Recovery copy written to ${dest}. Store it encrypted and off this host, separately from backups."
}

# backup_key_verify_recovery SRC: the recovery copy opens with the passphrase and holds the live key.
backup_key_verify_recovery() {
  local src="$1" tmp rc
  _bk_passphrase || return 1
  [[ -s "$BACKUP_KEY_FILE" && -f "$src" ]] || { _bk_err "recovery copy or live key is missing"; return 1; }
  tmp=$(mktemp) || return 1
  if BAS_BACKUP_KEY_PASSPHRASE_ENC="$BAS_BACKUP_KEY_PASSPHRASE" openssl enc -d -aes-256-cbc -pbkdf2 -iter "$BACKUP_KEY_PBKDF2_ITER"         -pass env:BAS_BACKUP_KEY_PASSPHRASE_ENC -in "$src" -out "$tmp" 2>/dev/null      && cmp -s "$tmp" "$BACKUP_KEY_FILE"; then
    rc=0
  else
    rc=1; _bk_err "recovery copy does not open with this passphrase or does not match the live key"
  fi
  rm -f "$tmp"
  return $rc
}

# backup_key_recovery_confirm: the gate. Passes only when a verified recovery copy matches the live key.
#   Interactive (terminal): asks for the destination and passphrase, exports, verifies, records the marker.
#   Non-interactive: BAS_BACKUP_KEY_RECOVERY_PATH and BAS_BACKUP_KEY_PASSPHRASE do the same. Otherwise refuses.
backup_key_recovery_confirm() {
  local h
  h=$(_bk_key_hash)
  if [[ -n "$h" && -f "$BACKUP_KEY_MARKER" ]] && [[ "$(cat "$BACKUP_KEY_MARKER" 2>/dev/null)" == "$h" ]]; then
    return 0
  fi
  local dest="${BAS_BACKUP_KEY_RECOVERY_PATH:-}"
  if [[ -z "$dest" || -z "${BAS_BACKUP_KEY_PASSPHRASE:-}" ]]; then
    _bk_err "no confirmed recovery copy of the backup key. Run: sudo bash install.sh --export-backup-key <file outside this host's backups>, then retry. Non-interactive runs may set BAS_BACKUP_KEY_RECOVERY_PATH and BAS_BACKUP_KEY_PASSPHRASE."
    return 1
  fi
  backup_key_export "$dest" >/dev/null || return 1
  backup_key_verify_recovery "$dest" || { rm -f "$dest"; return 1; }
  local old_umask
  old_umask=$(umask); umask 077
  printf '%s
' "$h" > "$BACKUP_KEY_MARKER"
  umask "$old_umask"
  echo "Backup key recovery copy verified at ${dest}."
}
