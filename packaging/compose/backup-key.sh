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
