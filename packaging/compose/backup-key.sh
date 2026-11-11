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
# Paths that depend on DATA_DIR are resolved when used, not when this file is sourced (DATA_DIR is set later by the installer).
_bk_legacy() { echo "${BACKUP_KEY_LEGACY:-${DATA_DIR:-}/.backup_key}"; }
_bk_marker() { echo "${BACKUP_KEY_MARKER:-${DATA_DIR:-}/.backup-key-recovery-verified}"; }

_bk_err()  { echo "ERROR: $*" >&2; }
BACKUP_KEY_MIN_PASSPHRASE=16
BACKUP_KEY_PBKDF2_ITER=600000
_bk_note() { echo "NOTICE: $*" >&2; }

# _bk_options TITLE OPTION...: print a numbered list of what the operator can do next.
_bk_options() {
  local title="$1" n=1 o
  shift
  echo "$title" >&2
  for o in "$@"; do echo "  $n. $o" >&2; n=$((n + 1)); done
}

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
  [[ -e "$(_bk_legacy)" ]]
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
  if backup_key_legacy_present && openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$out" -pass "file:$(_bk_legacy)" 2>/dev/null; then
    _bk_note "this archive was made with the legacy co-located backup key ($(_bk_legacy)). Re-create backups so new archives use ${BACKUP_KEY_FILE}."
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
  if [[ -n "$h" && -f "$(_bk_marker)" ]] && [[ "$(cat "$(_bk_marker)" 2>/dev/null)" == "$h" ]]; then
    return 0
  fi
  local dest="${BAS_BACKUP_KEY_RECOVERY_PATH:-}"
  if [[ -z "$dest" || -z "${BAS_BACKUP_KEY_PASSPHRASE:-}" ]]; then
    _bk_err "backups cannot run: there is no confirmed recovery copy of the backup key. Nothing has been changed."
    _bk_options "Your options:"       "Create the recovery copy now: sudo bash install.sh --export-backup-key <file outside this host's backups>. Then run the install or upgrade again."       "Non-interactive: set BAS_BACKUP_KEY_RECOVERY_PATH=<file> and BAS_BACKUP_KEY_PASSPHRASE=<16 characters or more>, then run again."       "Stop here. The recovery copy is required before any backup can be taken."
    return 1
  fi
  backup_key_export "$dest" >/dev/null || return 1
  backup_key_verify_recovery "$dest" || { rm -f "$dest"; return 1; }
  local old_umask
  old_umask=$(umask); umask 077
  printf '%s
' "$h" > "$(_bk_marker)"
  umask "$old_umask"
  echo "Backup key recovery copy verified at ${dest}."
}

# backup_key_import SRC: a clean host installs the key from a recovery copy. Refuses to replace an existing key.
# Writes the same confirmation marker the gate checks, since the copy has just been verified against the key it installs.
backup_key_import() {
  local src="$1" dir tmp h
  [[ -f "$src" ]] || { _bk_err "recovery copy ${src} not found"; return 1; }
  [[ ! -s "$BACKUP_KEY_FILE" ]] || { _bk_err "a backup key already exists at ${BACKUP_KEY_FILE}; it was left unchanged"; return 1; }
  _bk_passphrase || return 1
  dir=$(dirname "$BACKUP_KEY_FILE")
  mkdir -p "$dir" || { _bk_err "cannot create ${dir}"; return 1; }
  local old_umask
  old_umask=$(umask); umask 077
  tmp=$(mktemp "${dir}/.backup-encryption.key.XXXXXX") || { umask "$old_umask"; return 1; }
  umask "$old_umask"
  if ! BAS_BACKUP_KEY_PASSPHRASE_ENC="$BAS_BACKUP_KEY_PASSPHRASE" openssl enc -d -aes-256-cbc -pbkdf2 -iter "$BACKUP_KEY_PBKDF2_ITER"         -pass env:BAS_BACKUP_KEY_PASSPHRASE_ENC -in "$src" -out "$tmp" 2>/dev/null; then
    rm -f "$tmp"; _bk_err "import failed: wrong passphrase or a damaged recovery copy"; return 1
  fi
  if [[ ! -s "$tmp" ]]; then rm -f "$tmp"; _bk_err "the recovery copy holds an empty key"; return 1; fi
  chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }
  if [[ "$(id -u)" == "0" ]]; then chown root:root "$tmp" || { rm -f "$tmp"; return 1; }; fi
  mv -f "$tmp" "$BACKUP_KEY_FILE" || { rm -f "$tmp"; _bk_err "could not place the backup key"; return 1; }
  h=$(_bk_key_hash)
  if [[ -n "$h" && -d "$(dirname "$(_bk_marker)")" ]]; then
    old_umask=$(umask); umask 077
    printf '%s
' "$h" > "$(_bk_marker)"
    umask "$old_umask"
  fi
  echo "Backup key restored to ${BACKUP_KEY_FILE} from the recovery copy."
}

# backup_key_prompt_inputs: on a terminal, ask for the recovery path and passphrase unless they are already set.
backup_key_prompt_inputs() {
  if [[ -t 0 ]]; then
    if [[ -z "${BAS_BACKUP_KEY_RECOVERY_PATH:-}" ]]; then
      read -r -p "  Recovery copy path (must be outside ${DATA_DIR}): " BAS_BACKUP_KEY_RECOVERY_PATH
    fi
    if [[ -z "${BAS_BACKUP_KEY_PASSPHRASE:-}" ]]; then
      local p1 p2
      read -r -s -p "  Recovery passphrase (16 characters or more): " p1; echo
      read -r -s -p "  Repeat passphrase: " p2; echo
      [[ "$p1" == "$p2" ]] || { _bk_err "the passphrases differ"; return 1; }
      BAS_BACKUP_KEY_PASSPHRASE="$p1"
    fi
    export BAS_BACKUP_KEY_RECOVERY_PATH BAS_BACKUP_KEY_PASSPHRASE
  fi
  return 0
}

# backup_key_gate: backups do not run until a verified recovery copy of the backup key exists (backup-key.sh).
backup_key_gate() {
  if backup_key_recovery_confirm 2>/dev/null; then
    return 0
  fi
  if [[ -t 0 && -z "${BAS_BACKUP_KEY_PASSPHRASE:-}" ]]; then
    echo "" >&2
    echo "A verified recovery copy of the backup encryption key is required before any backup can run." >&2
    echo "Without it, backups made with this key cannot be restored after the key is lost." >&2
    _bk_options "Your options:"       "Enter a path outside this host's backups and a passphrase now (you will be asked for both)."       "Stop now (Ctrl-C). Create the copy with: sudo bash install.sh --export-backup-key <file>, then start this again."
    echo "" >&2
  fi
  backup_key_prompt_inputs || return 1
  backup_key_recovery_confirm
}
