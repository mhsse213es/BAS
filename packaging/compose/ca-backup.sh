#!/usr/bin/env bash
# packaging/compose/ca-backup.sh
#
# Keeps the deployment CA private key out of backups in plaintext (P0.2).
#
# The live key stays where the orchestrator needs it (DATA_DIR/pki/ca-key.pem). Any copy that leaves the live directory
# (the upgrade backup, and the config archive written by the backup engine) carries the key wrapped with the interim
# database encryption key, db-encryption.key. That key lives in /etc/audspect/secrets, outside DATA_DIR, so a backup of
# DATA_DIR alone cannot be unwrapped. Restoring on a new host needs the database key too (export-db-key / import-db-key).
#
# Fail closed: if the wrap key cannot be used, staging fails and no plaintext key or partial copy is written.
#
# This file is sourced by install.sh. Functions return non-zero on failure and print a reason to stderr.

CA_WRAP_KEY_FILE="${CA_WRAP_KEY_FILE:-${DB_KEY_FILE:-/etc/audspect/secrets/db-encryption.key}}"
CA_KEY_NAME="ca-key.pem"
CA_WRAPPED_NAME="ca-key.pem.wrapped"

_cabk_err() { echo "ERROR: $*" >&2; }

# _cabk_wrap_ok: the wrap key is present, readable, and non-empty.
_cabk_wrap_ok() {
  [[ -f "$CA_WRAP_KEY_FILE" && -r "$CA_WRAP_KEY_FILE" && -s "$CA_WRAP_KEY_FILE" ]] || {
    _cabk_err "CA backup wrap key ${CA_WRAP_KEY_FILE} is missing or unreadable; the CA key cannot be backed up safely. Restore the database encryption key first."
    return 1
  }
}

# ca_backup_stage SRC_PKI_DIR DEST_DIR
# Copies everything in SRC except the plaintext key into DEST, and writes the wrapped key. The plaintext key is never
# copied, not even briefly.
ca_backup_stage() {
  local src="$1" dest="$2"
  [[ -d "$src" ]] || { _cabk_err "pki directory ${src} does not exist"; return 1; }
  if [[ -f "${src}/${CA_KEY_NAME}" ]]; then
    _cabk_wrap_ok || return 1
  fi

  local work
  work=$(mktemp -d) || { _cabk_err "cannot create a work directory"; return 1; }
  # openssl on Windows cannot resolve Git Bash /tmp paths; give it the native form. No effect on Linux.
  local nwork="$work"
  if command -v cygpath >/dev/null 2>&1; then nwork="$(cygpath -m "$work")"; fi
  # Stage in a private directory first. Only a complete result is moved into DEST.
  local entry
  while IFS= read -r -d '' entry; do
    [[ "$(basename "$entry")" == "$CA_KEY_NAME" ]] && continue
    cp -a "$entry" "$work/" || { _cabk_err "copy failed: ${entry}"; rm -rf "$work"; return 1; }
  done < <(find "$src" -mindepth 1 -maxdepth 1 -print0)

  if [[ -f "${src}/${CA_KEY_NAME}" ]]; then
    local old_umask
    old_umask=$(umask); umask 077
    if ! openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
          -in "${src}/${CA_KEY_NAME}" -out "${nwork}/${CA_WRAPPED_NAME}" -pass "file:${CA_WRAP_KEY_FILE}" 2>/dev/null; then
      umask "$old_umask"; _cabk_err "could not wrap the CA key"; rm -rf "$work"; return 1
    fi
    umask "$old_umask"
    # Prove the wrap round-trips to a valid private key before it is trusted as the only copy.
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "${nwork}/${CA_WRAPPED_NAME}" -pass "file:${CA_WRAP_KEY_FILE}" 2>/dev/null \
          | openssl pkey -noout >/dev/null 2>&1; then
      _cabk_err "wrapped CA key failed its round-trip check"; rm -rf "$work"; return 1
    fi
    chmod 600 "${work}/${CA_WRAPPED_NAME}"
  fi

  mkdir -p "$dest" || { _cabk_err "cannot create ${dest}"; rm -rf "$work"; return 1; }
  cp -a "$work"/. "$dest"/ || { _cabk_err "could not write ${dest}"; rm -rf "$work"; return 1; }
  rm -rf "$work"
  return 0
}

# ca_backup_unwrap PKI_DIR
# If PKI_DIR holds a wrapped key and no plaintext key, restores the plaintext key with mode 0600. Never overwrites a key
# that is already present. Refuses (and writes nothing) if the wrap key does not decrypt it.
ca_backup_unwrap() {
  local pki="$1"
  [[ -e "${pki}/${CA_KEY_NAME}" ]] && return 0
  [[ -f "${pki}/${CA_WRAPPED_NAME}" ]] || return 0
  _cabk_wrap_ok || return 1

  local tmp
  tmp=$(mktemp "${pki}/.ca-key.XXXXXX") || { _cabk_err "cannot create a temporary file in ${pki}"; return 1; }
  if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "${pki}/${CA_WRAPPED_NAME}" -out "$tmp" -pass "file:${CA_WRAP_KEY_FILE}" 2>/dev/null \
        || ! openssl pkey -in "$tmp" -noout >/dev/null 2>&1; then
    rm -f "$tmp"
    _cabk_err "the wrapped CA key does not decrypt with the current database encryption key; nothing was restored"
    return 1
  fi
  chmod 600 "$tmp"
  mv -f "$tmp" "${pki}/${CA_KEY_NAME}" || { rm -f "$tmp"; _cabk_err "could not place the restored CA key"; return 1; }
  return 0
}

# ca_backup_plaintext_report BACKUP_ROOT
# Prints each backup directory under BACKUP_ROOT that still holds a plaintext CA key. Read-only.
ca_backup_plaintext_report() {
  local root="$1"
  [[ -d "$root" ]] || return 0
  find "$root" -path "*/pki/${CA_KEY_NAME}" -type f -print 2>/dev/null | sed 's#/pki/'"${CA_KEY_NAME}"'$##' | sort
}
