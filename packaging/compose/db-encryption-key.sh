#!/usr/bin/env bash
# packaging/compose/db-encryption-key.sh
#
# Provisioning for the interim database encryption key (orchestrator/internal/secretstore). The key encrypts credential
# values stored in PostgreSQL. It lives outside the data directory, so database dumps and the automatic upgrade backup
# (which copies DATA_DIR) do not capture it.
#
# Layout on a Linux host:
#   /etc/audspect/secrets/                 root:<service-gid>  0750
#   /etc/audspect/secrets/db-encryption.key  root:<service-gid>  0640   (base64 of 32 random bytes, one line)
#
# The orchestrator container runs as UID/GID 65532 (distroless nonroot). <service-gid> is that group, so the container
# can read the key and nothing else can. Ownership by root keeps the key out of the service account's control.
#
# This file is sourced by install.sh. Every function returns non-zero on failure and prints a reason. No function prints the
# key or a passphrase.

DB_KEY_DIR="${DB_KEY_DIR:-/etc/audspect/secrets}"
DB_KEY_FILE="${DB_KEY_DIR}/db-encryption.key"
# Expected owner and group. Production values are root and the service group. Tests override them to their own IDs so the
# checks run without root; the defaults are the only values the installer uses.
DB_KEY_UID="${DB_KEY_UID:-0}"
DB_KEY_GID="${DB_KEY_GID:-65532}"
DB_KEY_PBKDF2_ITER=600000

_dbkey_err() { echo "ERROR: $*" >&2; }
_dbkey_info() { echo "$*"; }

# db_key_content_ok FILE: the file holds one line of base64 that decodes to exactly 32 bytes.
db_key_content_ok() {
  local file="$1" n lines
  lines=$(wc -l < "$file" 2>/dev/null | tr -d ' ')
  [[ "${lines:-0}" -le 1 ]] || return 1
  n=$(tr -d '\n' < "$file" | base64 -d 2>/dev/null | wc -c | tr -d ' ') || return 1
  [[ "$n" == "32" ]]
}

# db_key_perms_ok FILE: owner, group and mode match the expected layout. Mode may be 0600, 0400, 0440 or 0640: the group may
# read and nothing else has access.
db_key_perms_ok() {
  local file="$1" uid gid mode m
  [[ -f "$file" && ! -L "$file" ]] || return 1
  uid=$(stat -c %u "$file") || return 1
  gid=$(stat -c %g "$file") || return 1
  mode=$(stat -c %a "$file") || return 1
  m=$((8#$mode))
  [[ "$uid" == "$DB_KEY_UID" && "$gid" == "$DB_KEY_GID" ]] || return 1
  (( (m & 037) == 0 ))
}

# db_key_set_perms FILE: apply the expected owner, group and mode. Used only on a file whose content is already verified.
db_key_set_perms() {
  local file="$1"
  chown "${DB_KEY_UID}:${DB_KEY_GID}" "$file" && chmod 0640 "$file"
}

# db_key_ensure_dir: the key directory exists with the expected owner and mode.
db_key_ensure_dir() {
  mkdir -p "$DB_KEY_DIR" || { _dbkey_err "cannot create ${DB_KEY_DIR}"; return 1; }
  chown "${DB_KEY_UID}:${DB_KEY_GID}" "$DB_KEY_DIR" && chmod 0750 "$DB_KEY_DIR" \
    || { _dbkey_err "cannot set ownership of ${DB_KEY_DIR}"; return 1; }
}

# db_key_generate: write a new random key. Refuses to overwrite an existing file.
db_key_generate() {
  [[ ! -e "$DB_KEY_FILE" ]] || { _dbkey_err "refusing to overwrite an existing key"; return 1; }
  local tmp
  tmp="$(umask 077 && mktemp "${DB_KEY_DIR}/.db-encryption.key.XXXXXX")" || return 1
  (umask 077 && head -c 32 /dev/urandom | base64 -w0 > "$tmp") || { rm -f "$tmp"; return 1; }
  db_key_set_perms "$tmp" || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$DB_KEY_FILE" || { rm -f "$tmp"; return 1; }
}

# db_key_provision MODE: MODE is "fresh" (a new install) or "upgrade" (an existing install).
#   fresh:   reuse a verified key, repair its owner and mode if they drifted, or generate one when none exists.
#   upgrade: reuse a verified key. A missing key is an error: generating one would make every stored credential unreadable.
db_key_provision() {
  local mode="$1"
  db_key_ensure_dir || return 1
  if [[ -e "$DB_KEY_FILE" ]]; then
    if ! db_key_content_ok "$DB_KEY_FILE"; then
      _dbkey_err "the encryption key at ${DB_KEY_FILE} is not valid (expected base64 of 32 bytes). It was left unchanged."
      return 1
    fi
    if ! db_key_perms_ok "$DB_KEY_FILE"; then
      db_key_set_perms "$DB_KEY_FILE" || { _dbkey_err "cannot set ownership of ${DB_KEY_FILE}"; return 1; }
      db_key_perms_ok "$DB_KEY_FILE" || { _dbkey_err "${DB_KEY_FILE} does not have the expected owner and mode"; return 1; }
      _dbkey_info "Encryption key ownership and mode repaired."
    fi
    _dbkey_info "Encryption key present and verified."
    return 0
  fi
  if [[ "$mode" == "upgrade" ]]; then
    _dbkey_err "the encryption key is missing at ${DB_KEY_FILE}."
    _dbkey_err "An upgrade does not generate a key: stored credentials would become unreadable. Restore it from the recovery copy with: install.sh --import-db-key <recovery file>"
    return 1
  fi
  db_key_generate || { _dbkey_err "could not generate the encryption key at ${DB_KEY_FILE}"; return 1; }
  db_key_content_ok "$DB_KEY_FILE" && db_key_perms_ok "$DB_KEY_FILE" \
    || { _dbkey_err "the generated key did not verify"; return 1; }
  _dbkey_info "Encryption key generated at ${DB_KEY_FILE} (root:${DB_KEY_GID}, 0640)."
}

# _dbkey_passphrase CONFIRM: read the recovery passphrase. CONFIRM=yes asks twice (export); CONFIRM=no asks once (import).
# BAS_DB_KEY_PASSPHRASE is for automation and skips the prompt; the default is interactive so the passphrase is not in the
# environment or the shell history.
_dbkey_passphrase() {
  local confirm="$1" p
  if [[ -n "${BAS_DB_KEY_PASSPHRASE:-}" ]]; then
    p="$BAS_DB_KEY_PASSPHRASE"
  else
    read -rsp "Recovery passphrase (at least 12 characters): " p; echo >&2
    if [[ "$confirm" == "yes" ]]; then
      local again
      read -rsp "Repeat the passphrase: " again; echo >&2
      [[ "$p" == "$again" ]] || { _dbkey_err "passphrases do not match"; return 1; }
    fi
  fi
  [[ ${#p} -ge 12 ]] || { _dbkey_err "passphrase must be at least 12 characters"; return 1; }
  printf '%s' "$p"
}

# db_key_export DEST: write an encrypted recovery copy of the key. DEST must not exist and must not be inside DATA_DIR.
db_key_export() {
  local dest="$1" pass
  command -v openssl >/dev/null 2>&1 || { _dbkey_err "openssl is required"; return 1; }
  [[ -n "$dest" ]] || { _dbkey_err "usage: install.sh --export-db-key <recovery file>"; return 1; }
  db_key_content_ok "$DB_KEY_FILE" && db_key_perms_ok "$DB_KEY_FILE" \
    || { _dbkey_err "no verified encryption key at ${DB_KEY_FILE}"; return 1; }
  [[ ! -e "$dest" ]] || { _dbkey_err "refusing to overwrite ${dest}"; return 1; }
  pass="$(_dbkey_passphrase yes)" || return 1
  (umask 077 && BAS_KEY_PASS="$pass" openssl enc -aes-256-cbc -pbkdf2 -iter "$DB_KEY_PBKDF2_ITER" -salt \
      -pass env:BAS_KEY_PASS -in "$DB_KEY_FILE" -out "$dest") || { rm -f "$dest"; _dbkey_err "export failed"; return 1; }
  unset BAS_KEY_PASS pass
  chmod 0600 "$dest"
  _dbkey_info "Recovery copy written to ${dest}. Store it encrypted and off this host, separately from database backups."
}

# db_key_import SRC: restore the key from an encrypted recovery copy. Refuses to replace an existing key.
db_key_import() {
  local src="$1" pass tmp
  command -v openssl >/dev/null 2>&1 || { _dbkey_err "openssl is required"; return 1; }
  [[ -f "$src" ]] || { _dbkey_err "usage: install.sh --import-db-key <recovery file>"; return 1; }
  [[ ! -e "$DB_KEY_FILE" ]] || { _dbkey_err "a key already exists at ${DB_KEY_FILE}; it was left unchanged"; return 1; }
  db_key_ensure_dir || return 1
  pass="$(_dbkey_passphrase no)" || return 1
  tmp="$(mktemp "${DB_KEY_DIR}/.db-encryption.key.XXXXXX")" || return 1
  if ! (umask 077 && BAS_KEY_PASS="$pass" openssl enc -d -aes-256-cbc -pbkdf2 -iter "$DB_KEY_PBKDF2_ITER" \
        -pass env:BAS_KEY_PASS -in "$src" -out "$tmp") 2>/dev/null; then
    rm -f "$tmp"; unset BAS_KEY_PASS pass
    _dbkey_err "import failed: wrong passphrase or a damaged recovery copy"; return 1
  fi
  unset BAS_KEY_PASS pass
  if ! db_key_content_ok "$tmp"; then
    rm -f "$tmp"; _dbkey_err "the recovery copy does not contain a valid key"; return 1
  fi
  db_key_set_perms "$tmp" && mv -f "$tmp" "$DB_KEY_FILE" || { rm -f "$tmp"; _dbkey_err "could not install the key"; return 1; }
  db_key_perms_ok "$DB_KEY_FILE" || { _dbkey_err "imported key does not have the expected owner and mode"; return 1; }
  _dbkey_info "Encryption key restored to ${DB_KEY_FILE}. Run the restore verification before relying on it."
}
