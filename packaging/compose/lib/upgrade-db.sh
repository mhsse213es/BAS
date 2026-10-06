#!/usr/bin/env bash
# Upgrade record + database snapshot/restore for install.sh (H1 spec 5).
# Sourced, never executed. Every function takes explicit arguments and
# returns non-zero on failure; the caller decides whether that is fatal.
#
# An upgrade record is DATA_DIR/backups/upgrade-<UTC ts>-<from>-to-<to>/:
#   UPGRADE.json   id, from, to, state, started_at, updated_at, dump_sha256
#   db.dump.enc    pg_dump -Fc, encrypted with DATA_DIR/.backup_key
# Rollback restores exactly this snapshot -- never a scheduled backup.

PG_CONTAINER="${PG_CONTAINER:-audspect-postgres}"

_ur_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# upgrade_record_create <data_dir> <from> <to> -> prints the record dir
upgrade_record_create() {
  local data_dir="$1" from="$2" to="$3" ts dir
  ts=$(date -u '+%Y%m%dT%H%M%SZ')
  dir="${data_dir}/backups/upgrade-${ts}-${from}-to-${to}"
  mkdir -p "$dir" || return 1
  chmod 700 "$dir"
  cat > "${dir}/UPGRADE.json" <<EOF
{
  "id": "$(basename "$dir")",
  "from": "${from}",
  "to": "${to}",
  "state": "started",
  "started_at": "$(_ur_now)",
  "updated_at": "$(_ur_now)",
  "dump_sha256": ""
}
EOF
  echo "$dir"
}

# upgrade_record_set <dir> <key> <value>; keys: state, dump_sha256
upgrade_record_set() {
  local dir="$1" key="$2" value="$3" f="${1}/UPGRADE.json"
  case "$key" in state|dump_sha256) ;; *) echo "upgrade_record_set: unknown key ${key}" >&2; return 1 ;; esac
  [[ "$value" =~ ^[A-Za-z0-9._-]*$ ]] || { echo "upgrade_record_set: bad value for ${key}" >&2; return 1; }
  [[ -f "$f" ]] || { echo "upgrade_record_set: no ${f}" >&2; return 1; }
  sed -i -e "s|^  \"${key}\": \"[^\"]*\"|  \"${key}\": \"${value}\"|" \
         -e "s|^  \"updated_at\": \"[^\"]*\"|  \"updated_at\": \"$(_ur_now)\"|" "$f"
}

# upgrade_record_get <dir> <key> -> prints the value
upgrade_record_get() {
  sed -n "s|^  \"${2}\": \"\\([^\"]*\\)\".*|\\1|p" "${1}/UPGRADE.json"
}

# upgrade_record_latest <data_dir> -> newest restorable backups/upgrade-* dir;
# fails if none. Restorable: a snapshot hash is recorded and the record is
# not aborted or already rolled back. Ignores every other backup (scheduled
# archives, pre-H1 <ts>/ dirs).
upgrade_record_latest() {
  local d state
  while IFS= read -r d; do
    [[ -f "${d}/UPGRADE.json" ]] || continue
    [[ -n "$(upgrade_record_get "$d" dump_sha256)" ]] || continue
    state=$(upgrade_record_get "$d" state)
    [[ "$state" == aborted || "$state" == rolled-back ]] && continue
    echo "$d"
    return 0
  done < <(find "${1}/backups" -maxdepth 1 -type d -name 'upgrade-*' 2>/dev/null | LC_ALL=C sort -r)
  return 1
}

# backup_key_ensure <data_dir>: creates a 0600 .backup_key if missing and
# prints "created"; an existing key is never touched.
backup_key_ensure() {
  local key="${1}/.backup_key"
  [[ -f "$key" ]] && return 0
  (umask 077 && openssl rand -base64 48 > "$key") || return 1
  chmod 600 "$key"
  echo created
}

_ur_key() { echo "file:${DATA_DIR:?DATA_DIR must be set}/.backup_key"; }

# db_snapshot <dir>: encrypted pg_dump, proven readable, hash recorded.
db_snapshot() {
  local dir="$1" out="${1}/db.dump.enc" sha
  docker exec "$PG_CONTAINER" pg_dump -U bas_user -Fc bas_platform \
    | openssl enc -aes-256-cbc -pbkdf2 -salt -out "$out" -pass "$(_ur_key)" || return 1
  [[ -s "$out" ]] || return 1
  chmod 600 "$out"
  # The snapshot is only worth having if it decrypts and pg_restore can read it.
  openssl enc -d -aes-256-cbc -pbkdf2 -in "$out" -pass "$(_ur_key)" \
    | docker exec -i "$PG_CONTAINER" pg_restore --list >/dev/null || return 1
  sha=$(sha256sum "$out" | awk '{print $1}')
  upgrade_record_set "$dir" dump_sha256 "$sha"
}

# db_restore_prepare <dir>: verify the hash and decrypt the snapshot to
# <dir>/db.dump (0600, inside the 0700 record dir), proven readable by
# pg_restore. Touches neither the database nor the stack, so --rollback runs
# it before stopping anything. Leaves no plaintext on failure.
db_restore_prepare() {
  local dir="$1" in="${1}/db.dump.enc" plain="${1}/db.dump" want got
  rm -f "$plain"
  want=$(upgrade_record_get "$dir" dump_sha256)
  [[ -n "$want" && -f "$in" ]] || { echo "db_restore: ${dir} has no recorded snapshot" >&2; return 1; }
  got=$(sha256sum "$in" | awk '{print $1}')
  [[ "$got" == "$want" ]] || { echo "db_restore: snapshot hash mismatch (${got} != ${want}) -- refusing" >&2; return 1; }
  (umask 077 && openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$plain" -pass "$(_ur_key)") \
    || { rm -f "$plain"; echo "db_restore: decryption failed (wrong .backup_key?)" >&2; return 1; }
  docker exec -i "$PG_CONTAINER" pg_restore --list < "$plain" >/dev/null \
    || { rm -f "$plain"; echo "db_restore: decrypted snapshot is not readable by pg_restore" >&2; return 1; }
}

# db_restore_apply <dir>: replace bas_platform with <dir>/db.dump, then
# delete the plaintext. Returns 1 if it failed before the database was
# dropped (database untouched), 3 if it failed after (partially restored).
db_restore_apply() {
  local plain="${1}/db.dump" rc=0
  [[ -f "$plain" ]] || { echo "db_restore: ${plain} missing -- run db_restore_prepare first" >&2; return 1; }
  if ! docker exec "$PG_CONTAINER" dropdb -U bas_user --force bas_platform; then
    rm -f "$plain"
    return 1
  fi
  docker exec "$PG_CONTAINER" createdb -U bas_user bas_platform \
    && docker exec -i "$PG_CONTAINER" pg_restore -U bas_user -d bas_platform --no-owner --exit-on-error < "$plain" \
    || rc=3
  rm -f "$plain"
  return $rc
}

# db_restore <dir>: prepare then apply.
db_restore() {
  db_restore_prepare "$1" && db_restore_apply "$1"
}

# _env_get <key>: value from DATA_DIR/.env (written by install.sh, unquoted).
_env_get() { grep -m1 "^${1}=" "${DATA_DIR}/.env" 2>/dev/null | cut -d= -f2-; }

# _urlencode <s>: percent-encode everything but unreserved characters.
_urlencode() {
  local out="" b
  # Byte-wise via od, so multi-byte UTF-8 encodes per RFC 3986 in any locale.
  for b in $(printf '%s' "$1" | od -An -tx1 -v); do
    # shellcheck disable=SC2059  # printf \x escape from a validated hex byte
    case "$b" in
      3[0-9]|4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a]|2d|2e|5f|7e) out+=$(printf "\\x${b}") ;;
      *) out+="%${b^^}" ;;
    esac
  done
  echo "$out"
}

# run_migrate <subcommand>: one-off orchestrator container (Postgres must
# already be running) with the schema-owner URL passed only to this run;
# the long-running server never receives it.
run_migrate() {
  local user pw db url
  user=$(_env_get POSTGRES_USER); pw=$(_env_get POSTGRES_PASSWORD); db=$(_env_get POSTGRES_DB)
  [[ -n "$pw" ]] || { echo "run_migrate: POSTGRES_PASSWORD missing from ${DATA_DIR}/.env" >&2; return 1; }
  url="postgres://${user:-bas_user}:$(_urlencode "$pw")@postgres:5432/${db:-bas_platform}?sslmode=prefer"
  # Passed by name from docker's environment: a value on the command line
  # would show in host ps.
  (cd "${DATA_DIR}" && DATABASE_ADMIN_URL="$url" \
    docker compose -p "${COMPOSE_PROJECT}" run --rm --no-deps -T -e DATABASE_ADMIN_URL orchestrator migrate "$1")
}
