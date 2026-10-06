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

# upgrade_record_latest <data_dir> -> newest backups/upgrade-* dir; fails if none.
# Ignores every other backup (scheduled archives, pre-H1 <ts>/ dirs).
upgrade_record_latest() {
  local latest
  latest=$(find "${1}/backups" -maxdepth 1 -type d -name 'upgrade-*' 2>/dev/null | LC_ALL=C sort | tail -1)
  [[ -n "$latest" && -f "${latest}/UPGRADE.json" ]] || return 1
  echo "$latest"
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

# db_restore <dir>: verify the hash, then replace bas_platform with the snapshot.
db_restore() {
  local dir="$1" in="${1}/db.dump.enc" want got
  want=$(upgrade_record_get "$dir" dump_sha256)
  [[ -n "$want" && -f "$in" ]] || { echo "db_restore: ${dir} has no recorded snapshot" >&2; return 1; }
  got=$(sha256sum "$in" | awk '{print $1}')
  [[ "$got" == "$want" ]] || { echo "db_restore: snapshot hash mismatch (${got} != ${want}) -- refusing" >&2; return 1; }
  # Decrypt fully before touching the database: a bad key must not leave it dropped.
  local tmp
  tmp=$(mktemp) || return 1
  openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$tmp" -pass "$(_ur_key)" \
    || { rm -f "$tmp"; echo "db_restore: decryption failed (wrong .backup_key?)" >&2; return 1; }
  docker exec "$PG_CONTAINER" dropdb -U bas_user --force bas_platform \
    && docker exec "$PG_CONTAINER" createdb -U bas_user bas_platform \
    && docker exec -i "$PG_CONTAINER" pg_restore -U bas_user -d bas_platform --no-owner --exit-on-error < "$tmp"
  local rc=$?
  rm -f "$tmp"
  return $rc
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
  local user pw db
  user=$(_env_get POSTGRES_USER); pw=$(_env_get POSTGRES_PASSWORD); db=$(_env_get POSTGRES_DB)
  [[ -n "$pw" ]] || { echo "run_migrate: POSTGRES_PASSWORD missing from ${DATA_DIR}/.env" >&2; return 1; }
  (cd "${DATA_DIR}" && docker compose -p "${COMPOSE_PROJECT}" run --rm --no-deps -T \
    -e DATABASE_ADMIN_URL="postgres://${user:-bas_user}:$(_urlencode "$pw")@postgres:5432/${db:-bas_platform}?sslmode=prefer" \
    orchestrator migrate "$1")
}
