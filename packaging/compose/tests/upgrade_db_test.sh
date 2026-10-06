#!/usr/bin/env bash
# H1 Task 9: upgrade record, encrypted DB snapshot and exact restore.
# Needs Docker. Uses its own Postgres container (never audspect-postgres).
#   bash packaging/compose/tests/upgrade_db_test.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_CONTAINER="h1-upgrade-db-test-$$"
DATA_DIR="$(mktemp -d)"
export PG_CONTAINER DATA_DIR
FAILS=0

cleanup() { docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true; rm -rf "$DATA_DIR"; }
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
psql_c() { docker exec "$PG_CONTAINER" psql -U bas_user -d bas_platform -tAc "$1"; }

# shellcheck source=../lib/upgrade-db.sh
source "${HERE}/../lib/upgrade-db.sh"

openssl rand -base64 48 > "${DATA_DIR}/.backup_key"
docker run -d --name "$PG_CONTAINER" -e POSTGRES_USER=bas_user -e POSTGRES_PASSWORD=t \
  -e POSTGRES_DB=bas_platform postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG_CONTAINER" pg_isready -U bas_user -d bas_platform >/dev/null 2>&1 \
    && psql_c "SELECT 1" >/dev/null 2>&1 && break
  sleep 1
done

psql_c "CREATE TABLE t (id int PRIMARY KEY, v text); INSERT INTO t SELECT g, 'row' || g FROM generate_series(1, 50) g;" >/dev/null
before=$(psql_c "SELECT md5(string_agg(t::text, ',' ORDER BY id)) FROM t")

# 1. record + snapshot
rec=$(upgrade_record_create "$DATA_DIR" 1.9.0 1.10.0)
[[ "$(basename "$rec")" == upgrade-*-1.9.0-to-1.10.0 ]] && pass "record name $(basename "$rec")" || fail "record name: $rec"
grep -q '"state": "started"' "${rec}/UPGRADE.json" && pass "state started" || fail "state not started"
if db_snapshot "$rec"; then pass "snapshot taken"; else fail "snapshot failed"; fi
[[ -s "${rec}/db.dump.enc" ]] && pass "db.dump.enc written" || fail "no db.dump.enc"
sha=$(sha256sum "${rec}/db.dump.enc" | awk '{print $1}')
grep -q "\"dump_sha256\": \"${sha}\"" "${rec}/UPGRADE.json" && pass "dump hash recorded" || fail "dump hash not recorded"
upgrade_record_set "$rec" state migrated
grep -q '"state": "migrated"' "${rec}/UPGRADE.json" && pass "state set" || fail "state not updated"

# 2. mutate, restore exactly (H1-T10)
psql_c "INSERT INTO t VALUES (999, 'after'); ALTER TABLE t ADD COLUMN extra int;" >/dev/null
if db_restore "$rec"; then pass "restore ran"; else fail "restore failed"; fi
after=$(psql_c "SELECT md5(string_agg(t::text, ',' ORDER BY id)) FROM t")
[[ "$after" == "$before" ]] && pass "rows restored exactly" || fail "rows differ after restore"
[[ "$(psql_c "SELECT count(*) FROM information_schema.columns WHERE table_name = 't' AND column_name = 'extra'")" == 0 ]] \
  && pass "added column gone" || fail "added column survived restore"

# 3. latest upgrade record ignores newer scheduled/legacy backups (Review Focus 4)
sleep 1
mkdir -p "${DATA_DIR}/backups/29991231-235959"
touch "${DATA_DIR}/backups/audspect-backup-29991231-235959.tar.enc"
older=$(upgrade_record_create "$DATA_DIR" 1.8.0 1.9.0)
mv "$older" "${DATA_DIR}/backups/upgrade-20000101T000000Z-1.8.0-to-1.9.0"
[[ "$(upgrade_record_latest "$DATA_DIR")" == "$rec" ]] && pass "latest is the upgrade record" \
  || fail "latest = $(upgrade_record_latest "$DATA_DIR"), want $rec"
empty="$(mktemp -d)"
if upgrade_record_latest "$empty" >/dev/null 2>&1; then fail "latest succeeded with no records"; else pass "no record -> error"; fi
rm -rf "$empty"

# 4. tampered snapshot is refused, database untouched
psql_c "INSERT INTO t VALUES (1000, 'kept')" >/dev/null
printf 'x' >> "${rec}/db.dump.enc"
if db_restore "$rec" 2>/dev/null; then fail "tampered restore accepted"; else pass "tampered restore refused"; fi
[[ "$(psql_c "SELECT count(*) FROM t WHERE id = 1000")" == 1 ]] && pass "database untouched" || fail "database changed by refused restore"

# 5. admin password is URL-encoded byte-wise for the migrate DSN
[[ "$(_urlencode 'p@ss/w:rd%+ é')" == 'p%40ss%2Fw%3Ard%25%2B%20%C3%A9' ]] && pass "password URL-encoded" \
  || fail "_urlencode = $(_urlencode 'p@ss/w:rd%+ é')"

echo "---"
if [[ $FAILS -eq 0 ]]; then echo "ALL PASS"; else echo "${FAILS} FAILED"; exit 1; fi
