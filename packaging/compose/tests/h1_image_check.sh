#!/usr/bin/env bash
# H1 image check: `orchestrator migrate` inside the real garbled distroless
# release image (orchestrator/Dockerfile), against throwaway Postgres.
# Needs Docker and ~6 GB free RAM for the garble build (too much for the
# Windows build host's 4 GB Docker VM). Run from the repo root:
#   bash packaging/compose/tests/h1_image_check.sh            # build + check
#   bash packaging/compose/tests/h1_image_check.sh <image>    # check an image
# Uses its own network/container names (h1chk-*); publishes no ports.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FIXTURE="${ROOT}/orchestrator/internal/db/migrate/testdata/v1.7.0.sql"
IMG="${1:-}"
if [[ -z "$IMG" ]]; then
  IMG="bas-orchestrator:h1-check"
  echo "--- building ${IMG} from ${ROOT} at $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"
  DOCKER_BUILDKIT=1 docker build -f "${ROOT}/orchestrator/Dockerfile" -t "$IMG" "$ROOT" || { echo "FAIL: image build"; exit 1; }
fi
NET=h1chk-net; PG=h1chk-pg
FAILS=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() { docker rm -f "$PG" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; }
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=bas_user -e POSTGRES_PASSWORD=adminpw \
  -e POSTGRES_DB=bas_platform postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG" pg_isready -U bas_user -d bas_platform >/dev/null 2>&1 \
    && docker exec "$PG" psql -U bas_user -d bas_platform -tAc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
psql_c() { docker exec "$PG" psql -U bas_user -d "$1" -tAc "$2"; }

# migrate loads the full server config, which (like compose) needs
# DATABASE_URL and a strong JWT_SECRET; throwaway values per run.
JWT_SECRET="$(openssl rand -hex 32)"
# mig <db> <subcommand>: prints output; returns the container's exit code.
mig() {
  docker run --rm --network "$NET" \
    -e DATABASE_ADMIN_URL="postgres://bas_user:adminpw@${PG}:5432/$1?sslmode=disable" \
    -e DATABASE_URL="postgres://bas_app:apppw-1@${PG}:5432/$1?sslmode=disable" \
    -e JWT_SECRET="$JWT_SECRET" -e BAS_APP_DB_PASSWORD=apppw-1 "$IMG" migrate "$2"
}

echo "--- image user: $(docker inspect -f '{{.Config.User}}' "$IMG")"

# 1. fresh database
psql_c bas_platform 'SELECT 1' >/dev/null
out=$(mig bas_platform status); rc=$?
echo "$out" | sed 's/^/    /'
[[ $rc == 2 ]] && pass "status on empty DB -> exit 2 (pending)" || fail "status rc ${rc}, want 2"
out=$(mig bas_platform up); rc=$?
echo "$out" | sed 's/^/    /'
[[ $rc == 0 ]] && pass "up on fresh DB" || fail "up rc ${rc}"
[[ "$(psql_c bas_platform 'SELECT version::text || dirty::text FROM schema_migrations')" == 3false ]] \
  && pass "schema_migrations = 3, clean" || fail "schema_migrations: $(psql_c bas_platform 'SELECT * FROM schema_migrations')"
n=$(psql_c bas_platform "SELECT count(*) FROM pg_tables WHERE schemaname='public'")
echo "    public tables: $n"
[[ "$n" -gt 100 ]] && pass "embedded baseline applied (${n} tables)" || fail "only ${n} tables"
[[ "$(psql_c bas_platform 'SELECT max(version) FROM reference_data_version')" -ge 1 ]] \
  && pass "embedded seed applied" || fail "no seed version"
[[ "$(psql_c bas_platform "SELECT count(*) FROM payload_families")" -gt 0 ]] && pass "seed rows present" || fail "no seed rows"
out=$(mig bas_platform up); rc=$?
echo "$out" | sed 's/^/    /'
[[ $rc == 0 ]] && echo "$out" | grep -q '3→3' && pass "second up is a no-op" || fail "second up rc ${rc}"
out=$(mig bas_platform status); rc=$?
echo "$out" | sed 's/^/    /'
[[ $rc == 0 ]] && pass "status -> exit 0 (up to date)" || fail "status rc ${rc}, want 0"
docker run --rm --network "$NET" -e PGPASSWORD=apppw-1 postgres:16-alpine \
  psql -h "$PG" -U bas_app -d bas_platform -tAc 'SELECT count(*) FROM agents' >/dev/null 2>&1 \
  && pass "bas_app logs in with the provisioned password" || fail "bas_app login failed"
docker run --rm --network "$NET" -e PGPASSWORD=apppw-1 postgres:16-alpine \
  psql -h "$PG" -U bas_app -d bas_platform -tAc 'UPDATE schema_migrations SET dirty = true' >/dev/null 2>&1 \
  && fail "bas_app can write schema_migrations" || pass "bas_app cannot write schema_migrations"

# 2. adoption of a real v1.7.0 install
psql_c bas_platform 'CREATE DATABASE v170' >/dev/null
docker exec -i "$PG" psql -q -U bas_user -d v170 -v ON_ERROR_STOP=1 < "$FIXTURE" >/dev/null \
  && pass "v1.7.0 fixture loaded" || fail "fixture load failed"
out=$(mig v170 up); rc=$?
echo "$out" | sed 's/^/    /'
[[ $rc == 0 ]] && echo "$out" | grep -q 'adopted' && pass "v1.7.0 adopted" || fail "v1.7.0 up rc ${rc}"
[[ "$(psql_c v170 "SELECT hostname FROM agents WHERE agent_id = 'a-v170'")" == host-v170 ]] \
  && pass "v1.7.0 agent row kept" || fail "v1.7.0 agent row lost"

# 3. unrecognised database is refused, untouched
psql_c bas_platform 'CREATE DATABASE other' >/dev/null
psql_c other 'CREATE TABLE customers (id int)' >/dev/null
out=$(mig other up); rc=$?
echo "$out" | sed 's/^/    /'
[[ $rc == 1 ]] && pass "unrecognised DB refused" || fail "unrecognised rc ${rc}"
[[ "$(psql_c other "SELECT count(*) FROM pg_tables WHERE schemaname='public'")" == 1 ]] \
  && pass "unrecognised DB untouched" || fail "unrecognised DB changed"

echo "---"
if [[ $FAILS -eq 0 ]]; then echo "ALL PASS"; else echo "${FAILS} FAILED"; exit 1; fi
