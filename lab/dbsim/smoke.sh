#!/bin/sh
# dbsim lab smoke test. NOT run by the author (the stack does not exist on the
# dev host); it must be run on the staging host.
#
# For each engine, from the separate "agent" container, as the least-privilege
# test account: issue a statement that BEGINS with the agent's marker comment
# form  /* dbsim:bas-dbsim:smoke-<rand> */  and poll the alerts index
# (.alerts-security.alerts-*, as the read-only connector account) for an alert
# on that DB server's host.name whose raw document contains the marker.
# Checks: postgresql (simple protocol), postgresql-extended (psql \bind, the
# extended protocol pgx uses), mysql (text protocol; the Go driver's
# prepared-statement path is NOT covered - run the dbsim_integration tests).
#
# Exit 0 only if every check passes. Expected BEFORE the stack exists: FAIL.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
if [ -f .env ]; then set -a; . ./.env; set +a; fi
: "${DBSIM_TEST_PASSWORD:?set in .env}" "${ALERTS_READER_PASSWORD:?set in .env}"
TIMEOUT=${SMOKE_TIMEOUT:-90}
COMPOSE=${COMPOSE:-docker compose}

if ! $COMPOSE exec -T agent true >/dev/null 2>&1; then
  echo "FAIL: the lab 'agent' container is not running (bring the stack up first)"
  exit 2
fi

rand=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
fail=0

PGPASSWORD=$DBSIM_TEST_PASSWORD; export PGPASSWORD
MYSQL_PWD=$DBSIM_TEST_PASSWORD; export MYSQL_PWD

# es_hits HOSTNAME -> alerts for that DB host in the last 15 minutes, raw JSON.
es_hits() {
  body=$(printf '{"size":200,"sort":[{"@timestamp":"desc"}],"query":{"bool":{"filter":[{"term":{"host.name":"%s"}},{"range":{"@timestamp":{"gte":"now-15m"}}}]}}}' "$1")
  printf 'user = "dbsim_alerts_reader:%s"\n' "$ALERTS_READER_PASSWORD" |
    $COMPOSE exec -T agent curl -s -K - -H 'Content-Type: application/json' \
      -d "$body" 'http://elasticsearch:9200/.alerts-security.alerts-*/_search?allow_no_indices=true&expand_wildcards=open,hidden'
}

# wait_alert HOSTNAME MARKER -> 0 when an alert document contains MARKER.
wait_alert() {
  start=$(date +%s)
  while :; do
    resp=$(es_hits "$1" 2>/dev/null || true)
    case $resp in *"$2"*) return 0 ;; esac
    now=$(date +%s)
    [ $((now - start)) -ge "$TIMEOUT" ] && return 1
    sleep 3
  done
}

report() { # label rc
  if [ "$2" -eq 0 ]; then echo "PASS  $1"; else echo "FAIL  $1 (no alert containing the marker within ${TIMEOUT}s)"; fail=1; fi
}

m_pg="bas-dbsim:smoke-$rand-pg"
$COMPOSE exec -T -e PGPASSWORD agent psql -X -q -h postgres -U dbsim_test -d dbsim \
  -c "/* dbsim:$m_pg */ SELECT 1" >/dev/null
rc=0; wait_alert dbsim-pg "$m_pg" || rc=1
report "postgresql          marker=$m_pg" "$rc"

m_pgx="bas-dbsim:smoke-$rand-pgx"
printf '/* dbsim:%s */ SELECT $1::text \\bind x \\g\n' "$m_pgx" |
  $COMPOSE exec -T -e PGPASSWORD agent psql -X -q -h postgres -U dbsim_test -d dbsim >/dev/null
rc=0; wait_alert dbsim-pg "$m_pgx" || rc=1
report "postgresql-extended marker=$m_pgx" "$rc"

m_my="bas-dbsim:smoke-$rand-my"
$COMPOSE exec -T -e MYSQL_PWD agent mysql --comments -h mysql -u dbsim_test -D dbsim \
  -e "/* dbsim:$m_my */ SELECT 1" >/dev/null
rc=0; wait_alert dbsim-mysql "$m_my" || rc=1
report "mysql               marker=$m_my" "$rc"

if [ "$fail" -ne 0 ]; then echo "SMOKE: FAIL"; exit 1; fi
echo "SMOKE: PASS"
