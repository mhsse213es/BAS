#!/bin/sh
# dbsim lab Elastic setup. Idempotent. NOT run by the author (no Docker here).
#
#   setup.sh es      ES side: kibana_system password, dbsim-audit index
#                    template, filebeat writer role/user, alerts reader
#                    role/user. Run by the compose "bootstrap" service.
#   setup.sh kibana  Kibana side: detection-engine alerts index + the marker
#                    rule from rule.json. Run on the Docker host AFTER kibana
#                    is healthy.
#   setup.sh all     both (default).
#
# Env: ELASTIC_PASSWORD (required), KIBANA_SYSTEM_PASSWORD, FILEBEAT_PASSWORD,
# ALERTS_READER_PASSWORD (es phase), ES_URL (default http://127.0.0.1:59200),
# KIBANA_URL (default http://127.0.0.1:55601). Passwords are [A-Za-z0-9] only
# (they are placed in JSON bodies unescaped). Needs only sh and curl.
set -eu

phase=${1:-all}
here=$(cd "$(dirname "$0")" && pwd)
ES_URL=${ES_URL:-http://127.0.0.1:59200}
KIBANA_URL=${KIBANA_URL:-http://127.0.0.1:55601}
: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD is required}"

# Passwords are placed into JSON bodies unescaped: enforce [A-Za-z0-9] only.
for v in ELASTIC_PASSWORD KIBANA_SYSTEM_PASSWORD FILEBEAT_PASSWORD ALERTS_READER_PASSWORD; do
  eval "val=\${$v:-}"
  # Only the ES phase needs the last three; empty is caught by its own :? check.
  case $val in *[!A-Za-z0-9]*) echo "$v must be [A-Za-z0-9] only" >&2; exit 1;; esac
done

# api METHOD URL [curl args...] -> prints body, then a final line "HTTP <code>".
# The elastic credential goes to curl on stdin (-K -), never on argv.
api() {
  m=$1; u=$2; shift 2
  printf 'user = "elastic:%s"\n' "$ELASTIC_PASSWORD" |
    curl -s -K - -X "$m" -H 'Content-Type: application/json' \
      -H 'kbn-xsrf: true' -w '\nHTTP %{http_code}\n' "$@" "$u"
}
# must METHOD URL [curl args...]: fail unless HTTP 2xx.
must() {
  out=$(api "$@") || { echo "request failed: $1 $2" >&2; exit 1; }
  code=$(printf '%s\n' "$out" | tail -n 1 | sed 's/^HTTP //')
  case $code in 2??) return 0;; esac
  echo "FAILED $1 $2 -> HTTP $code" >&2
  printf '%s\n' "$out" | sed '$d' | head -c 2000 >&2; echo >&2
  exit 1
}

wait_for() { # name url grep-pattern
  i=0
  while [ "$i" -lt 90 ]; do
    if api GET "$2" 2>/dev/null | grep -q "$3"; then return 0; fi
    i=$((i + 1)); sleep 2
  done
  echo "timed out waiting for $1" >&2; exit 1
}

phase_es() {
  : "${KIBANA_SYSTEM_PASSWORD:?}" "${FILEBEAT_PASSWORD:?}" "${ALERTS_READER_PASSWORD:?}"
  wait_for elasticsearch "$ES_URL/_cluster/health" '"status"'

  must POST "$ES_URL/_security/user/kibana_system/_password" \
    -d "{\"password\":\"$KIBANA_SYSTEM_PASSWORD\"}"

  must PUT "$ES_URL/_index_template/dbsim-audit" --data-binary "@$here/index-template.json"

  must PUT "$ES_URL/_security/role/dbsim_filebeat_writer" -d '{
    "cluster": ["monitor"],
    "indices": [{"names": ["dbsim-audit-*"],
                 "privileges": ["auto_configure", "create_index", "create_doc", "index"]}]
  }'
  must PUT "$ES_URL/_security/user/dbsim_filebeat" -d "{
    \"password\": \"$FILEBEAT_PASSWORD\", \"roles\": [\"dbsim_filebeat_writer\"]
  }"

  # Read-only account for the detectverify Elastic connector: basic auth
  # (Config.ClientID / ClientSecret) with read on the alerts indices only.
  must PUT "$ES_URL/_security/role/dbsim_alerts_reader" -d '{
    "cluster": ["monitor"],
    "indices": [{"names": [".alerts-security.alerts-*", ".internal.alerts-security.alerts-*"],
                 "privileges": ["read", "view_index_metadata"]}]
  }'
  must PUT "$ES_URL/_security/user/dbsim_alerts_reader" -d "{
    \"password\": \"$ALERTS_READER_PASSWORD\", \"roles\": [\"dbsim_alerts_reader\"]
  }"
  echo "es phase done"
}

phase_kibana() {
  wait_for kibana "$KIBANA_URL/api/status" '"level":"available"'

  # Creates .alerts-security.alerts-default. Deprecated/optional on some 8.x
  # builds, so a failure is a warning, not fatal (creating the rule also
  # initialises the alerts index in the default space).
  code=$(api POST "$KIBANA_URL/api/detection_engine/index" | tail -n 1)
  echo "detection_engine/index: $code"

  # Create the rule; if it already exists (409) update it in place.
  out=$(api POST "$KIBANA_URL/api/detection_engine/rules" --data-binary "@$here/rule.json")
  code=$(printf '%s\n' "$out" | tail -n 1 | sed 's/^HTTP //')
  case $code in
    2??) echo "rule created" ;;
    409) must PUT "$KIBANA_URL/api/detection_engine/rules" --data-binary "@$here/rule.json"
         echo "rule updated" ;;
    *)   echo "rule create failed: HTTP $code" >&2
         printf '%s\n' "$out" | sed '$d' | head -c 2000 >&2; echo >&2
         exit 1 ;;
  esac
  echo "kibana phase done"
}

case $phase in
  es) phase_es ;;
  kibana) phase_kibana ;;
  all) phase_es; phase_kibana ;;
  *) echo "usage: setup.sh [es|kibana|all]" >&2; exit 2 ;;
esac
