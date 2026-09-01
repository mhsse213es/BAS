#!/usr/bin/env bash
# Combined agent-plane + API-plane load test against a staging server.
# Usage: ./runbook.sh <agents> <stage-label> <server-url> <duration>
set -euo pipefail

AGENTS="${1:?agent count required}"
LABEL="${2:?stage label required, e.g. stage5-5000}"
SERVER_URL="${3:?staging server URL required}"
DURATION="${4:-15m}"
JWT="${BAS_JWT:?set BAS_JWT to a valid session token before running}"
AGENT_SECRET="${BAS_AGENT_SECRET:?set BAS_AGENT_SECRET to the configured AGENT_SECRET before running}"

OUT_DIR="orchestrator/loadtest/results/combined/${LABEL}"
mkdir -p "$OUT_DIR"

echo "[runbook] scraping /metrics every 15s for the duration of this stage..."
(
  while true; do
    curl -fsS "${SERVER_URL}/metrics" >> "${OUT_DIR}/metrics-snapshots.txt" 2>&1 || true
    echo "---$(date -u +%FT%TZ)---" >> "${OUT_DIR}/metrics-snapshots.txt"
    sleep 15
  done
) &
SCRAPE_PID=$!
trap 'kill $SCRAPE_PID 2>/dev/null || true' EXIT

echo "[runbook] starting loadgen ($AGENTS agents)..."
orchestrator/loadgen -server "$SERVER_URL" -agent-secret "$AGENT_SECRET" -agents "$AGENTS" -ramp-rate 100 -duration "$DURATION" -heartbeat 30s \
  > "${OUT_DIR}/loadgen.log" 2>&1 &
LOADGEN_PID=$!

echo "[runbook] starting k6 API mix..."
k6 run --vus 50 --duration "$DURATION" orchestrator/loadtest/k6/api-mix.js \
  -e BAS_SERVER_URL="$SERVER_URL" -e BAS_JWT="$JWT" \
  --summary-export="${OUT_DIR}/k6-summary.json" \
  > "${OUT_DIR}/k6.log" 2>&1 &
K6_PID=$!

wait "$LOADGEN_PID" "$K6_PID"
kill "$SCRAPE_PID" 2>/dev/null || true

echo "[runbook] stage $LABEL complete. Results in $OUT_DIR"
