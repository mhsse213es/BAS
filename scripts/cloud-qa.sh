#!/usr/bin/env bash
# Runs the cloud BAS test groups. Usage: scripts/cloud-qa.sh <group|all>
# Groups are documented in docs/cloud-qa-test-runbook.md.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)/orchestrator"
cd "$ROOT"

run() { echo "== $1"; shift; go test -count=1 "$@"; }

case "${1:-all}" in
  retry)    run retry ./internal/cloudgraph/ -run 'DoWithRetry|ParseRetryAfter|Backoff|Redact' -v ;;
  aws)      run aws ./internal/cloudgraph/ -run 'AWS' -v ;;
  gcp)      run gcp ./internal/cloudgraph/ -run 'GCP' -v ;;
  azure)    run azure ./internal/cloudgraph/ -run 'Azure|Preflight|Deny' -v ;;
  audit)    run audit ./internal/cloudgraph/ -run 'CloudTrail|ParseCloudTrail|LiveCorrelator|ActivityLog|GCPAudit|GCPCanonical|GCPEmail|EventCorrelator' -v ;;
  scenario) run scenario ./internal/cloudgraph/ -run 'Scenario|ObserveCloud|BuiltinCloud|GlobMatch' -v ;;
  db)       run db ./internal/db/ -run 'CloudPlan|CloudScenario|DiscoveredGraph|DiscoveryFailure' -v ;;
  api)      run api ./internal/api/ -run 'Cloud|ValidateCloud|AccountChecked' -v ;;
  live)
    echo "== live (requires tenant env vars; run only after preflight is green)"
    go test -count=1 -tags=integration ./internal/cloudgraph/ -run 'TestAzureDiscovery_Integration' -v ;;
  all)
    run cloudgraph ./internal/cloudgraph/ -v
    run db ./internal/db/ -run 'CloudPlan|CloudScenario|DiscoveredGraph|DiscoveryFailure'
    run api ./internal/api/ -run 'Cloud|ValidateCloud|AccountChecked' ;;
  *) echo "unknown group: $1" >&2; exit 2 ;;
esac
