#!/usr/bin/env bash
# Runs the Playwright smoke harness in the pinned Playwright image (browsers
# come from the image, never downloaded). Usage:
#   tools/smoke.sh <SMOKE_ROOT relative to orchestrator/web> [record]
set -euo pipefail
ORCH="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27"
HOST="$ORCH"
if command -v cygpath >/dev/null 2>&1; then HOST="$(cygpath -m "$ORCH")"; fi
REC=()
if [ "${2:-}" = "record" ]; then REC=(-e SMOKE_RECORD=1); fi
MSYS_NO_PATHCONV=1 exec docker run --rm --ipc=host -v "$HOST:/o" -w /o/web -e "SMOKE_ROOT=$1" -e SMOKE_CSP -e SMOKE_STRICT "${REC[@]}" \
  -e PLAYWRIGHT_IMAGE_VERSION=1.63.0 "$IMAGE" \
  sh -c 'npm ci --ignore-scripts --no-audit --no-fund >/dev/null && npm run smoke'
