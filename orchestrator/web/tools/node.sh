#!/usr/bin/env bash
# Runs a command inside the pinned Node image with orchestrator/web at /web.
# Node is never installed on the host (G1c Global Constraints).
set -euo pipefail
WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1"
HOST_DIR="$WEB_DIR"
if command -v cygpath >/dev/null 2>&1; then HOST_DIR="$(cygpath -m "$WEB_DIR")"; fi
MSYS_NO_PATHCONV=1 exec docker run --rm -v "$HOST_DIR:/web" -w /web "$IMAGE" "$@"
