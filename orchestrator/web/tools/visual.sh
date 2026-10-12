#!/usr/bin/env bash
# G1e visual equivalence: builds the baseline commit (tests/visual/BASELINE_REF)
# and the working tree, then compares them in the pinned Playwright image.
# Exit 0 = identical. .visual/ is removed on success, kept on failure.
set -euo pipefail
WEB="$(cd "$(dirname "$0")/.." && pwd)"
ORCH="$(cd "$WEB/.." && pwd)"
REPO="$(git -C "$WEB" rev-parse --show-toplevel)"
REF="$(tr -d '[:space:]' < "$WEB/tests/visual/BASELINE_REF")"
rm -rf "$WEB/.visual"
mkdir -p "$WEB/.visual/base"
git -C "$REPO" archive "$REF" orchestrator/web | tar -x -C "$WEB/.visual/base" --strip-components=2
IMAGE="mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27"
HOST="$ORCH"
if command -v cygpath >/dev/null 2>&1; then HOST="$(cygpath -m "$ORCH")"; fi
MSYS_NO_PATHCONV=1 docker run --rm --ipc=host -v "$HOST:/o" -w /o/web -e PLAYWRIGHT_IMAGE_VERSION=1.63.0 "$IMAGE" \
  sh -c 'npm ci --ignore-scripts --no-audit --no-fund >/dev/null \
    && ln -sfn /o/web/node_modules .visual/base/node_modules \
    && (cd .visual/base && node tools/build.mjs) \
    && node tools/build.mjs \
    && npx playwright test -c tests/visual/playwright.config.mjs \
    && rm -rf .visual'
# .visual/ is removed inside the container: on a Linux host its files are
# owned by the container's root user, which a host-side rm cannot delete.
