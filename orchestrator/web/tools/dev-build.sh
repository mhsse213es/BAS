#!/usr/bin/env bash
# Local dev: build the dashboard in the pinned Node image and copy dist/ to
# orchestrator/wwwroot/ (git-ignored) so the orchestrator can run from disk.
set -euo pipefail
WEB="$(cd "$(dirname "$0")/.." && pwd)"
"$WEB/tools/node.sh" sh -c 'npm ci --ignore-scripts --no-audit --no-fund && npm run build'
rm -rf "$WEB/../wwwroot"
cp -r "$WEB/dist" "$WEB/../wwwroot"
echo "orchestrator/wwwroot refreshed from web/dist"
