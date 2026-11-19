#!/usr/bin/env bash
# packaging/bundle-manifest.sh <scenarios_dir> <bundle_id> <out_json>
#
# Writes the bundle manifest that the post-build ingest (tcv.BundleManifest)
# reads: every shipped scenario *.yaml with its SHA-256, so the ingest can map
# each shipped file to its registry content version. Runs on the build host,
# which has no database access; the ingest runs where the database is.
#
# Output schema (must match orchestrator/internal/tcv/bundle_manifest.go):
#   {"schema":1,"bundle_id":"...","packaged_at":"RFC3339","entries":[{"path":"...","sha256":"..."}]}
#
# packaged_at comes from $BUNDLE_PACKAGED_AT when set (tests use this for
# determinism), otherwise the current UTC time.
set -euo pipefail
unset CDPATH

if [ "$#" -ne 3 ]; then
  echo "usage: bundle-manifest.sh <scenarios_dir> <bundle_id> <out_json>" >&2
  exit 2
fi
SCEN_DIR="$1"
BUNDLE_ID="$2"
OUT="$3"

if [ ! -d "$SCEN_DIR" ]; then
  echo "bundle-manifest: scenarios directory not found: $SCEN_DIR" >&2
  exit 1
fi
if [ -z "$BUNDLE_ID" ]; then
  echo "bundle-manifest: bundle_id must not be empty" >&2
  exit 1
fi

PACKAGED_AT="${BUNDLE_PACKAGED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

# Collect relative paths of *.yaml scenarios, sorted byte-wise for stable output.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
(cd "$SCEN_DIR" && find . -type f -name '*.yaml' -print | sed 's|^\./||' | LC_ALL=C sort) > "$tmp"

if [ ! -s "$tmp" ]; then
  echo "bundle-manifest: no *.yaml scenarios under $SCEN_DIR; refusing to write an empty manifest" >&2
  exit 1
fi

# JSON-escape backslash and double quote in a path (file names are repo-controlled).
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

{
  printf '{"schema":1,"bundle_id":"%s","packaged_at":"%s","entries":[' \
    "$(json_escape "$BUNDLE_ID")" "$PACKAGED_AT"
  first=1
  while IFS= read -r rel; do
    sum="$(sha256sum "$SCEN_DIR/$rel" | cut -d' ' -f1)"
    if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
    printf '{"path":"%s","sha256":"%s"}' "$(json_escape "$rel")" "$sum"
  done < "$tmp"
  printf ']}\n'
} > "$OUT"
