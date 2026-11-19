#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")"
for y in $(seq 2002 2026); do
  curl -sSf -o "nvdcve-2.0-$y.json.gz" "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz"
  curl -sSf -o "nvdcve-2.0-$y.meta" "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.meta"
  echo "nvd $y ok $(date -u +%FT%TZ)"
done
echo NVD_DONE
