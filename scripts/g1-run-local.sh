#!/usr/bin/env bash
# Local G1 run on the classifier view. Moves a locally built
# orchestrator/wwwroot/index.html aside and always restores it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$ROOT/orchestrator/wwwroot/index.html"
SAVED=""
if [ -f "$TARGET" ]; then SAVED="$(mktemp)"; mv "$TARGET" "$SAVED"; fi
restore() { rm -f "$TARGET"; if [ -n "$SAVED" ]; then mv "$SAVED" "$TARGET"; fi; }
trap restore EXIT
cd "$ROOT"
python3 scripts/g1-assemble-classifier-view.py
python3 scripts/g1-innerhtml-sink-classifier.py
python3 scripts/g1-trace-indirect-sinks.py
python3 scripts/g1-merge-classification.py
git show HEAD:security/g1/G1_FINAL_CLASSIFICATION.json > "${TMPDIR:-/tmp}/g1_base.json"
python3 scripts/g1-check-no-regression.py --against "${TMPDIR:-/tmp}/g1_base.json"
(cd scripts && python3 -m unittest test_g1_merge_classification test_g1_check_no_regression test_g1_assemble_classifier_view)
