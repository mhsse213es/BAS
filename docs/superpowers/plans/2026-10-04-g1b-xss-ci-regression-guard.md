# G1b: XSS Sink CI Regression Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a CI guard that fails a PR when a `.innerHTML` sink in `orchestrator/wwwroot/index.html` becomes more dangerous than it was on `main`, without re-litigating the 126 `unescaped_html` sinks G1a already reviewed and accepted, and without ever modifying the two proven G1a audit scripts.

**Architecture:** Two new stdlib-only Python scripts. `scripts/g1-merge-classification.py` deterministically merges the two existing (untouched) classifier/tracer CSVs into `Assessment/G1_FINAL_CLASSIFICATION.json` (new CI source of truth) and `.csv` (audit view), adding a content-hash `sink_id` and a coarse `severity_tier` to each sink. `scripts/g1-check-no-regression.py` groups sinks into `(function, target, op)` "slots", compares the current run's worst severity per slot against a `--against` baseline (the committed `main` version), and fails only when an existing slot's worst severity increased. A new CI step runs both scripts plus their `unittest` suites in the existing GitHub Actions job.

**Tech Stack:** Python 3 stdlib only (`csv`, `json`, `hashlib`, `re`, `argparse`, `importlib.util`, `unittest`) — no pip install, no venv, no Node/npm. GitHub Actions (existing `ubuntu-latest` runner, which ships `python3`).

**Spec:** `docs/superpowers/specs/2026-10-04-g1b-xss-ci-regression-guard-design.md`

## Global Constraints

- Zero changes to `scripts/g1-innerhtml-sink-classifier.py` or `scripts/g1-trace-indirect-sinks.py` — not even a `__main__`-guard refactor. The new checker duplicates the ~40-line `scan_function_spans()` matcher from the tracer rather than importing it (the tracer runs `SPANS = scan_function_spans(text)` at true module scope, so importing it would re-run the scan as an import side effect). It safely imports the classifier module via `importlib.util`, the same way the tracer itself already does, since the classifier has no such side effect.
- Python 3 stdlib only. No `pip install`, no virtualenv, no Node/npm/frontend framework. Tests use `unittest`, not `pytest`.
- `g1-merge-classification.py` must be deterministic: byte-identical JSON/CSV across repeated runs on an unchanged tree. Fixed row order (`function, target, op, sink_id`), fixed field order (dict insertion order, no `sort_keys=True`), no timestamps, no absolute/machine-specific paths, explicit `encoding="utf-8"` and `newline="\n"` everywhere (this dev box is Windows; CRLF must never leak into committed output).
- `Assessment/G1_FINAL_CLASSIFICATION.json` is the authoritative machine baseline (CI reads this); `Assessment/G1_FINAL_CLASSIFICATION.csv` is the human/audit view (same rows, same fields, CSV-serialized).
- `severity_tier`: `0` = `static`/`static_empty`, `1` = `escaped`, `2` = `unescaped_likely_safe`, `3` = `partial_escaped`, `4` = `unescaped_text`/`unescaped_html` (deliberately the same tier — both mean an unescaped runtime value reaches `.innerHTML`; the fine-grained `final_category` is preserved alongside `severity_tier` for remediation-hint purposes).
- `sink_id = f"{function}:{target}:{op}:{sha256(normalize(rhs)).hexdigest()[:12]}"`, where `normalize()` collapses all whitespace runs (including newlines — 183 of the 455 real `rhs` values contain embedded newlines) to a single space and trims.
- Regression rule operates on `(function, target, op)` **slots**, compared by the *maximum* `severity_tier` among the sinks at that slot (108 of 293 real slots have more than one sink, e.g. a static placeholder plus a dynamic render of the same target): a slot absent from the new run that existed in the baseline is OK (sink eliminated); an existing slot whose max severity increased is a FAIL; a slot that didn't exist in the baseline at all is reported in the output but never auto-failed, regardless of how dangerous its classification — G1a's own founding finding was that `unescaped_html` is sometimes fine once a human reads it (126 of 455 sinks are exactly that, already accepted), so auto-failing every new sink at a tier 126 existing ones already sit at would repeat that mistake.
- The canonical-escaper check is semantic (four independent whitespace/ordering-tolerant substitution regexes: `&`→`&amp;`, `<`→`&lt;`, `>`→`&gt;`, `"`→`&quot;`), not a literal multi-line signature match. Exactly one function in `index.html` may satisfy all four; it must not also map a bare `'` to any HTML entity (`&#39;`/`&apos;`/`&#x27;`) — several callers rely on receiving a raw `'` to apply their own quote-context escaping afterward.
- This project commits directly to `main` with a push immediately after every commit (no worktree, no feature branch) — the same convention G1/G1a used in this repo.

## Review Focus

- A `--against` baseline file containing the literal 2-character content `{}` (the very first run, no prior `main` baseline exists yet) — `load_json` must treat this as an empty sink list, not crash. Covered by Task 3, `TestLoadJson.test_empty_object_baseline_means_no_prior_sinks`.
- A sink's `rhs` is reformatted (reindented, rewrapped across lines) without changing its actual content — `sink_id` must be stable, or every reformat looks like "sink disappeared + new sink appeared." Covered by Task 1, `TestMerge.test_rhs_whitespace_does_not_affect_sink_id`.
- The committed `Assessment/G1_FINAL_CLASSIFICATION.{json,csv}` go stale (someone hand-edits them, or edits `index.html` and forgets to rerun the merge script) — the freshness check must catch this *before* the regression check ever runs against possibly-wrong data. Covered by Task 4's manual verification step (intentionally stale the committed JSON, confirm the freshness check's `git diff --exit-code` fails with the documented error, then revert).
- A slot with multiple sinks where one sink gets safer while a sibling at the same slot gets worse — must be judged by the slot's worst (max) sink, never an average or a raw count. Covered by Task 3, `TestCompareSlots.test_multiple_sinks_per_slot_compares_the_max`.
- A brand-new `.innerHTML` sink appears at the most dangerous tier (`unescaped_html`) — must not be auto-failed, but must be visibly named in the CI step's printed output so a human reviewer actually sees it. Covered by Task 3, `TestCompareSlots.test_brand_new_slot_is_reported_not_failed`, and by Task 4's live-CI verification reading the step's log output.

---

## Task 1: `scripts/g1-merge-classification.py`

**Files:**
- Create: `scripts/g1-merge-classification.py`
- Create: `scripts/test_g1_merge_classification.py`

**Interfaces:**
- Consumes: `Assessment/G1_INNERHTML_SINK_INVENTORY.csv` (fields: `line,function,target,op,category,data_source_tags,rhs_len,rhs`) and `Assessment/G1_INDIRECT_SINK_TRACE.csv` (fields: `line,function,original_category,resolved_category,notes,rhs`) — both produced by the untouched classifier/tracer scripts, never regenerated by this task.
- Produces: `merge(inv_csv_path=INV_CSV, trace_csv_path=TRACE_CSV) -> list[dict]`, each dict with keys `sink_id, line, function, target, op, baseline_category, final_category, severity_tier, data_source_tags, trace_notes, rhs`, sorted by `(function, target, op, sink_id)`. This exact schema and function signature is what Task 2 and Task 3 rely on.

Since the module filename has hyphens, it cannot be `import`ed normally — load it in the test file (and in any future consumer) via `importlib.util.spec_from_file_location`, the same pattern `g1-trace-indirect-sinks.py` already uses to load the classifier.

- [ ] **Step 1: Write the failing tests**

Create `scripts/test_g1_merge_classification.py`:

```python
import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "g1_merge_classification", REPO_ROOT / "scripts" / "g1-merge-classification.py"
)
merge_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(merge_mod)


def _write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


class TestMerge(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.inv_path = Path(self.tmpdir.name) / "inv.csv"
        self.trace_path = Path(self.tmpdir.name) / "trace.csv"

    def _write_inventory(self, rows):
        _write_csv(
            self.inv_path,
            ["line", "function", "target", "op", "category", "data_source_tags", "rhs_len", "rhs"],
            rows,
        )

    def _write_trace(self, rows):
        _write_csv(
            self.trace_path,
            ["line", "function", "original_category", "resolved_category", "notes", "rhs"],
            rows,
        )

    def test_static_sink_passes_through_unchanged(self):
        self._write_inventory([{
            "line": "10", "function": "f", "target": "el", "op": "=",
            "category": "static", "data_source_tags": "", "rhs_len": "4", "rhs": "'hi'",
        }])
        self._write_trace([])
        rows = merge_mod.merge(self.inv_path, self.trace_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["final_category"], "static")
        self.assertEqual(rows[0]["severity_tier"], 0)
        self.assertTrue(rows[0]["sink_id"].startswith("f:el:=:"))

    def test_indirect_sink_resolves_via_trace(self):
        self._write_inventory([{
            "line": "20", "function": "g", "target": "box", "op": "=",
            "category": "indirect_variable", "data_source_tags": "", "rhs_len": "4", "rhs": "html",
        }])
        self._write_trace([{
            "line": "20", "function": "g", "original_category": "indirect_variable",
            "resolved_category": "escaped", "notes": "resolved via trace", "rhs": "html",
        }])
        rows = merge_mod.merge(self.inv_path, self.trace_path)
        self.assertEqual(rows[0]["final_category"], "escaped")
        self.assertEqual(rows[0]["trace_notes"], "resolved via trace")

    def test_manual_resolution_applies_when_trace_is_unresolved(self):
        # Real sink from the committed baseline (line 11243, tile()'s write
        # to the dash-itsm-tiles target, rhs "html"): the automated tracer's
        # single scope-hop can't follow it further and leaves it
        # indirect_builder. The manual table supplies the real second-hop
        # answer a human already traced for this exact sink.
        self._write_inventory([{
            "line": "11243", "function": "tile",
            "target": "document.getElementById('dash-itsm-tiles')", "op": "=",
            "category": "indirect_variable", "data_source_tags": "", "rhs_len": "4", "rhs": "html",
        }])
        self._write_trace([{
            "line": "11243", "function": "tile", "original_category": "indirect_variable",
            "resolved_category": "indirect_builder", "notes": "unresolved by automated trace",
            "rhs": "html",
        }])
        rows = merge_mod.merge(self.inv_path, self.trace_path)
        self.assertEqual(rows[0]["final_category"], "escaped")

    def test_rhs_whitespace_does_not_affect_sink_id(self):
        self._write_inventory([
            {"line": "1", "function": "f", "target": "t", "op": "=", "category": "static",
             "data_source_tags": "", "rhs_len": "5", "rhs": "a + b"},
            {"line": "2", "function": "f2", "target": "t2", "op": "=", "category": "static",
             "data_source_tags": "", "rhs_len": "5", "rhs": "a +\n   b"},
        ])
        self._write_trace([])
        rows = merge_mod.merge(self.inv_path, self.trace_path)
        hash1 = rows[0]["sink_id"].rsplit(":", 1)[-1]
        hash2 = rows[1]["sink_id"].rsplit(":", 1)[-1]
        self.assertEqual(hash1, hash2)

    def test_deterministic_across_repeated_runs(self):
        self._write_inventory([
            {"line": "1", "function": "b", "target": "x", "op": "=", "category": "static",
             "data_source_tags": "", "rhs_len": "3", "rhs": "'a'"},
            {"line": "2", "function": "a", "target": "y", "op": "+=", "category": "unescaped_html",
             "data_source_tags": "user", "rhs_len": "1", "rhs": "v"},
        ])
        self._write_trace([])
        rows1 = merge_mod.merge(self.inv_path, self.trace_path)
        rows2 = merge_mod.merge(self.inv_path, self.trace_path)
        self.assertEqual(json.dumps(rows1), json.dumps(rows2))
        # Pins the row-ordering contract: sorted by (function, target, op, sink_id).
        self.assertEqual(rows1[0]["function"], "a")
        self.assertEqual(rows1[1]["function"], "b")

    def test_unresolvable_category_raises(self):
        self._write_inventory([{
            "line": "99", "function": "h", "target": "z", "op": "=",
            "category": "indirect_variable", "data_source_tags": "", "rhs_len": "1", "rhs": "w",
        }])
        self._write_trace([{
            "line": "99", "function": "h", "original_category": "indirect_variable",
            "resolved_category": "unclear", "notes": "no callable name found in rhs", "rhs": "w",
        }])
        with self.assertRaises(ValueError):
            merge_mod.merge(self.inv_path, self.trace_path)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest scripts.test_g1_merge_classification -v` (from the repo root)

Expected: `ModuleNotFoundError` or `FileNotFoundError` for `scripts/g1-merge-classification.py` — the module doesn't exist yet. (If `python3 -m unittest` can't resolve the package path from the repo root because `scripts/` has no `__init__.py`, run `cd scripts && python3 -m unittest test_g1_merge_classification -v` instead — either way, the failure must be "file not found," not a typo in the test itself.)

- [ ] **Step 3: Write the implementation**

Create `scripts/g1-merge-classification.py`:

```python
#!/usr/bin/env python3
"""Deterministic merge of the G1 classifier + indirect-sink-trace outputs
into Assessment/G1_FINAL_CLASSIFICATION.json (CI source of truth) and
Assessment/G1_FINAL_CLASSIFICATION.csv (human/audit view).

Reads (never modifies, never re-derives):
  Assessment/G1_INNERHTML_SINK_INVENTORY.csv  (from g1-innerhtml-sink-classifier.py)
  Assessment/G1_INDIRECT_SINK_TRACE.csv       (from g1-trace-indirect-sinks.py)

Trusts both files' function/target/op/rhs columns verbatim. The only
judgment this script adds on top of the two upstream scripts is the
MANUAL_RESOLUTIONS table below: five sinks where the automated tracer's
single-hop scope analysis could not fully resolve an indirect_* sink (it
returns "unclear" or stays indirect_builder/indirect_variable), and a
second hop of human analysis was needed during G1a. Each entry is keyed
by the sink's own (function, target, op, rhs_hash) identity, so it stops
applying -- rather than silently attaching to the wrong sink -- the
moment index.html changes enough to alter that sink's own rhs text.
"""
import csv
import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INV_CSV = REPO_ROOT / "Assessment" / "G1_INNERHTML_SINK_INVENTORY.csv"
TRACE_CSV = REPO_ROOT / "Assessment" / "G1_INDIRECT_SINK_TRACE.csv"
OUT_JSON = REPO_ROOT / "Assessment" / "G1_FINAL_CLASSIFICATION.json"
OUT_CSV = REPO_ROOT / "Assessment" / "G1_FINAL_CLASSIFICATION.csv"

INDIRECT_CATEGORIES = {"indirect_builder", "indirect_variable"}
UNRESOLVED_CATEGORIES = {"indirect_builder", "indirect_variable", "unclear"}

# 4 = unescaped_text and unescaped_html share a tier deliberately: both mean
# an unescaped runtime value reaches .innerHTML. The distinction is useful
# for choosing a fix (textContent vs HTML-context escaping), not severity.
SEVERITY_TIER = {
    "static": 0,
    "static_empty": 0,
    "escaped": 1,
    "unescaped_likely_safe": 2,
    "partial_escaped": 3,
    "unescaped_text": 4,
    "unescaped_html": 4,
}

# Second-hop human resolutions for sinks the automated tracer leaves
# unresolved. Keyed by (function, target, op, rhs_hash) -- the same
# identity components sink_id_for() uses -- so a key that no longer
# matches the live inventory simply stops applying.
MANUAL_RESOLUTIONS = {
    ("tile", "document.getElementById('dash-itsm-tiles')", "=", "e5e239560bc1"): (
        "escaped",
        "loadDashboardITSM's tile(lbl,val,col) closure doesn't escape lbl "
        "internally, but the one caller that passes dynamic data "
        "(p.provider, an ITSM byProvider API response) wraps it in x().",
    ),
    ("byStartedAtDesc", "tbody", "=", "a84861ce6bf1"): (
        "partial_escaped",
        "e.html is runRowHtml(r) or _sweepRowHtml(payload,opts); both "
        "builders are partial_escaped (documented runId / opts gaps, "
        "accepted as low-risk).",
    ),
    ("renderModalSelection", "note", "=", "3673014e72b6"): (
        "escaped",
        "_postureSummaryCache is written by renderModalSelection's "
        "catNames.join(', ') (posture-catalog phase names), wrapped in x().",
    ),
    ("rowHtml", "document.getElementById('results-body')", "=", "230d8358dc8e"): (
        "escaped",
        "Local rowHtml(k,v) closure in openIOCDetail escapes v internally "
        "(hardened: closes the phase-1-flagged fragile pattern).",
    ),
    ("openConfirmDiffModal", "document.getElementById('confirm-diff-body')", "=", "2da3370e4143"): (
        "escaped",
        "diffHtml parameter, traced across all 5 call sites -- every one "
        "passes rows built exclusively from _diffRow()/_diffSecretRow(), "
        "both fully escaped internally via x().",
    ),
}


def normalize(rhs):
    """Collapse all whitespace runs (including newlines) to one space and
    trim, so a sink's identity does not shift when its rhs expression is
    merely reformatted (183 of 455 real rhs values span multiple lines)."""
    return re.sub(r"\s+", " ", rhs).strip()


def sink_id_for(function, target, op, rhs):
    h = hashlib.sha256(normalize(rhs).encode("utf-8")).hexdigest()[:12]
    return f"{function}:{target}:{op}:{h}", h


def load_trace_by_line(trace_csv_path):
    trace_by_line = {}
    with open(trace_csv_path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            trace_by_line[int(row["line"])] = row
    return trace_by_line


def merge(inv_csv_path=INV_CSV, trace_csv_path=TRACE_CSV):
    trace_by_line = load_trace_by_line(trace_csv_path)
    out_rows = []
    with open(inv_csv_path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            line = int(row["line"])
            function = row["function"]
            target = row["target"]
            op = row["op"]
            rhs = row["rhs"]
            baseline_cat = row["category"]

            if baseline_cat in INDIRECT_CATEGORIES:
                t = trace_by_line.get(line)
                if t:
                    final_cat = t["resolved_category"]
                    notes = t["notes"]
                else:
                    final_cat = baseline_cat
                    notes = "NO TRACE ROW FOUND"
            else:
                final_cat = baseline_cat
                notes = ""

            sid, rhs_hash = sink_id_for(function, target, op, rhs)

            if final_cat in UNRESOLVED_CATEGORIES:
                manual = MANUAL_RESOLUTIONS.get((function, target, op, rhs_hash))
                if manual:
                    final_cat, notes = manual

            if final_cat not in SEVERITY_TIER:
                raise ValueError(
                    f"line {line}: final_category {final_cat!r} has no severity_tier "
                    "mapping -- this sink is still unresolved. Either the tracer "
                    "needs to resolve it, or it needs a MANUAL_RESOLUTIONS entry."
                )

            out_rows.append({
                "sink_id": sid,
                "line": line,
                "function": function,
                "target": target,
                "op": op,
                "baseline_category": baseline_cat,
                "final_category": final_cat,
                "severity_tier": SEVERITY_TIER[final_cat],
                "data_source_tags": row["data_source_tags"],
                "trace_notes": notes,
                "rhs": rhs,
            })

    out_rows.sort(key=lambda r: (r["function"], r["target"], r["op"], r["sink_id"]))
    return out_rows


def write_json(rows):
    text = json.dumps(rows, indent=1, ensure_ascii=False) + "\n"
    with open(OUT_JSON, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def write_csv(rows):
    fieldnames = [
        "sink_id", "line", "function", "target", "op",
        "baseline_category", "final_category", "severity_tier",
        "data_source_tags", "trace_notes", "rhs",
    ]
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    rows = merge()
    write_json(rows)
    write_csv(rows)
    from collections import Counter
    cnt = Counter(r["final_category"] for r in rows)
    print(f"TOTAL: {len(rows)}")
    for cat, n in cnt.most_common():
        print(f"  {cat}: {n}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scripts && python3 -m unittest test_g1_merge_classification -v`
Expected: `OK` with 6 tests passing (`test_static_sink_passes_through_unchanged`, `test_indirect_sink_resolves_via_trace`, `test_manual_resolution_applies_when_trace_is_unresolved`, `test_rhs_whitespace_does_not_affect_sink_id`, `test_deterministic_across_repeated_runs`, `test_unresolvable_category_raises`).

- [ ] **Step 5: Commit**

```bash
git add scripts/g1-merge-classification.py scripts/test_g1_merge_classification.py
git commit -m "feat(security): add G1 deterministic classification merge script"
git push
```

---

## Task 2: Regenerate the real G1 baseline

**Files:**
- Modify: `Assessment/G1_FINAL_CLASSIFICATION.csv` (new schema: adds `sink_id`, `severity_tier`; rows now sorted by `function, target, op, sink_id` instead of by `line`)
- Create: `Assessment/G1_FINAL_CLASSIFICATION.json`

**Interfaces:**
- Consumes: Task 1's `scripts/g1-merge-classification.py` `main()`.
- Produces: a real, committed `Assessment/G1_FINAL_CLASSIFICATION.json` for Task 4's CI freshness/regression checks to compare against. This must exist and be committed *before* Task 4 wires up CI, otherwise the freshness check's `git diff --exit-code` has nothing tracked to compare against and silently passes on an untracked new file.

This task has no unit test of its own — its deliverable is verified by matching the counts already known-correct from `05aa7cbe` (the commit where these counts were last hand-verified: `static 138, unescaped_html 126, escaped 86, partial_escaped 53, static_empty 41, unescaped_text 9, unescaped_likely_safe 2`, 455 total, 0 unresolved).

- [ ] **Step 1: Run the real merge**

Run: `python3 scripts/g1-merge-classification.py`

Expected output (counts must match exactly):
```
TOTAL: 455
  static: 138
  unescaped_html: 126
  escaped: 86
  partial_escaped: 53
  static_empty: 41
  unescaped_text: 9
  unescaped_likely_safe: 2
```

If any count differs from this, STOP — do not commit. That means either `MANUAL_RESOLUTIONS` in Task 1's script no longer matches the current `Assessment/G1_INDIRECT_SINK_TRACE.csv` content (check whether a key's `rhs_hash` still matches — if `index.html` changed one of the 5 manually-resolved sinks since this plan was written, the override silently stopped applying and needs a new hash), or something else in `index.html`/the inventory changed. Diagnose with `git diff Assessment/G1_INNERHTML_SINK_INVENTORY.csv Assessment/G1_INDIRECT_SINK_TRACE.csv` before proceeding.

- [ ] **Step 2: Verify the diff is the expected shape**

Run: `git diff --stat Assessment/G1_FINAL_CLASSIFICATION.csv`

Expected: the file is rewritten (every row changes, since row order and column set both changed) but `git diff Assessment/G1_FINAL_CLASSIFICATION.csv | grep '^[+-]' | wc -l` should be roughly `2 * 456` (every row once as a deletion, once as an addition) — not wildly more or fewer. Spot-check a handful of rows with `git diff Assessment/G1_FINAL_CLASSIFICATION.csv | head -60` to confirm the new `sink_id`/`severity_tier` columns look sane (e.g. `sink_id` values look like `funcname:target:op:12hexchars`) and no `final_category` values changed versus before.

- [ ] **Step 3: Commit**

```bash
git add Assessment/G1_FINAL_CLASSIFICATION.csv Assessment/G1_FINAL_CLASSIFICATION.json
git commit -m "chore(security): regenerate G1 baseline via deterministic merge script

Adds sink_id (content-hash identity) and severity_tier to every row;
rows now sorted by (function, target, op, sink_id) instead of by line.
final_category values are unchanged from the hand-merged 05aa7cbe
baseline -- verified identical counts (455 total, unescaped_html 126,
escaped 86, partial_escaped 53, static 138, static_empty 41,
unescaped_text 9, unescaped_likely_safe 2)."
git push
```

---

## Task 3: `scripts/g1-check-no-regression.py`

**Files:**
- Create: `scripts/g1-check-no-regression.py`
- Create: `scripts/test_g1_check_no_regression.py`

**Interfaces:**
- Consumes: the JSON row schema Task 1 produces (list of dicts with `sink_id, line, function, target, op, baseline_category, final_category, severity_tier, data_source_tags, trace_notes, rhs`); the classifier module's `text` attribute and `skip_comment`/`skip_regex_literal`/`skip_ws` functions, loaded via the same `importlib.util` pattern the tracer uses.
- Produces: a CLI `python3 scripts/g1-check-no-regression.py --against <baseline.json> [--current <current.json>]` that exits `0` on pass, `1` on fail, and prints a human-readable report. Also produces `compare_slots(old_sinks, new_sinks) -> (regressions, eliminated, new_slots)` and `check_canonical_escaper(text, clf) -> list[str]` (empty list = pass) as directly testable functions.

- [ ] **Step 1: Write the failing tests**

Create `scripts/test_g1_check_no_regression.py`:

```python
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(module_name, filename):
    spec = importlib.util.spec_from_file_location(module_name, REPO_ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


guard = _load("g1_check_no_regression", "g1-check-no-regression.py")
clf = _load("g1_classifier_for_tests", "g1-innerhtml-sink-classifier.py")


def _sink(function, target, op, severity_tier, sink_id=None):
    return {
        "sink_id": sink_id or f"{function}:{target}:{op}:deadbeefcafe",
        "line": 1,
        "function": function,
        "target": target,
        "op": op,
        "baseline_category": "unescaped_html",
        "final_category": "unescaped_html",
        "severity_tier": severity_tier,
        "data_source_tags": "",
        "trace_notes": "",
        "rhs": "x",
    }


class TestLoadJson(unittest.TestCase):
    def test_empty_object_baseline_means_no_prior_sinks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{}")
            path = f.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        self.assertEqual(guard.load_json(path), [])

    def test_array_baseline_loads_sinks(self):
        rows = [_sink("f", "t", "=", 1)]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(rows, f)
            path = f.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        self.assertEqual(guard.load_json(path), rows)


class TestCompareSlots(unittest.TestCase):
    def test_slot_eliminated_is_ok(self):
        old = [_sink("f", "t", "=", 4)]
        new = []
        regressions, eliminated, new_slots = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])
        self.assertEqual(len(eliminated), 1)
        self.assertEqual(new_slots, [])

    def test_slot_severity_increase_is_regression(self):
        old = [_sink("f", "t", "=", 1)]
        new = [_sink("f", "t", "=", 4)]
        regressions, eliminated, new_slots = guard.compare_slots(old, new)
        self.assertEqual(regressions, [(("f", "t", "="), 1, 4)])

    def test_slot_severity_same_or_decrease_is_ok(self):
        old = [_sink("f", "t", "=", 4)]
        new = [_sink("f", "t", "=", 1)]
        regressions, _, _ = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])

        same = [_sink("g", "u", "+=", 2)]
        regressions2, _, _ = guard.compare_slots(same, same)
        self.assertEqual(regressions2, [])

    def test_brand_new_slot_is_reported_not_failed(self):
        old = []
        new = [_sink("f", "t", "=", 4)]
        regressions, eliminated, new_slots = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])
        self.assertEqual(new_slots, [(("f", "t", "="), 4)])

    def test_multiple_sinks_per_slot_compares_the_max(self):
        old = [_sink("f", "t", "=", 0, sink_id="a"), _sink("f", "t", "=", 1, sink_id="b")]
        new = [_sink("f", "t", "=", 0, sink_id="a"), _sink("f", "t", "=", 4, sink_id="c")]
        regressions, _, _ = guard.compare_slots(old, new)
        self.assertEqual(regressions, [(("f", "t", "="), 1, 4)])


class TestCanonicalEscaperCheck(unittest.TestCase):
    GOOD = (
        "function escapeHTML(s) {\n"
        "  return String(s == null ? '' : s)\n"
        "    .replace(/&/g,'&amp;').replace(/</g,'&lt;')"
        ".replace(/>/g,'&gt;').replace(/\"/g,'&quot;');\n"
        "}\n"
    )

    def test_canonical_escaper_passes(self):
        self.assertEqual(guard.check_canonical_escaper(self.GOOD, clf), [])

    def test_missing_substitution_fails(self):
        broken = self.GOOD.replace(".replace(/\"/g,'&quot;')", "")
        errors = guard.check_canonical_escaper(broken, clf)
        self.assertEqual(len(errors), 1)
        self.assertIn("No function", errors[0])

    def test_duplicate_escaper_fails(self):
        dup = self.GOOD + self.GOOD.replace("escapeHTML", "xe")
        errors = guard.check_canonical_escaper(dup, clf)
        self.assertEqual(len(errors), 1)
        self.assertIn("functions implement", errors[0])

    def test_escaper_that_also_escapes_apostrophe_fails(self):
        over_escaping = self.GOOD.replace(
            ".replace(/\"/g,'&quot;');",
            ".replace(/\"/g,'&quot;').replace(/'/g,'&#39;');",
        )
        errors = guard.check_canonical_escaper(over_escaping, clf)
        self.assertEqual(len(errors), 1)
        self.assertIn("also escapes a bare", errors[0])

    def test_real_index_html_passes(self):
        # Integration check against the real file, not a fixture --
        # catches a real regression the fixture tests above can't see.
        real_clf = _load("g1_classifier_real", "g1-innerhtml-sink-classifier.py")
        errors = guard.check_canonical_escaper(real_clf.text, real_clf)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scripts && python3 -m unittest test_g1_check_no_regression -v`
Expected: `FileNotFoundError` for `scripts/g1-check-no-regression.py` — the module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `scripts/g1-check-no-regression.py`:

```python
#!/usr/bin/env python3
"""CI regression guard for G1's XSS-sink classification.

Compares the current Assessment/G1_FINAL_CLASSIFICATION.json against a
--against baseline JSON (the base branch's committed version, or the
literal content "{}" if none exists yet) and fails when a
(function, target, op) "slot" that existed in the baseline has gotten
more dangerous. A slot that disappears is OK (sink eliminated). A slot
that's brand new is reported, never auto-failed -- G1a's own finding was
that unescaped_html is sometimes fine once a human reads it (126 of 455
sinks are exactly that, already accepted), so failing every new sink at
a tier 126 existing ones already sit at would repeat that mistake.

Also runs the canonical-escaper check: exactly one function in
orchestrator/wwwroot/index.html must implement the &/</>/" substitutions,
and that one function must not also escape a bare '.
"""
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CURRENT_JSON = REPO_ROOT / "Assessment" / "G1_FINAL_CLASSIFICATION.json"


def load_json(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if data:
            raise ValueError(f"{path}: expected a JSON array of sinks or {{}}, got a non-empty object")
        return []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of sinks or {{}}")
    return data


def slot_key(sink):
    return (sink["function"], sink["target"], sink["op"])


def max_severity_by_slot(sinks):
    out = {}
    for s in sinks:
        k = slot_key(s)
        tier = s["severity_tier"]
        if k not in out or tier > out[k]:
            out[k] = tier
    return out


def compare_slots(old_sinks, new_sinks):
    """Returns (regressions, eliminated, new_slots):
      regressions: [(slot, old_max_tier, new_max_tier), ...] where new > old
      eliminated:  [(slot, old_max_tier), ...] where the slot no longer exists
      new_slots:   [(slot, new_max_tier), ...] where the slot didn't exist before
    """
    old_by_slot = max_severity_by_slot(old_sinks)
    new_by_slot = max_severity_by_slot(new_sinks)

    regressions = []
    eliminated = []
    new_slots = []

    for slot, old_tier in old_by_slot.items():
        if slot not in new_by_slot:
            eliminated.append((slot, old_tier))
        else:
            new_tier = new_by_slot[slot]
            if new_tier > old_tier:
                regressions.append((slot, old_tier, new_tier))

    for slot, new_tier in new_by_slot.items():
        if slot not in old_by_slot:
            new_slots.append((slot, new_tier))

    return regressions, eliminated, new_slots


# --- Canonical-escaper check -------------------------------------------
# Duplicated from g1-trace-indirect-sinks.py's scan_function_spans() and
# its helpers, not imported: that module runs
# SPANS = scan_function_spans(text) at true module scope (unguarded by
# if __name__ == "__main__"), so importing it for reuse would re-run the
# whole scan as an unwanted side effect of import. See
# docs/superpowers/specs/2026-10-04-g1b-xss-ci-regression-guard-design.md,
# Architecture section 4.

AMP = re.compile(r"""\.replace\(\s*/&/g\s*,\s*['"]&amp;['"]\s*\)""")
LT = re.compile(r"""\.replace\(\s*/</g\s*,\s*['"]&lt;['"]\s*\)""")
GT = re.compile(r"""\.replace\(\s*/>/g\s*,\s*['"]&gt;['"]\s*\)""")
QUOT = re.compile(r"""\.replace\(\s*/"/g\s*,\s*['"]&quot;['"]\s*\)""")
APOS = re.compile(
    r"""\.replace\(\s*/'/g\s*,\s*['"](&#39;|&apos;|&#x27;)['"]\s*\)""",
    re.IGNORECASE,
)

FN_START_RE = re.compile(
    r"function\s+([A-Za-z_$][\w$]*)\s*\("
    r"|(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\("
    r"|(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*function\s*\("
)


def _skip_string(text, i):
    q = text[i]
    j = i + 1
    nn = len(text)
    while j < nn:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == q:
            j += 1
            break
        j += 1
    return j


def _find_matching_paren(text, open_pos, clf):
    i = open_pos
    nn = len(text)
    depth = 0
    while i < nn:
        c = text[i]
        nc = clf.skip_comment(text, i)
        if nc is not None:
            i = nc
            continue
        nr = clf.skip_regex_literal(text, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            i = _skip_string(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return nn


def _find_matching_brace(text, open_pos, clf):
    i = open_pos
    nn = len(text)
    depth = 0
    while i < nn:
        c = text[i]
        nc = clf.skip_comment(text, i)
        if nc is not None:
            i = nc
            continue
        nr = clf.skip_regex_literal(text, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            i = _skip_string(text, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return nn


def scan_function_spans(text, clf):
    spans = []
    i = 0
    nn = len(text)
    in_str = None
    while i < nn:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        nc = clf.skip_comment(text, i)
        if nc is not None:
            i = nc
            continue
        nr = clf.skip_regex_literal(text, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        m = FN_START_RE.match(text, i)
        if m:
            name = m.group(1) or m.group(2) or m.group(3)
            paren_start = m.end() - 1
            paren_end = _find_matching_paren(text, paren_start, clf)
            brace_start = clf.skip_ws(text, paren_end)
            if brace_start < nn and text[brace_start] == "{":
                brace_end = _find_matching_brace(text, brace_start, clf)
                spans.append((m.start(), brace_start + 1, brace_end, name))
                i = brace_start + 1
                continue
        i += 1
    return spans


def find_escaper_candidates(text, clf):
    spans = scan_function_spans(text, clf)
    out = []
    for decl_start, body_start, body_end, name in spans:
        body = text[body_start:body_end]
        if AMP.search(body) and LT.search(body) and GT.search(body) and QUOT.search(body):
            line = text.count("\n", 0, decl_start) + 1
            out.append((name, line, bool(APOS.search(body))))
    return out


def check_canonical_escaper(text, clf):
    candidates = find_escaper_candidates(text, clf)
    errors = []
    if len(candidates) == 0:
        errors.append(
            "No function implements all four canonical HTML-escaping "
            "substitutions (& -> &amp;, < -> &lt;, > -> &gt;, \" -> &quot;)."
        )
    elif len(candidates) > 1:
        names = ", ".join(f"{n} (line {l})" for n, l, _ in candidates)
        errors.append(
            f"{len(candidates)} functions implement the full escaper "
            f"substitution set -- expected exactly one canonical escaper: {names}"
        )
    else:
        name, line, has_apos = candidates[0]
        if has_apos:
            errors.append(
                f"Canonical escaper {name!r} (line {line}) now also escapes "
                "a bare ' -- this breaks callers that apply their own "
                "quote-context escaping afterward."
            )
    return errors


def load_classifier_module():
    spec = importlib.util.spec_from_file_location(
        "g1_classifier", REPO_ROOT / "scripts" / "g1-innerhtml-sink-classifier.py"
    )
    clf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(clf)
    return clf


def format_slot(slot):
    function, target, op = slot
    return f"{function}():{target} {op}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--against", required=True,
        help="Path to the baseline JSON to compare against (file content '{}' means no prior baseline).",
    )
    parser.add_argument(
        "--current", default=str(CURRENT_JSON),
        help="Path to the current classification JSON (default: %(default)s).",
    )
    args = parser.parse_args()

    old_sinks = load_json(args.against)
    new_sinks = load_json(args.current)
    regressions, eliminated, new_slots = compare_slots(old_sinks, new_sinks)

    clf = load_classifier_module()
    escaper_errors = check_canonical_escaper(clf.text, clf)

    ok = True

    print(f"G1 XSS sink regression guard: {len(new_sinks)} current sinks, {len(old_sinks)} baseline sinks")
    print(f"  {len(eliminated)} slot(s) eliminated (OK)")

    if new_slots:
        print(f"  {len(new_slots)} brand-new slot(s) (reported, not auto-failed -- review manually):")
        for slot, tier in sorted(new_slots):
            print(f"    NEW   severity={tier}  {format_slot(slot)}")

    if regressions:
        ok = False
        print(f"  {len(regressions)} slot(s) REGRESSED:")
        for slot, old_tier, new_tier in sorted(regressions):
            print(f"    FAIL  severity {old_tier} -> {new_tier}  {format_slot(slot)}")

    if escaper_errors:
        ok = False
        print("  canonical escaper check FAILED:")
        for e in escaper_errors:
            print(f"    FAIL  {e}")
    else:
        print("  canonical escaper check OK (exactly one escaper, apostrophe not escaped)")

    if not ok:
        print("\nG1 regression guard: FAIL")
        return 1
    print("\nG1 regression guard: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scripts && python3 -m unittest test_g1_check_no_regression -v`
Expected: `OK` with 10 tests passing (2 `TestLoadJson`, 4 `TestCompareSlots`, 4 `TestCanonicalEscaperCheck` including the real-file integration test).

- [ ] **Step 5: Run it for real against Task 2's committed baseline (self-check)**

Run: `python3 scripts/g1-check-no-regression.py --against Assessment/G1_FINAL_CLASSIFICATION.json`
Expected: exit code `0`, `0 slot(s) REGRESSED`, `0 brand-new slot(s)` (comparing the committed baseline against itself), `canonical escaper check OK`.

- [ ] **Step 6: Commit**

```bash
git add scripts/g1-check-no-regression.py scripts/test_g1_check_no_regression.py
git commit -m "feat(security): add G1 CI regression guard (slot severity + canonical escaper check)"
git push
```

---

## Task 4: Wire into CI and verify a real run

**Files:**
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: Task 1's `scripts/g1-merge-classification.py`, Task 2's committed `Assessment/G1_FINAL_CLASSIFICATION.json`, Task 3's `scripts/g1-check-no-regression.py` and both tasks' `test_g1_*.py` suites.
- Produces: nothing further downstream — this is the last task.

- [ ] **Step 1: Add the new step**

The job sets `defaults.run.working-directory: orchestrator` for every step, but this new step's scripts and `Assessment/` paths live at the repo root — so it needs its own `working-directory: .` to escape that default (a step-level `working-directory` is resolved relative to `$GITHUB_WORKSPACE`, i.e. the repo root, regardless of the job default).

Edit `.github/workflows/test.yml`, inserting right after the `actions/checkout@v4` step (fails fast, before spending time on the Go toolchain):

```yaml
      - uses: actions/checkout@v4

      - name: G1 XSS sink regression guard
        working-directory: .
        run: |
          python3 scripts/g1-merge-classification.py
          git diff --exit-code Assessment/G1_FINAL_CLASSIFICATION.json Assessment/G1_FINAL_CLASSIFICATION.csv || \
            (echo "::error::Assessment/G1_FINAL_CLASSIFICATION.{json,csv} is stale -- run 'python3 scripts/g1-merge-classification.py' and commit the result." && exit 1)
          git fetch origin main --depth=1 2>/dev/null || true
          git show origin/main:Assessment/G1_FINAL_CLASSIFICATION.json > /tmp/g1_main_baseline.json 2>/dev/null || echo "{}" > /tmp/g1_main_baseline.json
          python3 scripts/g1-check-no-regression.py --against /tmp/g1_main_baseline.json
          cd scripts && python3 -m unittest test_g1_merge_classification test_g1_check_no_regression -v

      - uses: actions/setup-go@v5
        with:
          go-version-file: orchestrator/go.mod
```

Note: on a direct push to `main` itself, `origin/main` after the fetch *is* the commit under test, so the regression check degenerates to comparing the tree against itself (always 0 regressions) — this step's real value is on pull requests, where `origin/main` is the actual unmerged base. That's expected, not a bug.

- [ ] **Step 2: Verify the freshness check actually catches staleness (manual, local)**

Before trusting the CI step, prove the freshness check works: temporarily corrupt the committed JSON, confirm the exact command used in the YAML fails, then restore it.

Run:
```bash
cp Assessment/G1_FINAL_CLASSIFICATION.json /tmp/g1_backup.json
echo '[]' > Assessment/G1_FINAL_CLASSIFICATION.json
python3 scripts/g1-merge-classification.py
git diff --exit-code Assessment/G1_FINAL_CLASSIFICATION.json Assessment/G1_FINAL_CLASSIFICATION.csv
echo "exit code: $?"
cp /tmp/g1_backup.json Assessment/G1_FINAL_CLASSIFICATION.json
git checkout -- Assessment/G1_FINAL_CLASSIFICATION.csv
git status --porcelain Assessment/
```

Expected: `git diff --exit-code` prints a diff and `exit code: 1` (the corruption was detected), and after restoring, `git status --porcelain Assessment/` prints nothing (clean — the corruption didn't leak into a commit).

- [ ] **Step 3: Commit and push**

```bash
git add .github/workflows/test.yml
git commit -m "ci(security): add G1 XSS sink regression guard to the test workflow"
git push
```

- [ ] **Step 4: Watch the real GitHub Actions run**

Run: `gh run watch $(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')`

Expected: the run reaches the `G1 XSS sink regression guard` step and it's green, with log output showing `0 slot(s) REGRESSED`, `0 brand-new slot(s)` (comparing `origin/main` against itself, same reasoning as Step 1's note), `canonical escaper check OK`, and both `unittest` suites passing (16 tests total: 6 from Task 1 + 10 from Task 3). Read the actual log via `gh run view --log <run-id> --job <job-id>` if `gh run watch`'s summary doesn't show the step's stdout, to confirm the `git fetch origin main` line actually resolved `origin/main` rather than silently falling back to `{}` (a push-to-main event should always have `origin/main` fetchable, since it *is* the commit just pushed).

Do not consider this task done on local script success alone — this step's whole purpose (resolving the spec's open question about shallow-checkout `origin/main` availability) is only proven by a real green run.
