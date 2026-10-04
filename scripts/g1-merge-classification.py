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
