"""Measures how many SigmaHQ rules exist for the ATT&CK techniques Audspect's scenarios actually run.

Dev-time tool only. It reads a local SigmaHQ checkout and the scenarios/ folder; it never touches the network and
nothing here is shipped to a customer server. Run it before building anything on top of the rule library, so the
coverage the product can claim is measured, not assumed.

    python tools/rulelib/coverage.py [--sigma tools/rulelib/sigma] [--scenarios scenarios]
                                     [--json out.json] [--md out.md]

Matching is reported three ways, because they mean different things to an analyst:
  exact       a rule is tagged with the very technique id the scenario runs
  via-sub     the scenario runs a parent technique (T1059); a rule covers one of its sub-techniques (T1059.001)
  via-parent  the scenario runs a sub-technique; the only rule is tagged with its parent technique
Only exact matches are "directly applicable". The other two are listed so the gap is visible, never hidden.
"""
import argparse
import datetime
import glob
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

import yaml

TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TAG_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)

# SigmaHQ's trees. "rules" is the main, stable set; the others are narrower collections. Reported separately so the
# release can choose what to ship instead of inheriting everything.
TREES = ["rules", "rules-emerging-threats", "rules-threat-hunting", "rules-compliance", "rules-dfir"]
EXCLUDED_STATUS = {"deprecated", "unsupported"}


def tested_techniques(scenarios_dir):
    """technique_id of every step in every scenario YAML under scenarios_dir (recursive)."""
    all_t, profiled = defaultdict(set), set()
    for path in glob.glob(os.path.join(scenarios_dir, "**", "*.yaml"), recursive=True):
        try:
            doc = yaml.safe_load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for step in doc.get("steps") or []:
            if not isinstance(step, dict):
                continue
            tid = str(step.get("technique_id") or "").strip().upper()
            if TECH_RE.match(tid):
                all_t[tid].add(os.path.relpath(path, scenarios_dir).replace("\\", "/"))
                if step.get("detection_profiles"):
                    profiled.add(tid)
    return all_t, profiled


def rule_techniques(rule):
    out = set()
    for tag in rule.get("tags") or []:
        m = TAG_RE.match(str(tag))
        if m:
            out.add("T" + m.group(1) + ("." + m.group(2) if m.group(2) else ""))
    return out


def load_sigma(sigma_dir):
    """{tree: [ {id,title,status,level,product,techniques,path} ]} for every non-deprecated rule."""
    out = {}
    for tree in TREES:
        rules = []
        for path in glob.glob(os.path.join(sigma_dir, tree, "**", "*.yml"), recursive=True):
            try:
                doc = yaml.safe_load(open(path, encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            status = str(doc.get("status") or "").lower()
            if status in EXCLUDED_STATUS:
                continue
            rules.append({
                "id": str(doc.get("id") or ""), "title": str(doc.get("title") or ""), "status": status,
                "level": str(doc.get("level") or ""), "product": str((doc.get("logsource") or {}).get("product") or ""),
                "techniques": sorted(rule_techniques(doc)), "path": os.path.relpath(path, sigma_dir).replace("\\", "/"),
            })
        out[tree] = rules
    return out


def classify(tid, by_technique):
    """('exact'|'via-sub'|'via-parent'|'none', [rule ids])"""
    if tid in by_technique:
        return "exact", by_technique[tid]
    if "." not in tid:
        subs = sorted(t for t in by_technique if t.startswith(tid + "."))
        if subs:
            return "via-sub", sorted({r for t in subs for r in by_technique[t]})
    else:
        parent = tid.split(".")[0]
        if parent in by_technique:
            return "via-parent", by_technique[parent]
    return "none", []


def measure(sigma_dir, scenarios_dir, trees):
    tested, profiled = tested_techniques(scenarios_dir)
    rules_by_tree = load_sigma(sigma_dir)
    by_tech = defaultdict(list)
    used = []
    for tree in trees:
        for r in rules_by_tree.get(tree, []):
            used.append(r)
            for t in r["techniques"]:
                by_tech[t].append(r["id"])
    rows = []
    for tid in sorted(tested):
        kind, ids = classify(tid, by_tech)
        rows.append({"technique": tid, "match": kind, "rules": len(ids), "profiled": tid in profiled,
                     "scenarios": sorted(tested[tid])[:5], "scenarioCount": len(tested[tid])})
    counts = Counter(r["match"] for r in rows)
    return {"trees": trees, "rulesConsidered": len(used), "testedTechniques": len(rows),
            "profiledTechniques": len(profiled), "counts": dict(counts), "rows": rows,
            "ruleCountsByTree": {t: len(v) for t, v in rules_by_tree.items()}}


def git_commit(path):
    try:
        return subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def markdown(report, commit):
    n = report["testedTechniques"]
    c = report["counts"]
    pct = lambda k: f"{(c.get(k, 0) * 100.0 / n):.0f}%" if n else "0%"
    lines = [
        "# Sigma rule coverage for Audspect's tested techniques", "",
        f"Measured {datetime.date.today().isoformat()} against SigmaHQ commit `{commit}`.",
        f"Trees counted: {', '.join(report['trees'])}. Deprecated and unsupported rules are excluded.", "",
        f"- Techniques Audspect's scenarios run: **{n}** ({report['profiledTechniques']} of them have a detection profile)",
        f"- Rules considered: **{report['rulesConsidered']}**", "",
        "| Match | Techniques | Share | Meaning |", "|---|---:|---:|---|",
        f"| exact | {c.get('exact', 0)} | {pct('exact')} | a rule is tagged with the technique the scenario runs |",
        f"| via-sub | {c.get('via-sub', 0)} | {pct('via-sub')} | scenario runs a parent technique; rules exist only for its sub-techniques |",
        f"| via-parent | {c.get('via-parent', 0)} | {pct('via-parent')} | scenario runs a sub-technique; the rule is tagged with the parent only |",
        f"| none | {c.get('none', 0)} | {pct('none')} | no Sigma rule: shown as \"no rule available\", never invented |", "",
        "Only **exact** matches are directly applicable. The other two are listed so the gap stays visible.", "",
        "## Techniques with no Sigma rule", "",
    ]
    none = [r for r in report["rows"] if r["match"] == "none"]
    lines += [f"- {r['technique']} ({r['scenarioCount']} scenario file(s))" for r in none] or ["- none"]
    return "\n".join(lines) + "\n"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma", default=os.path.join(here, "sigma"))
    ap.add_argument("--scenarios", default=os.path.join(root, "scenarios"))
    ap.add_argument("--trees", default="rules", help="comma-separated SigmaHQ trees to count")
    ap.add_argument("--json")
    ap.add_argument("--md")
    a = ap.parse_args()
    trees = [t for t in a.trees.split(",") if t]
    report = measure(a.sigma, a.scenarios, trees)
    commit = git_commit(a.sigma)
    report["sigmaCommit"] = commit
    md = markdown(report, commit)
    if a.json:
        json.dump(report, open(a.json, "w", encoding="utf-8"), indent=1)
    if a.md:
        open(a.md, "w", encoding="utf-8").write(md)
    sys.stdout.write(md)


if __name__ == "__main__":
    main()
