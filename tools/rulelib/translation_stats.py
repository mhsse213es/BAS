"""Measures how many applicable SigmaHQ rules convert to each backend, per tested technique.

Dev-time only. Applicable = a rule tagged with a technique Audspect's scenarios run (exact match, or the rule's
technique is the parent of a tested sub-technique). Uses the same pySigma backends as scripts/rulelib-gen, so the
numbers describe what the generator would actually produce.

    python tools/rulelib/translation_stats.py [--sigma tools/rulelib/sigma] [--json out.json] [--md out.md]
"""
import argparse
import glob
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts", "rulelib-gen"))

import yaml  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402

import coverage as cov  # noqa: E402
from translate import BACKENDS, translate_rule  # noqa: E402


def applicable_rules(sigma_dir, tested, trees):
    """[(path, doc)] of rules whose technique tags match a tested technique, exactly or via the parent."""
    tested_set = set(tested)
    parents = {t.split(".")[0] for t in tested_set if "." in t}
    out = []
    for tree in trees:
        for path in glob.glob(os.path.join(sigma_dir, tree, "**", "*.yml"), recursive=True):
            doc = yaml.safe_load(open(path, encoding="utf-8"))
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            if str(doc.get("status") or "").lower() in cov.EXCLUDED_STATUS:
                continue
            techs = cov.rule_techniques(doc)
            hit_exact = techs & tested_set
            hit_parent = {t for t in techs if t in parents and t not in tested_set}
            if hit_exact or hit_parent:
                out.append((path, doc, hit_exact, hit_parent))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma", default=os.path.join(HERE, "sigma"))
    ap.add_argument("--scenarios", default=os.path.join(ROOT, "scenarios"))
    ap.add_argument("--trees", default="rules")
    ap.add_argument("--json")
    ap.add_argument("--md")
    a = ap.parse_args()
    tested, _ = cov.tested_techniques(a.scenarios)
    rules = applicable_rules(a.sigma, tested, a.trees.split(","))
    print(f"{len(rules)} applicable rules; translating to {len(BACKENDS)} backends...", file=sys.stderr)

    ok = Counter(); fail = Counter(); reasons = defaultdict(Counter)
    per_tech = defaultdict(lambda: defaultdict(int))  # technique -> backend -> rules that translated
    all5 = 0
    for i, (path, doc, exact, parent) in enumerate(rules):
        try:
            rule = SigmaCollection.from_yaml(open(path, encoding="utf-8").read()).rules[0]
        except Exception as e:  # a rule pySigma cannot even parse: counted against every backend
            for b in BACKENDS:
                fail[b] += 1
                reasons[b]["parse: " + type(e).__name__] += 1
            continue
        translations, failures = translate_rule(rule)
        got = {t["backend"] for t in translations}
        for b in BACKENDS:
            if b in got:
                ok[b] += 1
                for t in exact | parent:
                    per_tech[t][b] += 1
            else:
                fail[b] += 1
        for f in failures:
            reasons[f["backend"]][f["reason"].split(":")[0] + ": " + f["reason"].split(":", 1)[-1].strip()[:70]] += 1
        if len(got) == len(BACKENDS):
            all5 += 1
        if (i + 1) % 200 == 0:
            print(f"  {i + 1}/{len(rules)}", file=sys.stderr)

    n = len(rules)
    rows = []
    for tid in sorted(tested):
        direct = [r for r in rules if tid in r[2]]
        via_parent = [r for r in rules if "." in tid and tid.split(".")[0] in r[3]]
        rows.append({"technique": tid, "exactRules": len(direct), "parentRules": len(via_parent),
                     "translated": {b: per_tech[tid].get(b, 0) for b in BACKENDS}})
    report = {"applicableRules": n, "translatedAll5": all5, "ok": dict(ok), "failed": dict(fail),
              "topFailures": {b: reasons[b].most_common(5) for b in BACKENDS}, "rows": rows}
    if a.json:
        json.dump(report, open(a.json, "w", encoding="utf-8"), indent=1)
    md = [f"- Applicable rules: **{n}**; convert to **all 5** backends: **{all5}** ({all5 * 100 // max(n, 1)}%)", "",
          "| Backend | Converted | Failed | Rate |", "|---|---:|---:|---:|"]
    for b in BACKENDS:
        md.append(f"| {b} | {ok[b]} | {fail[b]} | {ok[b] * 100 // max(n, 1)}% |")
    md += ["", "Most common failures per backend:"]
    for b in BACKENDS:
        md.append(f"- {b}: " + "; ".join(f"{c}x {r}" for r, c in reasons[b].most_common(3)))
    text = "\n".join(md) + "\n"
    if a.md:
        open(a.md, "w", encoding="utf-8").write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
