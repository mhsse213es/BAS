"""Entrypoint: load -> translate -> export -> validate, writing the bundle into internal/rulelib/ruledata/.

Full library (the normal run), from the pinned SigmaHQ checkout made by tools/rulelib/fetch_sigma.sh:

    python build.py --sigma-dir ../../tools/rulelib/sigma/rules --sigma-root ../../tools/rulelib/sigma

Scope is every ATT&CK technique any Audspect scenario step runs (plus the parent of a tested sub-technique), so the
library never carries rules for techniques the product cannot test. Each rule keeps a stable AUDRULE id through
id_registry.json (commit it: ids are never reused), and carries the upstream facts unchanged plus provenance and
licence. Deprecated and unsupported rules are left out. Nothing is fetched here; this is a dev-time tool and is
never invoked by packaging.

The old curated seed run still works: omit the flags and it reads sigma_seed/.
"""
import argparse
import datetime
import importlib.metadata
import json
import os
import sys
from collections import Counter

from export import build_rule_record, write_bundle
from ids import assign_ids
from load_sigma import load_rules
from techniques import applicable_technique_ids, tested_techniques
from validate import ValidationError, validate_build

SCHEMA_VERSION = 2  # 2: records carry tags, dates and source provenance; translations carry mapping and data source

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SIGMA_URL = "https://github.com/SigmaHQ/sigma"
ATTRIBUTION = ("Detection rules are from the SigmaHQ project (https://github.com/SigmaHQ/sigma), licensed under the "
               "Detection Rule License (DRL) 1.1. Each rule keeps its original author, title, id and references; "
               "the per-SIEM queries are generated from the rule by Audspect.")


def _version(dist: str) -> str:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _known_attack_ids() -> set[str]:
    path = os.path.join(ROOT, "orchestrator", "internal", "reporting", "attackdata", "attack_enrichment.json")
    with open(path, encoding="utf-8") as f:
        return set(json.load(f).keys())


def _load_registry(path: str, existing_rules_json: str) -> dict[str, str]:
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    # First full run: keep the ids the shipped seed rules already have.
    if os.path.exists(existing_rules_json):
        with open(existing_rules_json, encoding="utf-8") as f:
            return {r["sigmaId"]: r["id"] for r in json.load(f)}
    return {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigma-dir", default=os.path.join(HERE, "sigma_seed"))
    parser.add_argument("--sigma-root", default="", help="SigmaHQ checkout root (for provenance paths and commit)")
    parser.add_argument("--sigma-commit", default="")
    parser.add_argument("--scenarios-dir", default=os.path.join(ROOT, "scenarios"))
    parser.add_argument("--registry", default=os.path.join(HERE, "id_registry.json"))
    parser.add_argument("--out", default=os.path.join(ROOT, "orchestrator", "internal", "rulelib", "ruledata"))
    args = parser.parse_args()

    full = bool(args.sigma_root)
    commit = args.sigma_commit
    if full and not commit:
        with open(os.path.join(ROOT, "tools", "rulelib", "SIGMA_COMMIT"), encoding="utf-8") as f:
            commit = f.read().strip()

    tested = tested_techniques(args.scenarios_dir)
    technique_ids = applicable_technique_ids(tested)
    print(f"scoped to {len(tested)} tested technique(s) ({len(technique_ids)} with parents) from {args.scenarios_dir}")

    rules = load_rules(args.sigma_dir, technique_ids)
    print(f"loaded {len(rules)} matching Sigma rule(s) from {args.sigma_dir}")
    if full:
        # A rule id must be unique: SigmaHQ guarantees it, a corrupt checkout might not.
        seen: dict[str, str] = {}
        for r in rules:
            if str(r.id) in seen:
                print(f"VALIDATION FAILED: duplicate Sigma id {r.id} in {r.source.path} and {seen[str(r.id)]}", file=sys.stderr)
                return 1
            seen[str(r.id)] = str(r.source.path)

    registry = _load_registry(args.registry, os.path.join(args.out, "rules.json"))
    id_for, registry = assign_ids([str(r.id) for r in rules], registry)

    source = None
    if full:
        source = {"name": "SigmaHQ", "url": SIGMA_URL, "commit": commit, "license": "DRL-1.1",
                  "licenseUrl": "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"}
    rules.sort(key=lambda r: id_for[str(r.id)])
    built = []
    for i, r in enumerate(rules):
        built.append(build_rule_record(r, id_for[str(r.id)], source=source, sigma_root=args.sigma_root or None))
        if (i + 1) % 250 == 0:
            print(f"  translated {i + 1}/{len(rules)}")

    backend_counts: Counter = Counter()
    mapping_counts: Counter = Counter()
    translation_failures: list[dict] = []
    for record in built:
        for t in record["translations"]:
            backend_counts[t["backend"]] += 1
            mapping_counts[f"{t['backend']}:{t['mapping']}"] += 1
        for f in record["failures"]:
            translation_failures.append({"ruleId": record["id"], "sigmaId": record["sigmaId"], **f})

    all_techniques: set[str] = set()
    for record in built:
        all_techniques.update(record["techniqueIds"])
    known = _known_attack_ids() if full else technique_ids
    unrecognized = sorted(t for t in all_techniques if t not in known)

    metadata = {
        "schemaVersion": SCHEMA_VERSION,
        "generatorVersion": _version("pysigma"),
        "sigmaCommit": commit if full else "n/a (curated sigma_seed/, not a SigmaHQ checkout)",
        "sourceLicense": "DRL-1.1" if full else "",
        "attribution": ATTRIBUTION if full else "",
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ruleCount": len(built),
        "techniqueCount": len(all_techniques),
        "testedTechniqueCount": len(tested),
        "backends": dict(backend_counts),
        "mappings": dict(mapping_counts),
        "unrecognizedTechniqueIds": unrecognized,
        "translationFailures": translation_failures,
    }

    try:
        validate_build(built, known_technique_ids=known)
    except ValidationError as e:
        print(f"VALIDATION FAILED: {e}", file=sys.stderr)
        return 1

    write_bundle(args.out, built, metadata)
    with open(args.registry, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=0, sort_keys=True)
        f.write("\n")
    print(f"wrote {len(built)} rule(s) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
