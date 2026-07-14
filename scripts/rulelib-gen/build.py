"""Entrypoint: runs load -> translate -> export -> validate against the
curated sigma_seed/ directory, scoped to techniques scenarios/*.yaml already
covers, and writes the bundle into internal/rulelib/ruledata/.

Usage:
    .venv/Scripts/python build.py [--sigma-dir sigma_seed] [--out ../../orchestrator/internal/rulelib/ruledata]

Re-run by hand whenever sigma_seed/ or scenarios/*.yaml changes — this is
never invoked by packaging/windows-build.ps1.
"""
import argparse
import datetime
import importlib.metadata
import os
import sys
from collections import Counter

from export import build_rule_record, write_bundle
from load_sigma import load_rules
from techniques import covered_techniques
from validate import ValidationError, validate_build

SCHEMA_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigma-dir", default=os.path.join(os.path.dirname(__file__), "sigma_seed"))
    parser.add_argument("--scenarios-dir", default=os.path.join(os.path.dirname(__file__), "..", "..", "scenarios"))
    parser.add_argument("--out", default=os.path.join(
        os.path.dirname(__file__), "..", "..", "orchestrator", "internal", "rulelib", "ruledata"))
    args = parser.parse_args()

    technique_ids = covered_techniques(args.scenarios_dir)
    print(f"scoped to {len(technique_ids)} technique(s) from {args.scenarios_dir}: {sorted(technique_ids)}")

    rules = load_rules(args.sigma_dir, technique_ids)
    print(f"loaded {len(rules)} matching Sigma rule(s) from {args.sigma_dir}")

    built = [build_rule_record(r, i + 1) for i, r in enumerate(rules)]

    backend_counts: Counter = Counter()
    translation_failures: list[dict] = []
    for record in built:
        for t in record["translations"]:
            backend_counts[t["backend"]] += 1
        for f in record["failures"]:
            translation_failures.append({"ruleId": record["id"], "sigmaId": record["sigmaId"], **f})

    all_techniques: set[str] = set()
    for record in built:
        all_techniques.update(record["techniqueIds"])

    metadata = {
        "schemaVersion": SCHEMA_VERSION,
        "generatorVersion": _version("pysigma"),
        "sigmaCommit": "n/a (curated sigma_seed/, not a SigmaHQ checkout)",
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ruleCount": len(built),
        "techniqueCount": len(all_techniques),
        "backends": dict(backend_counts),
        "translationFailures": translation_failures,
    }

    try:
        validate_build(built, known_technique_ids=technique_ids)
    except ValidationError as e:
        print(f"VALIDATION FAILED: {e}", file=sys.stderr)
        return 1

    write_bundle(args.out, built, metadata)
    print(f"wrote {len(built)} rule(s) to {args.out}")
    return 0


def _version(dist: str) -> str:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


if __name__ == "__main__":
    sys.exit(main())
