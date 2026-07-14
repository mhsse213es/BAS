"""Stage 4 of the generator pipeline: assemble each SigmaRule + its
translations into the JSON shape internal/rulelib embeds, and write the
output files."""
import json
import os

from load_sigma import rule_technique_ids
from translate import translate_rule


def build_rule_record(rule, index: int) -> dict:
    translations, failures = translate_rule(rule)
    with open(rule.source.path, encoding="utf-8") as f:
        raw_yaml = f.read()
    return {
        "id": f"AUDRULE-{index:06d}",
        "sigmaId": str(rule.id),
        "title": rule.title,
        "description": rule.description or "",
        "techniqueIds": sorted(rule_technique_ids(rule)),
        "severity": str(rule.level) if rule.level else "",
        "status": str(rule.status) if rule.status else "",
        "author": rule.author or "",
        "references": [str(r) for r in rule.references],
        "falsePositives": [str(fp) for fp in rule.falsepositives],
        "logSource": {
            "category": rule.logsource.category or "",
            "product": rule.logsource.product or "",
            "service": rule.logsource.service or "",
        },
        "detection": raw_yaml,
        "translations": translations,
        "failures": failures,
    }


def write_bundle(out_dir: str, built_rules: list[dict], metadata: dict) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rules.json"), "w", encoding="utf-8") as f:
        json.dump(built_rules, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(os.path.join(out_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, sort_keys=True)
        f.write("\n")
