"""Stage 4 of the generator pipeline: assemble each SigmaRule + its
translations into the JSON shape internal/rulelib embeds, and write the
output files."""
import json
import os

from load_sigma import rule_technique_ids
from translate import translate_rule


def _iso(d) -> str:
    return d.isoformat() if d else ""


def build_rule_record(rule, rule_id: str | None = None, source: dict | None = None,
                      sigma_root: str | None = None, index: int | None = None) -> dict:
    """One library record. Upstream facts (id, title, author, dates, references, tags, the raw rule YAML) are
    carried unchanged; `source` is the provenance and licence of the checkout the rule came from."""
    translations, failures = translate_rule(rule)
    with open(rule.source.path, encoding="utf-8") as f:
        raw_yaml = f.read()
    path = str(rule.source.path)
    if sigma_root:
        path = os.path.relpath(path, sigma_root)
    rec_source = dict(source or {})
    rec_source["path"] = path.replace("\\", "/")
    return {
        "id": rule_id or f"AUDRULE-{index:06d}",
        "source": rec_source,
        "tags": [str(t) for t in rule.tags],
        "date": _iso(rule.date),
        "modified": _iso(rule.modified),
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
    # One rule per line: a library of thousands of rules stays diffable, and a regeneration changes only the
    # lines of the rules that changed.
    with open(os.path.join(out_dir, "rules.json"), "w", encoding="utf-8") as f:
        f.write("[\n" + ",\n".join(json.dumps(r, sort_keys=True, ensure_ascii=False) for r in built_rules) + "\n]\n")
    with open(os.path.join(out_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, sort_keys=True)
        f.write("\n")
