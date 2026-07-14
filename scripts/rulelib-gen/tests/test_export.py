import json
import os
import tempfile

from export import build_rule_record, write_bundle
from load_sigma import load_rules

SEED_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_seed")


def test_build_rule_record_shape():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    record = build_rule_record(rules[0], index=1)
    assert record["id"] == "AUDRULE-000001"
    assert record["title"] == "Suspicious PowerShell Encoded Command"
    assert record["techniqueIds"] == ["T1059.001"]
    assert record["severity"] == "medium"
    assert record["status"] == "stable"
    assert "detection" in record and "selection" in record["detection"]
    assert len(record["translations"]) == 5
    assert record["failures"] == []


def test_write_bundle_produces_valid_json_files():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    record = build_rule_record(rules[0], index=1)
    metadata = {
        "schemaVersion": 1, "generatorVersion": "test", "sigmaCommit": "n/a",
        "generatedAt": "2026-07-14T00:00:00Z", "ruleCount": 1, "techniqueCount": 1,
        "backends": {"splunk": 1}, "translationFailures": [],
    }
    with tempfile.TemporaryDirectory() as d:
        write_bundle(d, [record], metadata)
        with open(os.path.join(d, "rules.json")) as f:
            rules_out = json.load(f)
        with open(os.path.join(d, "metadata.json")) as f:
            meta_out = json.load(f)
    assert rules_out == [record]
    assert meta_out == metadata
