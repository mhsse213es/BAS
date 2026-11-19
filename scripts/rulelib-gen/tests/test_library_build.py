"""The full-library build: scope by what Audspect's scenarios actually run, read a nested SigmaHQ checkout, keep a
stable Audspect id per upstream rule, and carry provenance and licence on every rule."""
import json
import os
import textwrap

import pytest

from export import build_rule_record, write_bundle
from ids import assign_ids
from load_sigma import load_rules
from techniques import applicable_technique_ids
from techniques import tested_techniques as scenario_techniques
from validate import ValidationError, validate_build


def _w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(text))


RULE = """
    title: {title}
    id: {id}
    status: {status}
    author: Some Author
    date: 2020-01-02
    modified: 2024-05-06
    references:
        - https://example.com/ref
    tags:
        - attack.execution
        - attack.{tag}
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            Image|endswith: '\\cmd.exe'
        condition: selection
    level: medium
"""


def _rule(d, rel, id, tag, status="test", title="A rule"):
    _w(os.path.join(d, rel), RULE.format(id=id, tag=tag, status=status, title=title))


def test_tested_techniques_reads_every_step_of_every_scenario_recursively(tmp_path):
    _w(str(tmp_path / "a.yaml"), "steps:\n  - technique_id: T1059.001\n  - technique_id: T1003\n    detection_profiles: [p]\n")
    _w(str(tmp_path / "sub" / "b.yaml"), "steps:\n  - technique_id: T1486\n  - name: no technique\n")
    assert scenario_techniques(str(tmp_path)) == {"T1059.001", "T1003", "T1486"}


def test_applicable_ids_add_the_parent_of_a_tested_sub_technique():
    assert applicable_technique_ids({"T1059.001", "T1003"}) == {"T1059.001", "T1003", "T1059"}


def test_load_rules_reads_nested_folders_and_matches_exact_or_parent(tmp_path):
    _rule(str(tmp_path), "windows/process_creation/exact.yml", "00000000-0000-0000-0000-000000000001", "t1059.001")
    _rule(str(tmp_path), "windows/process_creation/parent.yml", "00000000-0000-0000-0000-000000000002", "t1059")
    _rule(str(tmp_path), "linux/other.yml", "00000000-0000-0000-0000-000000000003", "t1486")
    rules = load_rules(str(tmp_path), applicable_technique_ids({"T1059.001"}))
    assert sorted(str(r.id) for r in rules) == ["00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"]


def test_load_rules_skips_deprecated_and_unsupported_rules(tmp_path):
    _rule(str(tmp_path), "ok.yml", "00000000-0000-0000-0000-000000000001", "t1059.001")
    _rule(str(tmp_path), "old.yml", "00000000-0000-0000-0000-000000000002", "t1059.001", status="deprecated")
    _rule(str(tmp_path), "no.yml", "00000000-0000-0000-0000-000000000003", "t1059.001", status="unsupported")
    assert [str(r.id) for r in load_rules(str(tmp_path), {"T1059.001"})] == ["00000000-0000-0000-0000-000000000001"]


def test_load_rules_skips_a_file_it_cannot_parse_and_keeps_the_rest(tmp_path):
    _rule(str(tmp_path), "ok.yml", "00000000-0000-0000-0000-000000000001", "t1059.001")
    _w(str(tmp_path / "broken.yml"), "title: [unclosed\n")
    assert len(load_rules(str(tmp_path), {"T1059.001"})) == 1


def test_assign_ids_keeps_existing_ids_and_numbers_new_rules_after_the_highest():
    registry = {"sig-a": "AUDRULE-000007", "sig-b": "AUDRULE-000003"}
    ids, updated = assign_ids(["sig-b", "sig-new2", "sig-a", "sig-new1"], registry)
    assert ids["sig-a"] == "AUDRULE-000007" and ids["sig-b"] == "AUDRULE-000003"
    assert ids["sig-new1"] == "AUDRULE-000008" and ids["sig-new2"] == "AUDRULE-000009"  # new ones in sorted order
    assert updated["sig-new1"] == "AUDRULE-000008" and len(updated) == 4


def test_a_rule_keeps_its_upstream_facts_and_carries_provenance(tmp_path):
    _rule(str(tmp_path), "windows/x.yml", "00000000-0000-0000-0000-000000000009", "t1059.001", title="Original Title")
    rule = load_rules(str(tmp_path), {"T1059.001"})[0]
    source = {"name": "SigmaHQ", "url": "https://github.com/SigmaHQ/sigma", "commit": "abc123", "license": "DRL-1.1"}
    rec = build_rule_record(rule, "AUDRULE-000042", source=source, sigma_root=str(tmp_path))
    assert rec["id"] == "AUDRULE-000042" and rec["sigmaId"] == "00000000-0000-0000-0000-000000000009"
    assert rec["title"] == "Original Title" and rec["author"] == "Some Author"
    assert rec["references"] == ["https://example.com/ref"]
    assert rec["tags"] == ["attack.execution", "attack.t1059.001"]
    assert rec["date"] == "2020-01-02" and rec["modified"] == "2024-05-06"
    assert rec["source"]["commit"] == "abc123" and rec["source"]["license"] == "DRL-1.1"
    assert rec["source"]["path"] == "windows/x.yml"
    assert "Image|endswith" in rec["detection"]  # the raw upstream YAML, verbatim


def _vrule(**kw):
    base = {"id": "AUDRULE-000001", "sigmaId": "s1", "techniqueIds": ["T1059.001"], "translations": [{"backend": "splunk"}], "failures": []}
    base.update(kw)
    return base


def test_validate_tolerates_a_technique_newer_than_the_bundled_attack_data_when_another_is_known():
    validate_build([_vrule(techniqueIds=["T1059.001", "T1059.012"])], known_technique_ids={"T1059.001"})


def test_validate_still_rejects_a_rule_with_no_recognised_technique():
    with pytest.raises(ValidationError, match="unrecognized ATT&CK technique"):
        validate_build([_vrule(techniqueIds=["T9999.999"])], known_technique_ids={"T1059.001"})


def test_the_bundle_is_one_rule_per_line_and_loads_as_json(tmp_path):
    rules = [_vrule(id="AUDRULE-000001"), _vrule(id="AUDRULE-000002", sigmaId="s2")]
    write_bundle(str(tmp_path), rules, {"schemaVersion": 1})
    text = open(tmp_path / "rules.json", encoding="utf-8").read()
    assert json.loads(text) == rules
    assert text.count("\n") == len(rules) + 2  # "[", one line per rule, "]" plus the final newline
