"""Elasticsearch DSL translation of a Sigma rule, which unlike a Lucene query_string can ask for case-insensitive
matching (`case_insensitive: true`). Structure only here; behaviour against Elasticsearch is in esvalidate.py."""
import json

import pytest
from sigma.collection import SigmaCollection

from elastic_dsl import Unsupported, rule_to_dsl


def dsl(detection: str, condition: str = "sel") -> dict:
    yml = "title: t\nstatus: test\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n" + detection + "  condition: " + condition + "\n"
    rule = SigmaCollection.from_yaml(yml).rules[0]
    return json.loads(rule_to_dsl(rule))["query"]


def test_equals_is_a_case_insensitive_term():
    q = dsl("  sel:\n    process.name: Cmd.exe\n")
    assert q == {"term": {"process.name": {"value": "Cmd.exe", "case_insensitive": True}}}


def test_startswith_is_a_prefix():
    q = dsl("  sel:\n    process.name|startswith: Cmd\n")
    assert q == {"prefix": {"process.name": {"value": "Cmd", "case_insensitive": True}}}


def test_contains_and_endswith_are_wildcards():
    assert dsl("  sel:\n    f|contains: abc\n") == {"wildcard": {"f": {"value": "*abc*", "case_insensitive": True}}}
    assert dsl("  sel:\n    f|endswith: .exe\n") == {"wildcard": {"f": {"value": "*.exe", "case_insensitive": True}}}


def test_literal_wildcard_characters_are_escaped():
    # Sigma: \? is a literal question mark and \ a literal backslash; a bare ? is a wildcard
    literal = dsl("  sel:\n    f|contains: 'a\\?b\\\\c'\n")
    assert literal["wildcard"]["f"]["value"] == "*a\\?b\\\\c*"
    wild = dsl("  sel:\n    f|contains: 'a?b'\n")
    assert wild["wildcard"]["f"]["value"] == "*a?b*"


def test_and_or_not_keep_their_shape():
    q = dsl("  a:\n    f: one\n  b:\n    g: two\n  c:\n    h: three\n", "a and (b or c) and not c")
    assert set(q) == {"bool"}
    assert "filter" in q["bool"]
    kinds = [list(x)[0] for x in q["bool"]["filter"]]
    assert kinds.count("bool") == 2  # the OR group and the NOT
    groups = [x["bool"] for x in q["bool"]["filter"] if "bool" in x]
    assert any("must_not" in g for g in groups)
    assert any(g.get("minimum_should_match") == 1 for g in groups)


def test_numbers_and_comparisons_are_not_marked_case_insensitive():
    assert dsl("  sel:\n    event.code: 4688\n") == {"term": {"event.code": {"value": 4688}}}
    assert dsl("  sel:\n    n|gt: 5\n") == {"range": {"n": {"gt": 5}}}


def test_null_and_exists():
    assert dsl("  sel:\n    f: null\n") == {"bool": {"must_not": [{"exists": {"field": "f"}}]}}
    assert dsl("  sel:\n    f|exists: true\n") == {"exists": {"field": "f"}}


def test_ip_field_prefix_becomes_cidr_and_text_matches_nothing():
    assert dsl("  sel:\n    destination.ip|startswith: '127.'\n") == {"term": {"destination.ip": "127.0.0.0/8"}}
    assert dsl("  sel:\n    source.ip|contains: '-'\n") == {"match_none": {}}
    assert dsl("  sel:\n    source.ip: 10.0.0.0/8\n") == {"term": {"source.ip": "10.0.0.0/8"}}


def test_regex_keyword_and_field_reference_are_not_translated():
    for det in ("  sel:\n    f|re: 'a.*b'\n", "  sel:\n    - 'free text'\n", "  sel:\n    f|fieldref: g\n"):
        with pytest.raises(Unsupported):
            dsl(det)


def _translations(detection: str):
    import translate
    yml = ("title: t\nstatus: test\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n" + detection)
    rule = SigmaCollection.from_yaml(yml).rules[0]
    trs, _ = translate.translate_rule(rule)
    return {t["backend"]: t for t in trs}


def test_translate_rule_adds_a_dsl_only_to_the_field_mapped_elastic_translation():
    by = _translations("  sel:\n    Image|endswith: '.exe'\n  condition: sel\n")
    assert by["elastic"]["mapping"] == "pipeline"
    assert by["elastic"]["query"]  # the Lucene query is still there, unchanged
    dsl_doc = json.loads(by["elastic"]["dsl"])
    assert "case_insensitive" in by["elastic"]["dsl"] and "query" in dsl_doc
    for other in ("splunk", "microsoft_sentinel", "crowdstrike"):
        assert "dsl" not in by[other]


def test_a_regex_rule_under_ecs_windows_is_not_shipped_as_a_corrupt_query_and_has_no_dsl():
    # pySigma's ecs_windows pipeline turns a regex value into the text of a Python object; that query can never match,
    # so the Elastic translation is recorded as a failure rather than shipped, and there is nothing to add a DSL to.
    by = _translations("  sel:\n    CommandLine|re: 'a.*b'\n  condition: sel\n")
    assert "elastic" not in by


def test_empty_string_is_an_existing_field_with_no_characters():
    # `term ""` never matches in Elasticsearch, so the condition is spelled as exists-and-not-one-character
    q = dsl("  sel:\n    f: ''\n")
    assert q == {"bool": {"filter": [{"exists": {"field": "f"}}], "must_not": [{"wildcard": {"f": {"value": "?*"}}}]}}


def test_startswith_empty_string_holds_for_any_value():
    assert dsl("  sel:\n    f|startswith: ''\n") == {"exists": {"field": "f"}}


def test_non_ascii_letters_also_match_upper_and_lower_case():
    # Elasticsearch's case_insensitive folds ASCII only, so the other cases of non-ASCII letters are added
    q = dsl("  sel:\n    f|contains: 'Järjest'\n")
    values = sorted(c["wildcard"]["f"]["value"] for c in q["bool"]["should"])
    assert values == ["*JÄrjest*", "*Järjest*"]  # ASCII letters are left to case_insensitive; only ä/Ä is added
    assert all(c["wildcard"]["f"]["case_insensitive"] for c in q["bool"]["should"])
    assert q["bool"]["minimum_should_match"] == 1


def test_pure_ascii_value_gets_no_extra_variants():
    assert dsl("  sel:\n    f: Abc\n") == {"term": {"f": {"value": "Abc", "case_insensitive": True}}}
