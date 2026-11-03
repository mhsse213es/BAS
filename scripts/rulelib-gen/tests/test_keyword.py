"""Keyword-scoped: a rule with no field conditions at all is a free-text search of the raw log message. For Splunk and
Elastic (where a plain text search is valid) it is labelled keyword, with the log it belongs to; it needs no field mapping
and claims none. Every other backend stays generic."""
import textwrap

from sigma.collection import SigmaCollection

from translate import is_keyword_only, translate_rule


def rule_for(logsource, detection):
    ls = "\n".join(f"        {k}: {v}" for k, v in logsource.items())
    return SigmaCollection.from_yaml(textwrap.dedent(f"""
    title: K
    id: 18181818-1818-1818-1818-181818181818
    status: test
    logsource:
{ls}
    detection:
        {detection}
        condition: selection
    level: low
""")).rules[0]


KEYWORDS = "selection:\n            - 'Traceback'\n            - 'SQL syntax'"
FIELDED = "selection:\n            message|contains: 'Traceback'"


def by(rule):
    return {t["backend"]: t for t in translate_rule(rule)[0]}


def test_keyword_only_detection():
    assert is_keyword_only(rule_for({"product": "django", "category": "application"}, KEYWORDS))
    assert not is_keyword_only(rule_for({"product": "django", "category": "application"}, FIELDED))


def test_keyword_rule_is_labelled_for_splunk_and_elastic_with_its_log_and_no_schema_claim():
    t = by(rule_for({"product": "django", "category": "application"}, KEYWORDS))
    for b in ("splunk", "elastic", "microsoft_sentinel"):
        assert t[b]["mapping"] == "keyword" and t[b]["pipeline"] == "" and t[b]["verification"] == "none", b
        assert "django" in t[b]["dataSource"].lower() and "Traceback" in t[b]["query"], b
    for b in ("microsoft_defender", "crowdstrike"):
        assert t[b]["mapping"] == "generic" and t[b]["dataSource"] == "", b


def test_a_fielded_rule_is_never_keyword_and_a_mapped_family_keeps_its_pipeline():
    assert by(rule_for({"product": "django", "category": "application"}, FIELDED))["splunk"]["mapping"] == "generic"
    cisco = by(rule_for({"product": "cisco", "service": "aaa"}, KEYWORDS))
    assert cisco["splunk"]["mapping"] == "pipeline"
