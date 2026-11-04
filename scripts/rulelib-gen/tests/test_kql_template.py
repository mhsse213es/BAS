"""A generic Sentinel or Defender query is a bare predicate (`Field =~ "x" and ...`), which is not a KQL query. It is wrapped as
a template with an explicit <Table> placeholder and a comment, so it cannot be mistaken for something ready to paste.
Mapped and keyword queries are never wrapped."""
import textwrap

from sigma.collection import SigmaCollection

from translate import kql_template, translate_rule


def test_a_bare_predicate_becomes_a_commented_table_template():
    out = kql_template('Provider_Name =~ "X" and EventID == 33205')
    lines = out.split("\n")
    assert lines[0].startswith("//") and "<Table>" in lines[0]
    assert "<Table>" in lines and lines[lines.index("<Table>") + 1] == '| where Provider_Name =~ "X" and EventID == 33205'


def test_the_predicate_is_kept_verbatim_including_multiline():
    pred = 'A == 1 and\n  (B contains "x" or C =~ "y")'
    assert kql_template(pred).endswith("| where " + pred)


def rule(logsource, detection):
    ls = "\n".join(f"        {k}: {v}" for k, v in logsource.items())
    return SigmaCollection.from_yaml(textwrap.dedent(f"""
    title: T
    id: 20202020-2020-2020-2020-202020202020
    status: test
    logsource:
{ls}
    detection:
        {detection}
        condition: selection
    level: low
""")).rules[0]


def by(r):
    return {t["backend"]: t for t in translate_rule(r)[0]}


def test_generic_kusto_translations_are_templates_and_other_backends_are_untouched():
    t = by(rule({"product": "fortigate", "service": "event"}, "selection:\n            action: login"))
    for b in ("microsoft_sentinel", "microsoft_defender"):
        assert t[b]["mapping"] == "generic" and "<Table>" in t[b]["query"] and "| where" in t[b]["query"], b
    assert "<Table>" not in t["splunk"]["query"] and "<Table>" not in t["elastic"]["query"]


def test_mapped_and_keyword_kusto_queries_are_never_wrapped():
    mapped = by(rule({"product": "windows", "category": "process_creation"}, "selection:\n            Image|endswith: '\\\\cmd.exe'"))
    assert "<Table>" not in mapped["microsoft_sentinel"]["query"]
    kw = by(rule({"product": "django", "category": "application"}, "selection:\n            - 'Traceback'"))
    assert kw["microsoft_sentinel"]["query"].startswith("search ")
