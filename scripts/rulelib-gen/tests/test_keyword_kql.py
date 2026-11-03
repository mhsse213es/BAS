"""Keyword rules on Sentinel: the Kusto backend emits a bare boolean expression, which is not a query. Microsoft documents
`search "a" and ("b" or "c")` for Sentinel; each term needs wildcards to keep Sigma's substring meaning (a bare term is a
whole-token match). Defender XDR is not in that page's list, so it stays generic."""
import textwrap

from sigma.collection import SigmaCollection

from translate import kql_search, translate_rule


def test_search_prefix_and_substring_wildcards_on_every_literal():
    assert kql_search('"new user" and ("GID=0," or "UID=0,")') == 'search "*new user*" and ("*GID=0,*" or "*UID=0,*")'
    assert kql_search('not "x"') == 'search not "*x*"'


def test_an_escaped_quote_inside_a_literal_is_kept_inside_it():
    assert kql_search(r'"say \"hi\"" or "b"') == r'search "*say \"hi\"*" or "*b*"'


def test_anything_that_is_not_only_literals_and_boolean_operators_is_refused():
    assert kql_search('Image =~ "cmd.exe"') is None
    assert kql_search('"a" and _=~@"x.*"') is None
    assert kql_search("") is None


def rule(detection, logsource="product: django\n        category: application"):
    return SigmaCollection.from_yaml(textwrap.dedent(f"""
    title: K
    id: 19191919-1919-1919-1919-191919191919
    status: test
    logsource:
        {logsource}
    detection:
        {detection}
        condition: selection
    level: low
""")).rules[0]


def by(r):
    return {t["backend"]: t for t in translate_rule(r)[0]}


def test_sentinel_gets_a_valid_search_query_and_says_how_to_scope_it():
    t = by(rule("selection:\n            - 'Traceback'\n            - 'SQL syntax'"))["microsoft_sentinel"]
    assert t["mapping"] == "keyword" and t["verification"] == "none" and t["pipeline"] == ""
    assert t["query"].startswith('search "*Traceback*"') and '"*SQL syntax*"' in t["query"]
    assert "search in (" in t["dataSource"]


def test_defender_and_crowdstrike_stay_generic_for_keyword_rules():
    t = by(rule("selection:\n            - 'Traceback'"))
    for b in ("microsoft_defender", "crowdstrike"):
        assert t[b]["mapping"] == "generic", b
