"""Elasticsearch DSL translation of a Sigma rule.

A Lucene `query_string` cannot ask for case-insensitive matching, and Sigma matches case-insensitively, so a
Lucene query on a `keyword` field matches only when the event's case equals the rule's. The DSL term, prefix and
wildcard queries take `case_insensitive: true`, so this translation preserves Sigma's semantics where the Lucene one
cannot. The Lucene query is still shipped, unchanged, for compatibility.

The input is a rule that has already been through the same processing pipeline as the Lucene translation, so field
names agree between the two. The condition tree is the one pySigma's own backends read, which keeps the boolean
structure (AND, OR, NOT, grouping) identical to the rule.

What is deliberately not translated (Unsupported: the rule keeps its Lucene query and gets no DSL):
  - regular expressions: Elasticsearch's regexp is Lucene syntax and anchored, not Sigma's PCRE search;
  - free-text keyword searches, which rely on the analysers of every field rather than one named field;
  - field-to-field comparisons.
Nothing here lowercases a value: that would not make a keyword field case-insensitive.
"""
import ipaddress
import json
import re


class Unsupported(Exception):
    """A part of the rule this translation does not express."""


_PREFIX_IP = re.compile(r"^(?P<octets>\d{1,3}(?:\.\d{1,3}){0,2})\.$")


def _is_ip_field(name):
    return name == "ip" or name.endswith(".ip")


def _split(sigma_string):
    """(literal text without wildcards, 'none'|'prefix'|'general', escaped ES wildcard pattern)."""
    from sigma.types import SpecialChars
    parts = sigma_string.s
    pattern = []
    literal = []
    specials = []
    for i, part in enumerate(parts):
        if isinstance(part, str):
            literal.append(part)
            pattern.append(re.sub(r"([\\*?])", r"\\\1", part))
        else:
            specials.append((i, part))
            pattern.append("*" if part == SpecialChars.WILDCARD_MULTI else "?")
    text = "".join(literal)
    if not specials:
        return text, "none", "".join(pattern)
    if len(specials) == 1 and specials[0][0] == len(parts) - 1 and specials[0][1] == SpecialChars.WILDCARD_MULTI:
        return text, "prefix", "".join(pattern)
    return text, "general", "".join(pattern)


def _ip_leaf(field, sigma_string):
    text, kind, _ = _split(sigma_string)
    if kind == "none":
        return {"term": {field: text}}
    m = _PREFIX_IP.match(text)
    if kind == "prefix" and m:
        octets = m.group("octets").split(".")
        return {"term": {field: "%s/%d" % (".".join(octets + ["0"] * (4 - len(octets))), 8 * len(octets))}}
    # any other text condition can never be met by an address
    return {"match_none": {}}


def _nonascii_variants(text):
    """`case_insensitive` folds ASCII letters only (Elasticsearch 8.15: `Ä` does not match `ä`). For a value with
    cased letters outside ASCII, also match them all upper-cased and all lower-cased, so a rule written in either
    form matches either. A mixed-case spelling of those letters is not covered."""
    def conv(fn):
        return "".join(fn(c) if ord(c) > 127 else c for c in text)
    out = []
    for cand in (text, conv(str.upper), conv(str.lower)):
        if cand not in out:
            out.append(cand)
    return out


def _string_clause(field, text, kind, pattern):
    if kind == "none" and text == "":
        # `term ""` never matches in Elasticsearch, with or without case_insensitive. An empty string is a field that
        # exists but has no character. Reliable on keyword and text fields; the `wildcard` field type cannot express it.
        return {"bool": {"filter": [{"exists": {"field": field}}], "must_not": [{"wildcard": {field: {"value": "?*"}}}]}}
    if kind == "prefix" and text == "":
        return {"exists": {"field": field}}  # startswith '' holds for any value
    if kind == "none":
        mk = lambda t, p: {"term": {field: {"value": t, "case_insensitive": True}}}
    elif kind == "prefix":
        mk = lambda t, p: {"prefix": {field: {"value": t, "case_insensitive": True}}}
    else:
        mk = lambda t, p: {"wildcard": {field: {"value": p, "case_insensitive": True}}}
    variants = _nonascii_variants(pattern if kind == "general" else text)
    if len(variants) == 1:
        return mk(text, pattern)
    if kind == "general":
        kids = [mk(None, v) for v in variants]
    else:
        kids = [mk(v, None) for v in variants]
    return {"bool": {"should": kids, "minimum_should_match": 1}}


def _leaf(node):
    from sigma.conditions import ConditionFieldEqualsValueExpression
    from sigma.types import (SigmaString, SigmaNumber, SigmaBool, SigmaNull, SigmaRegularExpression,
                             SigmaCIDRExpression, SigmaFieldReference, SigmaExists, SigmaCompareExpression,
                             SigmaExpansion)
    if not isinstance(node, ConditionFieldEqualsValueExpression):
        raise Unsupported("free-text keyword search")
    return _value(node.field, node.value)


def _value(field, v):
    from sigma.types import (SigmaString, SigmaNumber, SigmaBool, SigmaNull, SigmaRegularExpression,
                             SigmaCIDRExpression, SigmaFieldReference, SigmaExists, SigmaCompareExpression,
                             SigmaExpansion)
    if isinstance(v, SigmaExpansion):
        # equivalent spellings (windash, base64 offsets): any one of them satisfies the condition
        kids = [_value(field, x) for x in v.values]
        return kids[0] if len(kids) == 1 else {"bool": {"should": kids, "minimum_should_match": 1}}
    if isinstance(v, SigmaString):
        if _is_ip_field(field):
            return _ip_leaf(field, v)
        return _string_clause(field, *_split(v))
    if isinstance(v, SigmaNumber):
        return {"term": {field: {"value": v.number}}}
    if isinstance(v, SigmaBool):
        return {"term": {field: {"value": bool(v.boolean)}}}
    if isinstance(v, SigmaNull):
        return {"bool": {"must_not": [{"exists": {"field": field}}]}}
    if isinstance(v, SigmaExists):
        leaf = {"exists": {"field": field}}
        return leaf if v.exists else {"bool": {"must_not": [leaf]}}
    if isinstance(v, SigmaCIDRExpression):
        return {"term": {field: str(ipaddress.ip_network(v.cidr, strict=False))}}
    if isinstance(v, SigmaCompareExpression):
        op = (v.op.name if hasattr(v.op, "name") else str(v.op)).lower()
        if op not in ("gt", "gte", "lt", "lte"):
            raise Unsupported("comparison operator %s" % op)
        return {"range": {field: {op: v.number.number}}}
    if isinstance(v, SigmaRegularExpression):
        raise Unsupported("regular expression")
    if isinstance(v, SigmaFieldReference):
        raise Unsupported("field-to-field comparison")
    raise Unsupported("value type %s" % type(v).__name__)


def _node(node):
    from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT
    if isinstance(node, ConditionAND):
        kids = [_node(a) for a in node.args]
        return kids[0] if len(kids) == 1 else {"bool": {"filter": kids}}
    if isinstance(node, ConditionOR):
        kids = [_node(a) for a in node.args]
        return kids[0] if len(kids) == 1 else {"bool": {"should": kids, "minimum_should_match": 1}}
    if isinstance(node, ConditionNOT):
        return {"bool": {"must_not": [_node(node.args[0])]}}
    return _leaf(node)


def tree_to_dsl(tree):
    """Compact JSON text of {"query": ...} for a resolved condition tree. Raises Unsupported."""
    return json.dumps({"query": _node(tree)}, separators=(",", ":"), sort_keys=True)


def rule_to_dsl(rule):
    """DSL for a SigmaRule that has already been through the translation's processing pipeline."""
    cond = rule.detection.parsed_condition[0]
    return tree_to_dsl(cond.parsed.postprocess(rule.detection, cond))
