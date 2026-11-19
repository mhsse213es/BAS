"""Translate a Sigma (PCRE-style, unanchored "search") regular expression to an Elasticsearch `regexp` query value.

Elasticsearch's regexp is Lucene syntax: the pattern must match the WHOLE value, `\\s \\d \\w \\b` do not exist (`\\s` is
a literal `s`), and `@ & ~ < > # "` are operators. So the pattern is rewritten, not passed through:
  - `.*` is put on each side unless the pattern is anchored with `^` / `$`;
  - `\\s \\S \\d \\D \\w \\W` become character classes, `\\n \\t \\r` become the character, `(?:` becomes `(`;
  - a leading `(?i)` (or the rule's `i` flag) becomes `case_insensitive: true`;
  - Lucene operator characters are escaped; `.` becomes `[^\\n]` (PCRE's dot) unless the rule has the `s` flag;
  - a `?` after a quantifier (lazy) is dropped: for a yes/no search it matches the same values.
Anything else (lookaround, `\\b`, back-references, `\\x..`, inline flags, `^`/`$` in the middle, the `m` flag) raises
Unsupported, so the rule gets no regex DSL rather than a wrong one.
"""
import re


class Unsupported(Exception):
    pass


_WS = " \t\n\r\f\v"
_CLASS = {"s": _WS, "d": "0-9", "w": "a-zA-Z0-9_"}
_NEG = {"S": "s", "D": "d", "W": "w"}
_CTRL = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v"}
_LUCENE_OPS = set('@&~<>#"')
_BOUNDED_THEN_MORE = re.compile(r"(?:\[\^(?:\\.|[^\]\\])*\]|(?<!\\)\.)\{\d*,(?:3[2-9]|[4-9]\d|\d{3,})\}(?!\$|\)*$)")
_QUANT = re.compile(r"\{\d+(?:,\d*)?\}")


def _lit(c):
    return "\\" + c if c in _LUCENE_OPS else c


def _other_case(lits):
    """Elasticsearch's case_insensitive does not reach inside [...]: add the other case of each letter and letter range."""
    extra, k = [], 0
    while k < len(lits):
        c = lits[k]
        if c and k + 2 < len(lits) and lits[k + 1] == "-" and lits[k + 2] and c.isalpha() and lits[k + 2].isalpha():
            lo, hi = c, lits[k + 2]
            if lo.islower() == hi.islower():
                extra.append(lo.swapcase() + "-" + hi.swapcase())
            k += 3
            continue
        if c and c.isalpha() and c.isascii():
            extra.append(c.swapcase())
        k += 1
    return "".join(extra)


def to_lucene(pattern, ignorecase=False, multiline=False, dotall=False, query_string=False):
    """Return (value, case_insensitive) for an Elasticsearch regexp query.

    With query_string=True the value is for a Lucene `field:/.../` regex: a slash is escaped, and because that syntax
    has no case flag, case-insensitivity is written into the pattern as letter classes ([aA]) and False is returned."""
    if multiline:
        raise Unsupported("multi-line flag")
    p = pattern
    if p.startswith("(?i)"):
        p, ignorecase = p[4:], True
    start_anchor = p.startswith("^")
    if start_anchor:
        p = p[1:]
    elif _BOUNDED_THEN_MORE.search(p):
        # `.*X[^"]{0,64}Y`: a long bounded repeat of a class that overlaps what follows, behind an unanchored prefix,
        # makes Lucene's automaton explode (checked on Elasticsearch 8.15.3: HTTP 400 even at 200,000 states)
        raise Unsupported("bounded repeat of 32 or more of a negated class, followed by more pattern, in an unanchored regex")
    end_anchor = False
    if p.endswith("$") and not p.endswith("\\$"):
        p, end_anchor = p[:-1], True
    out, i, n = [], 0, len(p)
    last_quant = False  # the previous token was a quantifier (so a following `?` is lazy)
    while i < n:
        c = p[i]
        if c == "\\":
            if i + 1 >= n:
                raise Unsupported("trailing backslash")
            e = p[i + 1]
            i += 2
            if e in _CLASS:
                out.append("[" + _CLASS[e] + "]")
            elif e in _NEG:
                out.append("[^" + _CLASS[_NEG[e]] + "]")
            elif e in _CTRL:
                out.append(_CTRL[e])
            elif e.isalnum():
                raise Unsupported("escape \\" + e)
            else:
                out.append("\\" + e)  # an escaped punctuation character is that character in both syntaxes
            last_quant = False
        elif c == "[":
            j, body = i + 1, ["["]
            if j < n and p[j] == "^":
                body.append("^")
                j += 1
            first = True
            lits = []  # plain characters in order (None where an escape sits), to add the other case under (?i)
            while j < n and (p[j] != "]" or first):
                d = p[j]
                first = False
                if d == "\\":
                    if j + 1 >= n:
                        raise Unsupported("trailing backslash")
                    e = p[j + 1]
                    j += 2
                    lits.append(None)
                    if e in _CLASS:
                        body.append(_CLASS[e])
                    elif e in _CTRL:
                        body.append(_CTRL[e])
                    elif e.isalnum():
                        raise Unsupported("escape \\" + e + " in a class")
                    else:
                        body.append("\\" + e)
                elif d == "[":
                    raise Unsupported("nested or POSIX class")
                else:
                    body.append(_lit(d))
                    lits.append(d)
                    j += 1
            if j >= n:
                raise Unsupported("unterminated class")
            if ignorecase:
                body.append(_other_case(lits))
            body.append("]")
            out.append("".join(body))
            i = j + 1
            last_quant = False
        elif c == "(":
            if p.startswith("(?:", i):
                out.append("(")
                i += 3
            elif p.startswith("(?", i):
                raise Unsupported("group construct " + p[i:i + 3])
            else:
                out.append("(")
                i += 1
            last_quant = False
        elif c == ")" or c == "|":
            prev = out[-1] if out else "("
            # Lucene rejects an empty alternative, `(a|)` or `(|a)`: spell the empty string `()`
            if (c == "|" and prev in ("(", "|")) or (c == ")" and prev == "|"):
                out.append("()")
            out.append(c)
            i += 1
            last_quant = False
        elif c in "*+":
            if last_quant:
                raise Unsupported("possessive or doubled quantifier")
            out.append(c)
            i += 1
            last_quant = True
        elif c == "?":
            if last_quant:
                i += 1  # lazy marker: same yes/no answer
                last_quant = False
            else:
                out.append("?")
                i += 1
                last_quant = True
        elif c == "{":
            m = _QUANT.match(p, i)
            if not m or last_quant:
                raise Unsupported("brace that is not a quantifier")
            out.append(m.group(0))
            i = m.end()
            last_quant = True
        elif c in "^$":
            raise Unsupported("anchor inside the pattern")
        elif c == ".":
            out.append("." if dotall else "[^\n]")
            i += 1
            last_quant = False
        else:
            if query_string and ignorecase and c.isascii() and c.isalpha():
                out.append("[" + c.lower() + c.upper() + "]")
            else:
                out.append("\\/" if query_string and c == "/" else _lit(c))
            i += 1
            last_quant = False
    if query_string:
        ignorecase = False
    body = "(" + "".join(out) + ")"  # grouped so a top-level `a|b` stays one operand
    return ("" if start_anchor else ".*") + body + ("" if end_anchor else ".*"), ignorecase


# a field-qualified regex in a Lucene query_string: name:/body/ (a slash inside is escaped)
_QS_REGEX = re.compile(r"(?P<field>[\w.@-]+):/(?P<body>(?:\\.|[^/\\])*)/")


def pad_query_regexes(query):
    """Rewrite every `field:/regex/` in a Lucene query so it searches (Sigma semantics) instead of matching the whole
    value. Raises Unsupported for a regex Lucene cannot express."""
    def one(m):
        value, _ = to_lucene(m.group("body"), query_string=True)
        return "%s:/%s/" % (m.group("field"), value)
    return _QS_REGEX.sub(one, query)


# ---- recovering regexes that a pySigma pipeline turns into text -------------------------------------------------
# pySigma's `ecs_windows` pipeline stringifies a regex value into "SigmaRegularExpression(regexp=...)". The regex is
# swapped for a placeholder word before the pipeline runs and put back afterwards, in the Lucene text and the DSL.
_PLACEHOLDER = re.compile(r"\bAUDRX(\d+)\b")


def protect_regexes(rule):
    """Return (copy of the rule with each regex value replaced by a placeholder, {placeholder: SigmaRegularExpression})."""
    import copy
    from sigma.rule import SigmaDetection
    from sigma.types import SigmaRegularExpression, SigmaString
    rule = copy.deepcopy(rule)
    found = {}

    def walk(det):
        for item in det.detection_items:
            if isinstance(item, SigmaDetection):
                walk(item)
                continue
            for k, val in enumerate(item.value):
                if isinstance(val, SigmaRegularExpression):
                    name = "AUDRX%d" % len(found)
                    found[name] = val
                    item.value[k] = SigmaString(name)
    for det in rule.detection.detections.values():
        walk(det)
    return rule, found


def restore_query_regexes(query, found):
    """Put the regexes back into a Lucene query (`field:AUDRX0` -> `field:/padded regex/`)."""
    from sigma.types import SigmaRegularExpressionFlag as Flag

    def one(m):
        rx = found["AUDRX" + m.group(1)]
        flags = set(rx.flags or ())
        value, _ = to_lucene(rx.to_plain(), ignorecase=Flag.IGNORECASE in flags, multiline=Flag.MULTILINE in flags,
                             dotall=Flag.DOTALL in flags, query_string=True)
        return "/" + value + "/"
    return _PLACEHOLDER.sub(one, query)
