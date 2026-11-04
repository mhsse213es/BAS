"""Elasticsearch cannot apply a wildcard to an `ip`-typed field.

Checked on Elasticsearch 8.15 (staging): `destination.ip:127.*` answers HTTP 400 in strict mode ("Can only use
prefix queries on keyword, text and wildcard fields") and silently matches nothing in lenient mode, while a CIDR
(`"127.0.0.0/8"`) works. Sigma's startswith / contains on an address therefore needs rewriting.
"""
import re

_DROP = "\x00DROP\x00"

# <field ending in .ip>:<one value, or a parenthesised group of values>
_IP_FIELD_TERM = re.compile(r"(?P<field>(?:\w+\.)*ip):(?P<value>\([^()]*\)|[^\s()]+)")
_PREFIX_IP = re.compile(r"^(?P<octets>\d{1,3}(?:\.\d{1,3}){0,2})\.\*$")


class UnexpressibleOnIpField(Exception):
    """A condition on an ip field that no Elasticsearch query can express."""


def _rewrite_value(tok):
    """The replacement for one value: a new string, '' to drop it, or None to keep it as it is."""
    if "*" not in tok.replace("\\*", ""):
        return None
    m = _PREFIX_IP.match(tok)
    if m:
        octets = m.group("octets").split(".")
        return '"%s/%d"' % (".".join(octets + ["0"] * (4 - len(octets))), 8 * len(octets))
    # a wildcard value that is not an address prefix: it can only match text, and an ip field never holds text
    return ""


def fix_ip_wildcards(query):
    """Rewrite wildcards on `.ip` fields: an IPv4 prefix becomes a CIDR; a branch that can never be an address is
    dropped, which is exact because an ip field cannot hold it. A condition that is only such a branch raises
    UnexpressibleOnIpField rather than guessing."""

    def term(m):
        field, value = m.group("field"), m.group("value")
        if value.startswith("("):
            parts = re.split(r"\s+OR\s+", value[1:-1])
            kept = []
            for p in parts:
                r = _rewrite_value(p)
                if r is None:
                    kept.append(p)
                elif r:
                    kept.append(r)
            if not kept:
                raise UnexpressibleOnIpField(field)
            if kept == parts:
                return m.group(0)
            return "%s:(%s)" % (field, " OR ".join(kept))
        r = _rewrite_value(value)
        if r is None:
            return m.group(0)
        if r == "":
            return _DROP
        return "%s:%s" % (field, r)

    out = _IP_FIELD_TERM.sub(term, query)
    if _DROP in out:
        out = re.sub(r"\s+OR\s+" + re.escape(_DROP), "", out)
        out = re.sub(re.escape(_DROP) + r"\s+OR\s+", "", out)
        if _DROP in out:
            raise UnexpressibleOnIpField("ip")
    return out
