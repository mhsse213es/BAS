"""Tests the shipped Elastic (Lucene) queries against a real Elasticsearch.

Two phases, so the Elasticsearch password never has to leave the server that holds it:

  python esvalidate.py gen  <rules.json> <cases.json>      build test cases (runs anywhere pySigma is installed)
  python esvalidate.py run  <cases.json> <results.json>    run them (stdlib only; reads ES_URL, ES_USER, ES_PASS)
  python esvalidate.py report <results.json> <report.md>   summarise

What a result means, and what it does not:

  Each case takes a rule, applies the same processing pipeline the generator used, and builds events from the
  resulting detection: a positive event that satisfies it, a benign negative, and (where the rule has a
  `not filter` clause) a filtered negative. The shipped query must match the positive and miss the negatives
  when Elasticsearch evaluates it. PASS therefore proves the query is valid and logically equivalent to the rule
  under the test mapping (all strings `keyword`, `*.ip` as `ip`). It does NOT prove that a collector emits the
  field names the pipeline produced: that stays with the rule's `verification` value, which this tool never
  changes. UNTESTABLE means no event could be built honestly (a regular expression, a field comparison, a
  conflicting constraint...), and says why. Nothing is counted as tested unless Elasticsearch evaluated it.
"""
import base64
import copy
import fnmatch
import ipaddress
import json
import os
import re
import sys
import urllib.request

SENTINEL = "zz-benign-value-zz"

# A pySigma object's repr in a query (the Lucene backend escapes its parenthesis). Events are built from the same
# rule as the query, so a corrupt query can still match them: this must be checked on the text itself.
LEAKED_OBJECT = re.compile(r"Sigma(?:String|RegularExpression|Number|Bool|CIDR|Null|Expansion|Placeholder|Query)\\?\(|SpecialChars\.")


# --------------------------------------------------------------------------------------------------------------
# gen: build events from a rule
# --------------------------------------------------------------------------------------------------------------

class Untestable(Exception):
    pass


def _pattern_text(sigma_string, fill="x"):
    """A concrete string matching a SigmaString pattern: wildcards become `fill`."""
    from sigma.types import SpecialChars
    out = []
    for part in sigma_string.s:
        if isinstance(part, str):
            out.append(part)
        elif part == SpecialChars.WILDCARD_MULTI:
            out.append(fill)
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append(fill)
        else:
            out.append(fill)
    return "".join(out)


def _regex_of(sigma_string, ci=True):
    from sigma.types import SpecialChars
    rx = ""
    for part in sigma_string.s:
        if isinstance(part, str):
            rx += re.escape(part)
        elif part == SpecialChars.WILDCARD_MULTI:
            rx += ".*"
        else:
            rx += "."
    return re.compile("^" + rx + "$", (re.IGNORECASE if ci else 0) | re.DOTALL)


def _solve_field(constraints):
    """One value for a field that must satisfy every constraint (SigmaString patterns), or Untestable."""
    if len(constraints) == 1:
        return _pattern_text(constraints[0])
    candidates = [_pattern_text(c) for c in constraints]
    # patterns of the form *literal* can be satisfied together by joining their literals
    literals = []
    for c in constraints:
        text = _pattern_text(c, fill="")
        literals.append(text)
    candidates.append("x".join(literals))
    candidates.append("".join(literals))
    for cand in candidates:
        # case-sensitive on purpose: the event must also match in a keyword field, which is
        if all(_regex_of(c, ci=False).match(cand) for c in constraints):
            return cand
    raise Untestable("two conditions on the same field cannot be satisfied by one value")


def _leaf_constraint(node):
    """('field', name, kind, payload) for a leaf of the resolved condition tree."""
    from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionValueExpression
    from sigma.types import (SigmaString, SigmaNumber, SigmaBool, SigmaNull, SigmaRegularExpression,
                             SigmaCIDRExpression, SigmaFieldReference, SigmaExists, SigmaCompareExpression)
    if isinstance(node, ConditionValueExpression):
        v = node.value
        if isinstance(v, SigmaString):
            return ("field", "message", "str", v)
        raise Untestable("keyword search on a non-string value")
    if not isinstance(node, ConditionFieldEqualsValueExpression):
        raise Untestable("condition element %s is not supported by the test" % type(node).__name__)
    f, v = node.field, node.value
    from sigma.types import SigmaExpansion
    if isinstance(v, SigmaExpansion):
        v = v.values[0]  # an expansion lists equivalent spellings (windash, base64 offsets): any one satisfies it
    if isinstance(v, SigmaString):
        if f == "ip" or f.endswith(".ip"):
            # an ip field only holds addresses: build a real one, or refuse the branch
            text = _pattern_text(v, fill="")
            m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){0,2})\.$", text)
            if m and "*" in str(v):
                parts = m.group(1).split(".")
                return ("field", f, "lit", ".".join(parts + ["1"] * (4 - len(parts))))
            if not re.match(r"^[0-9a-fA-F.:]+$", text):
                raise Untestable("a text condition on the ip field %s cannot be met by an address" % f)
        return ("field", f, "str", v)
    if isinstance(v, SigmaNumber):
        return ("field", f, "lit", str(v.number))
    if isinstance(v, SigmaBool):
        return ("field", f, "lit", "true" if v.boolean else "false")
    if isinstance(v, SigmaNull):
        return ("field", f, "null", None)
    if isinstance(v, SigmaCIDRExpression):
        net = ipaddress.ip_network(v.cidr, strict=False)
        return ("field", f, "lit", str(net.network_address + 1 if net.num_addresses > 2 else net.network_address))
    if isinstance(v, SigmaExists):
        return ("field", f, "exists" if v.exists else "null", None)
    if isinstance(v, SigmaCompareExpression):
        n = v.number.number
        op = v.op.name if hasattr(v.op, "name") else str(v.op)
        step = {"GT": n + 1, "GTE": n, "LT": n - 1, "LTE": n}.get(op.upper())
        if step is None:
            raise Untestable("comparison operator %s" % op)
        return ("field", f, "lit", str(step))
    if isinstance(v, SigmaRegularExpression):
        raise Untestable("regular-expression value: no event is generated from a regex")
    if isinstance(v, SigmaFieldReference):
        raise Untestable("field-to-field comparison")
    raise Untestable("value type %s" % type(v).__name__)


def _satisfy(node, polarity=True):
    """Constraints (list of leaf tuples) for an event that makes `node` true. NOT subtrees are left
    unconstrained in the positive event (an absent field does not match). Raises Untestable."""
    from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT
    if isinstance(node, ConditionAND):
        out = []
        for a in node.args:
            out += _satisfy(a)
        return out
    if isinstance(node, ConditionOR):
        last = None
        for a in node.args:
            try:
                return _satisfy(a)
            except Untestable as e:
                last = e
        raise last or Untestable("empty OR")
    if isinstance(node, ConditionNOT):
        return []
    return [_leaf_constraint(node)]


def _build_event(constraints):
    by_field = {}
    absent = set()
    for _, f, kind, payload in constraints:
        if kind == "null":
            absent.add(f)
        elif kind == "exists":
            by_field.setdefault(f, []).append(("lit", "x"))
        elif kind == "lit":
            by_field.setdefault(f, []).append(("lit", payload))
        else:
            by_field.setdefault(f, []).append(("str", payload))
    event = {}
    for f, cs in by_field.items():
        if f in absent:
            raise Untestable("field required both present and empty")
        lits = [c[1] for c in cs if c[0] == "lit"]
        strs = [c[1] for c in cs if c[0] == "str"]
        if lits and (len(set(lits)) > 1):
            raise Untestable("two different literal values required for one field")
        if lits and strs:
            if not all(_regex_of(s).match(lits[0]) for s in strs):
                raise Untestable("literal and pattern conflict on one field")
            event[f] = lits[0]
        elif lits:
            event[f] = lits[0]
        else:
            event[f] = _solve_field(strs)
    return event


def _not_children(node, acc):
    from sigma.conditions import ConditionAND, ConditionNOT
    if isinstance(node, ConditionAND):
        for a in node.args:
            _not_children(a, acc)
    elif isinstance(node, ConditionNOT):
        acc.append(node.args[0])


def _leaves(node, acc):
    from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT
    if isinstance(node, (ConditionAND, ConditionOR, ConditionNOT)):
        for a in node.args:
            _leaves(a, acc)
    else:
        acc.append(node)


def _eval(node, event):
    """Does `event` satisfy the resolved condition tree? Raises Untestable for a leaf it cannot judge."""
    from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    _, f, kind, payload = _leaf_constraint(node)
    present = f in event and event[f] not in (None, "")
    if kind == "null":
        return not present
    if kind == "exists":
        return present
    if not present:
        return False
    if kind == "lit":
        return str(event[f]) == str(payload)
    return bool(_regex_of(payload).match(str(event[f])))


def _make_avoid(tree, event):
    """Add values so that no `not` clause of the rule matches `event`, using fields the rule's positive part leaves
    free. Returns the adjusted event, or raises Untestable."""
    nots = []
    _not_children(tree, nots)
    ev = dict(event)
    for child in nots:
        if not _eval(child, ev):
            continue
        leaves = []
        _leaves(child, leaves)
        for leaf in leaves:
            try:
                _, f, kind, _p = _leaf_constraint(leaf)
            except Untestable:
                continue
            if f not in ev and kind != "null":
                ev[f] = "zz-other-value"
        if _eval(child, ev):
            raise Untestable("cannot build an event that avoids one of the rule's filters")
    return ev


def build_case(rule_entry, rule, tree):
    case = {"id": rule_entry["id"], "title": rule_entry["title"]}
    try:
        base = _satisfy(tree)
        positive = _build_event(base)
        if not positive:
            raise Untestable("the rule requires no field values")
        positive = _make_avoid(tree, positive)
        if not _eval(tree, positive):
            raise Untestable("the event built for this rule does not satisfy it by the tool's own check")
    except Untestable as e:
        case["untestable"] = str(e)
        return case
    case["positive"] = positive
    negatives = [{"kind": "benign", "event": {k: SENTINEL for k in positive}}]
    # events that would match a `not` clause must be rejected even though the positive part matches
    nots = []
    _not_children(tree, nots)
    case["filterNegatives"] = 0
    for child in nots:
        try:
            extra = _satisfy(child)
            ev = _build_event(base + extra)
            # a filtered event must satisfy the filter and so fail the rule
            if _eval(child, ev) and not _eval(tree, ev):
                negatives.append({"kind": "filtered", "event": ev})
                case["filterNegatives"] += 1
        except Untestable:
            continue
    case["negatives"] = negatives
    # informational: Sigma matching is case-insensitive, an Elasticsearch keyword field is not
    case["caseVariant"] = {k: (v.upper() if isinstance(v, str) else v) for k, v in positive.items()}
    case["dslEvents"] = _dsl_events(positive, negatives)
    return case


def _is_ip_field(name):
    return name == "ip" or name.endswith(".ip")


def _recase(event, fn):
    return {k: (fn(v) if isinstance(v, str) and not _is_ip_field(k) else v) for k, v in event.items()}


def _dsl_events(positive, negatives):
    """Events for the DSL test. Sigma is case-insensitive, so the positive must match in its own case, upper-cased
    and lower-cased; a benign event must not; an event that satisfies a filter must not, in its own case or
    differing only in case."""
    pos = [("exact", positive), ("upper", _recase(positive, str.upper)), ("lower", _recase(positive, str.lower))]
    neg = [(n["kind"], n["event"]) for n in negatives]
    neg += [("filtered-upper", _recase(n["event"], str.upper)) for n in negatives if n["kind"] == "filtered"]
    return {"pos": [{"label": a, "event": b} for a, b in pos], "neg": [{"label": a, "event": b} for a, b in neg]}


def gen(rules_path, out_path, backend="elastic"):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from sigma.collection import SigmaCollection
    import translate as t
    from elastic_dsl import Unsupported, rule_to_dsl
    with open(rules_path, encoding="utf-8") as f:
        data = json.load(f)
    rules = data if isinstance(data, list) else data.get("rules", data)
    spec = t.BACKENDS[backend]
    cases = []
    for r in rules:
        tr = next((x for x in r.get("translations", []) if x["backend"] == backend and x["mapping"] in ("pipeline", "keyword")), None)
        if tr is None:
            continue
        entry = {"id": r["id"], "title": r["title"]}
        try:
            rule = SigmaCollection.from_yaml(r["detection"]).rules[0]
            family = t.log_source_family(rule)
            mapping = spec.mappings.get(family) if family else None
            if tr["mapping"] == "pipeline" and mapping:
                mapping.pipeline().apply(rule)
            cond = rule.detection.parsed_condition[0]
            tree = cond.parsed.postprocess(rule.detection, cond)
            case = build_case(entry, rule, tree)
            if tr["mapping"] == "pipeline":
                if tr.get("dsl"):
                    case["dsl"] = tr["dsl"]  # exactly what ships
                else:
                    try:
                        rule_to_dsl(rule)
                        case["dslUnsupported"] = "not generated"
                    except Unsupported as e:
                        case["dslUnsupported"] = str(e)
        except Exception as e:  # noqa: BLE001 - a rule the tool cannot read is reported, never skipped silently
            case = {"id": r["id"], "title": r["title"], "untestable": "could not build events: %s" % str(e)[:160]}
        cidr_fields = sorted({m.group(1) for m in re.finditer(r"([\w.]+):\(?[^\s)]*\/\d+", tr["query"]) if not m.group(1).endswith("ip")})
        case.update({"query": tr["query"], "mapping": tr["mapping"], "verification": tr.get("verification", ""),
                     "cidrOnNonIp": cidr_fields})
        cases.append(case)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"backend": backend, "cases": cases}, f)
    testable = sum(1 for c in cases if "positive" in c)
    print("cases=%d with_events=%d untestable_at_build=%d" % (len(cases), testable, len(cases) - testable))


# --------------------------------------------------------------------------------------------------------------
# run: evaluate in a real Elasticsearch (standard library only)
# --------------------------------------------------------------------------------------------------------------

class ES:
    def __init__(self):
        self.url = os.environ["ES_URL"].rstrip("/")
        auth = base64.b64encode(("%s:%s" % (os.environ["ES_USER"], os.environ["ES_PASS"])).encode()).decode()
        self.headers = {"Authorization": "Basic " + auth, "Content-Type": "application/json"}

    def call(self, method, path, body=None, ndjson=False):
        data = None
        if body is not None:
            data = body.encode() if ndjson else json.dumps(body).encode()
        hdr = dict(self.headers)
        if ndjson:
            hdr["Content-Type"] = "application/x-ndjson"
        req = urllib.request.Request(self.url + path, data=data, headers=hdr, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"error": raw.decode(errors="replace")[:300]}


def _stringify(event):
    return {k: (v if isinstance(v, str) else str(v)) for k, v in event.items()}


def run(cases_path, out_path):
    es = ES()
    with open(cases_path, encoding="utf-8") as f:
        payload = json.load(f)
    cases = payload["cases"]
    index = "audspect-ruletest-%d" % os.getpid()
    status, _ = es.call("PUT", "/" + index, {
        "settings": {"index.mapping.total_fields.limit": 100000, "number_of_shards": 1, "number_of_replicas": 0,
                     "index.mapping.ignore_malformed": True},
        "mappings": {"dynamic_templates": [
            {"ips": {"match_mapping_type": "string", "path_match": "*.ip", "mapping": {"type": "ip", "ignore_malformed": True}}},
            {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}]}})
    if status >= 300:
        raise SystemExit("could not create the scratch index: %s" % status)
    results = []
    try:
        # index every event once, remembering its document id
        docs = []  # (case index, label, doc id, event)
        for i, c in enumerate(cases):
            if "positive" not in c:
                continue
            docs.append((i, "positive", c["positive"]))
            for j, n in enumerate(c["negatives"]):
                docs.append((i, "neg%d:%s" % (j, n["kind"]), n["event"]))
            docs.append((i, "case", c["caseVariant"]))
        ids = {}
        indexed_ok = {}
        batch, meta = [], []
        def flush():
            nonlocal batch, meta
            if not batch:
                return
            st, resp = es.call("POST", "/_bulk?refresh=false", "".join(batch), ndjson=True)
            for item, m in zip(resp.get("items", []), meta):
                r = item.get("index", {})
                indexed_ok[m] = (r.get("status", 500) < 300, r.get("error", {}).get("reason", "")[:140] if r.get("error") else "")
            batch, meta = [], []
        for n, (i, label, ev) in enumerate(docs):
            key = "%d|%s" % (i, label)
            batch.append(json.dumps({"index": {"_index": index, "_id": key}}) + "\n" + json.dumps(_stringify(ev)) + "\n")
            meta.append(key)
            if len(batch) >= 500:
                flush()
        flush()
        es.call("POST", "/%s/_refresh" % index)
        for i, c in enumerate(cases):
            res = {"id": c["id"], "title": c["title"], "mapping": c["mapping"], "verification": c["verification"]}
            if "positive" not in c:
                res.update(status="UNTESTABLE", reason=c.get("untestable", "no events"))
                results.append(res)
                continue
            if LEAKED_OBJECT.search(c["query"]):
                res.update(status="FAIL", failure="corrupt", reason="the query contains a leaked pySigma object")
                results.append(res)
                continue
            q = {"query_string": {"query": c["query"], "analyze_wildcard": True}}
            st, v = es.call("GET", "/%s/_validate/query?explain=true" % index, {"query": q})
            if st >= 300 or v.get("valid") is False:
                reason = (v.get("explanations") or [{}])[0].get("error") or v.get("error", {}).get("reason") if isinstance(v.get("error"), dict) else None
                res.update(status="FAIL", reason="Elasticsearch rejected the query: %s" % str(reason or v)[:220], failure="syntax")
                results.append(res)
                continue

            def matches(label):
                key = "%d|%s" % (i, label)
                ok, why = indexed_ok.get(key, (False, "not indexed"))
                if not ok:
                    return None, why
                st2, r = es.call("GET", "/%s/_search" % index, {"size": 0, "terminate_after": 1, "query": {"bool": {"filter": [{"ids": {"values": [key]}}, q]}}})
                if st2 >= 300:
                    return None, "search failed"
                tot = r.get("hits", {}).get("total", {})
                return (tot.get("value", 0) > 0), ""

            pos, why = matches("positive")
            if pos is None:
                res.update(status="UNTESTABLE", reason="the positive event could not be indexed: %s" % why)
                results.append(res)
                continue
            fp = []
            for j, n in enumerate(c["negatives"]):
                m, _ = matches("neg%d:%s" % (j, n["kind"]))
                if m:
                    fp.append(n["kind"])
            case_hit, _ = matches("case")
            res["caseSensitive"] = (case_hit is False)
            res["filterNegatives"] = c.get("filterNegatives", 0)
            if not pos:
                res.update(status="FAIL", reason="the query did not match an event built from the rule", failure="missed")
            elif fp and c.get("cidrOnNonIp"):
                res.update(status="UNTESTABLE", reason="a CIDR filter on %s only works if the collector types that field as ip; "
                           "the test cannot know that" % ", ".join(c["cidrOnNonIp"]))
            elif fp:
                res.update(status="FAIL", reason="the query matched a benign/filtered event: %s" % ",".join(fp), failure="false_positive")
            else:
                res.update(status="PASS", reason="")
            results.append(res)
    finally:
        es.call("DELETE", "/" + index)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"backend": payload["backend"], "results": results}, f)
    from collections import Counter
    print(Counter(r["status"] for r in results))


# --------------------------------------------------------------------------------------------------------------
# rundsl: the DSL translation against Elasticsearch, per field mapping
# --------------------------------------------------------------------------------------------------------------

def _index_body(field_type):
    return {
        "settings": {"index.mapping.total_fields.limit": 100000, "number_of_shards": 1, "number_of_replicas": 0,
                     "index.mapping.ignore_malformed": True},
        "mappings": {"dynamic_templates": [
            {"ips": {"match_mapping_type": "string", "path_match": "*.ip", "mapping": {"type": "ip", "ignore_malformed": True}}},
            {"strings": {"match_mapping_type": "string", "mapping": {"type": field_type}}}]}}


def rundsl(cases_path, out_path, field_type):
    """field_type is the Elasticsearch type every string field gets: keyword, wildcard or text."""
    es = ES()
    with open(cases_path, encoding="utf-8") as f:
        cases = json.load(f)["cases"]
    index = "audspect-dsltest-%s-%d" % (field_type, os.getpid())
    st, resp = es.call("PUT", "/" + index, _index_body(field_type))
    if st >= 300:
        raise SystemExit("could not create the scratch index: %s %s" % (st, resp))
    results = []
    try:
        batch, keys = [], []
        for i, c in enumerate(cases):
            if "dsl" not in c or "dslEvents" not in c:
                continue
            for group in ("pos", "neg"):
                for n, e in enumerate(c["dslEvents"][group]):
                    key = "%d|%s|%d" % (i, group, n)
                    batch.append(json.dumps({"index": {"_index": index, "_id": key}}) + "\n" + json.dumps(_stringify(e["event"])) + "\n")
                    keys.append(key)
                    if len(batch) >= 500:
                        es.call("POST", "/_bulk?refresh=false", "".join(batch), ndjson=True)
                        batch = []
        if batch:
            es.call("POST", "/_bulk?refresh=false", "".join(batch), ndjson=True)
        es.call("POST", "/%s/_refresh" % index)
        for i, c in enumerate(cases):
            res = {"id": c["id"], "title": c["title"], "fieldType": field_type, "verification": c["verification"]}
            if c["mapping"] != "pipeline":
                res.update(status="NO_DSL", reason="keyword-only rule: relies on every field's analyser, so it keeps its Lucene query")
            elif "dsl" not in c:
                res.update(status="NO_DSL", reason="not translated: %s" % c.get("dslUnsupported", "no events could be built"))
            elif "dslEvents" not in c:
                res.update(status="UNTESTABLE", reason=c.get("untestable", "no events"))
            else:
                if LEAKED_OBJECT.search(c["dsl"]):
                    res.update(status="FAIL", failure="corrupt", reason="the DSL contains a leaked pySigma object")
                    results.append(res)
                    continue
                query = json.loads(c["dsl"])["query"]
                problems = []
                inconclusive = []
                skipped = 0
                evaluated = True
                for group in ("pos", "neg"):
                    for n, e in enumerate(c["dslEvents"][group]):
                        key = "%d|%s|%d" % (i, group, n)
                        if field_type == "wildcard" and group == "neg" and e["label"].startswith("filtered") \
                                and any(v == "" for v in e["event"].values()):
                            # Elasticsearch cannot query an empty string on a wildcard-typed field (tested on 8.15)
                            skipped += 1
                            continue
                        s2, r = es.call("GET", "/%s/_search" % index,
                                        {"size": 0, "terminate_after": 1, "query": {"bool": {"filter": [{"ids": {"values": [key]}}, query]}}})
                        if s2 >= 300:
                            res.update(status="FAIL", failure="syntax",
                                       reason="Elasticsearch rejected the query: %s" % str(r.get("error", {}).get("root_cause", r))[:200])
                            evaluated = False
                            break
                        hit = r.get("hits", {}).get("total", {}).get("value", 0) > 0
                        if group == "pos" and not hit:
                            problems.append("missed the %s-case positive" % e["label"])
                        if group == "neg" and hit:
                            if e["label"].startswith("filtered") and c.get("cidrOnNonIp"):
                                inconclusive.append(", ".join(c["cidrOnNonIp"]))
                            else:
                                problems.append("matched the %s negative" % e["label"])
                    if not evaluated:
                        break
                if evaluated:
                    if problems:
                        res.update(status="FAIL", failure="behaviour", reason="; ".join(problems))
                    elif inconclusive:
                        res.update(status="UNTESTABLE", reason="a CIDR filter on %s only works if the collector types that field as ip; "
                                   "the test cannot know that" % inconclusive[0])
                    else:
                        res.update(status="PASS", reason="")
                    if skipped:
                        res["emptyStringEventsSkipped"] = skipped
            results.append(res)
    finally:
        es.call("DELETE", "/" + index)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"backend": "elastic-dsl", "fieldType": field_type, "results": results}, f)
    from collections import Counter
    print(field_type, dict(Counter(r["status"] for r in results)))


# --------------------------------------------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------------------------------------------

def report(results_path, out_path):
    from collections import Counter
    with open(results_path, encoding="utf-8") as f:
        res = json.load(f)["results"]
    c = Counter(r["status"] for r in res)
    tested = c["PASS"] + c["FAIL"]
    cs = sum(1 for r in res if r["status"] == "PASS" and r.get("caseSensitive"))
    lines = ["# Elastic query test against a real Elasticsearch", "",
             "Mapped Elastic queries considered: %d" % len(res), "",
             "| Result | Rules |", "|---|---:|",
             "| Tested (Elasticsearch evaluated them) | %d |" % tested,
             "| PASS | %d |" % c["PASS"], "| FAIL | %d |" % c["FAIL"], "| UNTESTABLE | %d |" % c["UNTESTABLE"], ""]
    fails = Counter(r.get("failure", "") for r in res if r["status"] == "FAIL")
    if fails:
        lines += ["FAIL by kind: " + ", ".join("%s %d" % (k, v) for k, v in fails.most_common()), ""]
    unt = Counter(r["reason"] for r in res if r["status"] == "UNTESTABLE")
    lines += ["## Why rules were not testable", ""] + ["- %d: %s" % (n, why) for why, n in unt.most_common()] + [""]
    lines += ["## Case sensitivity (informational)", "",
              "%d of %d passing rules did NOT match the same event with its text upper-cased. Sigma matching is "
              "case-insensitive; an Elasticsearch keyword field is not." % (cs, c["PASS"]), ""]
    lines += ["## Failures", ""]
    for r in [r for r in res if r["status"] == "FAIL"][:200]:
        lines.append("- %s %s: %s" % (r["id"], r["title"], r["reason"]))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines[:14]))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "gen":
        gen(sys.argv[2], sys.argv[3])
    elif cmd == "run":
        run(sys.argv[2], sys.argv[3])
    elif cmd == "report":
        report(sys.argv[2], sys.argv[3])
    elif cmd == "rundsl":
        rundsl(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        raise SystemExit(__doc__)
