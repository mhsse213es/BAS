"""Differential test of elastic_regex.to_lucene against Python's `re` (PCRE-like search semantics).

  python esregex_diff.py gen  cases.json          build patterns, strings and Python's expected answers (local)
  python esregex_diff.py run  cases.json out.json [keyword|wildcard]   evaluate on Elasticsearch (ES_URL/ES_USER/ES_PASS)

For every pattern the translated regexp query must return exactly the strings that re.search matches. Strings are the
hand-written ones below plus mutations of them (a character deleted, inserted, upper-cased), so near misses are tested.
"""
import base64
import json
import os
import random
import re
import sys
import urllib.error
import urllib.request

# (pattern, flags) - the nine regexes the shipped rules use, then constructs each translation rule must get right.
REAL = [
    (r"\s-[FTd]\s", ""), (r"(.){200,}", ""), (r".+:assumed-role/aws:.+", ""),
    (r"(?:\s-[^-\s]{0,20}i|\s--inode\s)", ""), (r"(?:\s-[^-\s]{0,20}d|\s--directory\s)", ""),
    (r"""-(W|R)\s?(\s|"|')([0-9a-fA-F]{2}\s?){2,20}(\s|"|')""", ""), (r"-D", ""), (r"\s-O\s", ""),
    (r"(?i)(ipfs\.io/|ipfs\.io\s).+\..+@.+\.[a-z]+", ""),
]
SYNTH = [
    (r"^abc", ""), (r"abc$", ""), (r"^abc$", ""), (r"a|b", ""), (r"x(a|b)y", ""), (r"\d{3}-\d{2}", ""), (r"\w+@\w+", ""),
    (r"a.c", ""), (r"a.c", "s"), (r"[a-c]+z", ""), (r"[^0-9]{4}", ""), (r"a\.b", ""), (r"a+?b", ""), (r"colou?r", ""),
    (r"<tag>&amp;~#\"", ""), (r"\\\\server\\share", ""), (r"\S+\.exe\b".replace(r"\b", ""), ""), (r"\W\D", ""),
    (r"abc", "i"), (r"(?i)ABC", ""), (r"[\s,]x", ""), (r"a\tb", ""), (r"a{2,}b", ""), (r"(?:ab)+c", ""),
]
SEEDS = ["xx -F yy", "a -T b", "ls -ld /", "ls --inode ", "ls -i", "-W 0a 1b ", "-R  AB CD ", "-D", "cmd -O out",
         "x.assumed-role/aws:y", "arn:assumed-role/aws:role", "https://IPFS.IO/abc.def@ghi.com", "ipfs.io x.y@z.q",
         "abc", "ABC", "xabc", "abcx", "a-b", "ab", "aXc", "a\nc", "123-45", "a b@c", "colour", "color", "aab", "ababc",
         "<tag>&amp;~#\"", "\\\\server\\share", "foo.exe", "a1", "b,x", "a\tb", "zzz", "A", "x" * 210, "x" * 150,
         "axy", "xay", "xby", "xcy", "abcz", "dd", "1234", "a.b", "aXb"]


def mutate(rng, s):
    out = {s, s.upper(), s.lower()}
    for _ in range(6):
        if not s:
            break
        k = rng.randrange(len(s))
        out.add(s[:k] + s[k + 1:])
        out.add(s[:k] + rng.choice("-a F\t.x") + s[k:])
        out.add(s[:k] + s[k:k + 1].swapcase() + s[k + 1:])
    return out


def gen(path):
    from elastic_regex import to_lucene, Unsupported
    rng = random.Random(7)
    strings = sorted({m for s in SEEDS for m in mutate(rng, s)})
    cases = []
    for pat, fl in REAL + SYNTH:
        flags = re.IGNORECASE if "i" in fl else 0
        flags |= re.DOTALL if "s" in fl else 0
        try:
            value, ci = to_lucene(pat, ignorecase="i" in fl, dotall="s" in fl)
        except Unsupported as e:
            cases.append({"pattern": pat, "flags": fl, "unsupported": str(e)})
            continue
        rx = re.compile(pat, flags)
        qs, _ = to_lucene(pat, ignorecase="i" in fl, dotall="s" in fl, query_string=True)
        cases.append({"pattern": pat, "flags": fl, "value": value, "ci": ci, "qs": qs,
                      "expected": [i for i, s in enumerate(strings) if rx.search(s)]})
    json.dump({"strings": strings, "cases": cases}, open(path, "w"))
    print("patterns=%d strings=%d unsupported=%d" % (len(cases), len(strings), sum(1 for c in cases if "unsupported" in c)))


def run(path, out, field_type="keyword"):
    url, auth = os.environ["ES_URL"], base64.b64encode(("%s:%s" % (os.environ.get("ES_USER", "elastic"), os.environ["ES_PASS"])).encode()).decode()

    def call(m, p, b=None, raw=None):
        data = raw if raw is not None else (json.dumps(b).encode() if b is not None else None)
        r = urllib.request.Request(url + p, data=data, method=m, headers={"Authorization": "Basic " + auth, "Content-Type": "application/json" if raw is None else "application/x-ndjson"})
        try:
            with urllib.request.urlopen(r, timeout=60) as x:
                return x.status, json.loads(x.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")
    d = json.load(open(path))
    ix = "audspect-regexdiff-" + field_type
    call("DELETE", "/" + ix)
    call("PUT", "/" + ix, {"mappings": {"properties": {"f": {"type": field_type}, "n": {"type": "integer"}}}})
    bulk = "".join(json.dumps({"index": {"_index": ix, "_id": str(i)}}) + "\n" + json.dumps({"f": s, "n": i}) + "\n" for i, s in enumerate(d["strings"]))
    st, r = call("POST", "/_bulk?refresh=true", raw=bulk.encode())
    assert st < 300 and not r.get("errors"), r
    results, bad = [], 0
    for c in d["cases"]:
        res = {"pattern": c["pattern"], "flags": c["flags"]}
        if "unsupported" in c:
            res.update(status="NO_DSL", reason=c["unsupported"])
        else:
            q = {"regexp": {"f": {"value": c["value"]}}}
            if c["ci"]:
                q["regexp"]["f"]["case_insensitive"] = True
            st, r = call("GET", "/%s/_search" % ix, {"size": 10000, "_source": False, "fields": ["n"], "query": q})
            if st >= 300:
                res.update(status="FAIL", reason="HTTP %s %s" % (st, json.dumps(r)[:200]), value=c["value"])
            else:
                got = sorted(int(h["_id"]) for h in r["hits"]["hits"])
                st2, r2 = call("GET", "/%s/_search" % ix, {"size": 10000, "_source": False,
                               "query": {"query_string": {"query": "f:/" + c["qs"] + "/"}}})
                got_qs = sorted(int(h["_id"]) for h in r2["hits"]["hits"]) if st2 < 300 else "HTTP %s" % st2
                if got_qs != c["expected"]:
                    res.update(status="FAIL", value=c["qs"], reason="query_string form differs", queryStringGot=got_qs if isinstance(got_qs, str) else len(got_qs))
                elif got == c["expected"]:
                    res.update(status="PASS", matches=len(got))
                else:
                    res.update(status="FAIL", value=c["value"], missing=[d["strings"][i] for i in sorted(set(c["expected"]) - set(got))][:4],
                               extra=[d["strings"][i] for i in sorted(set(got) - set(c["expected"]))][:4])
        results.append(res)
    call("DELETE", "/" + ix)
    json.dump({"fieldType": field_type, "strings": len(d["strings"]), "results": results}, open(out, "w"), indent=1)
    import collections
    print(field_type, dict(collections.Counter(r["status"] for r in results)))


if __name__ == "__main__":
    if sys.argv[1] == "gen":
        gen(sys.argv[2])
    else:
        run(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "keyword")
