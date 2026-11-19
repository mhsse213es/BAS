import collections
import json
import re
import sys

res = json.load(open(sys.argv[1], encoding="utf8"))["results"]
depth = int(sys.argv[2]) if len(sys.argv) > 2 else 7
c = collections.Counter()
nocl = collections.defaultdict(set)
for t in res:
    for f in t["findings"]:
        if f["kind"] != "registry" or f["covered"]:
            continue
        parts = f["path"].split("\\")
        p = "\\".join(parts[:depth])
        p = re.sub(r"\{[0-9a-fA-F-]{36}\}.*", "{guid}", p)
        c[p.lower()] += 1
        if not t["hasCleanup"]:
            nocl[p.lower()].add(t["id"])
for p, n in c.most_common(70):
    print("%3d %s%s" % (n, p, "   <-- no cleanup: " + ",".join(sorted(nocl[p])) if p in nocl else ""))
