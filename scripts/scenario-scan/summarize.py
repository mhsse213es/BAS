import collections
import json
import re
import sys

res = json.load(open(sys.argv[1], encoding="utf8"))["results"]

# group uncovered registry writes by the first few path components
groups = collections.defaultdict(lambda: {"tests": set(), "noCleanup": set()})
for t in res:
    for f in t["findings"]:
        if f["kind"] != "registry" or f["covered"]:
            continue
        parts = f["path"].split("\\")
        head = "\\".join(parts[:4]).lower() if parts[0] in ("HKCU", "HKLM") else "\\".join(parts[:3]).lower()
        head = re.sub(r"\\[0-9a-f]{8}-[0-9a-f-]{27}.*", "\\{guid}", head)
        key = (parts[0] + "\\" + head.split("\\", 1)[1]) if "\\" in head else head
        groups[key]["tests"].add(t["id"] + " " + t["name"][:50])
        if not t["hasCleanup"]:
            groups[key]["noCleanup"].add(t["id"] + " " + t["name"][:50])

rows = sorted(groups.items(), key=lambda kv: -len(kv[1]["tests"]))
for k, v in rows[:40]:
    print("%3d  noCleanup=%2d  %s" % (len(v["tests"]), len(v["noCleanup"]), k))
