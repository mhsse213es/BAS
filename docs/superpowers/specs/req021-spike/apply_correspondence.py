"""Step 2: package correspondence. A fixed version counts only when the Ubuntu
package it comes from matches the reviewed product map for that KEV product.
Outputs correspondence.json. Reads local files only."""
import bz2, json, os, re
import xml.etree.ElementTree as ET
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
OVAL_D = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OVAL_L = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
RELEASES = ["focal", "jammy", "noble"]

res = json.load(open("results.json", encoding="utf-8"))
kev = {v["cveID"]: v for v in json.load(open("kev.json", encoding="utf-8"))["vulnerabilities"]}
pmap = {e["key"]: e for e in json.load(open("product_map.json", encoding="utf-8"))["entries"]}
critical = [r["cve"] for r in res["rows"]]
crit_set = set(critical)
oval_hits = {}  # cve -> rel -> [(pkg, fixes)]
oval_defs = set()  # CVEs with at least one vulnerability definition in any release

def parse(rel):
    root = ET.parse(bz2.open(f"com.ubuntu.{rel}.cve.oval.xml.bz2", "rb")).getroot()
    const_val = {}
    for cv in root.iter(f"{{{OVAL_D}}}constant_variable"):
        vals = [(v.text or "").strip() for v in cv.iter(f"{{{OVAL_D}}}value")]
        if vals:
            const_val[cv.get("id")] = vals[0]
    obj_name = {}
    for o in root.iter(f"{{{OVAL_L}}}dpkginfo_object"):
        n = o.find(f"{{{OVAL_L}}}name")
        if n is None:
            continue
        obj_name[o.get("id")] = const_val.get(n.get("var_ref")) if n.get("var_ref") else (n.text or "").strip()
    state_evr = {}
    for s in root.iter(f"{{{OVAL_L}}}dpkginfo_state"):
        e = s.find(f"{{{OVAL_L}}}evr")
        if e is not None and e.get("operation") == "less than":
            state_evr[s.get("id")] = e.text.strip()
    test_info = {}
    for t in root.iter(f"{{{OVAL_L}}}dpkginfo_test"):
        obj = t.find(f"{{{OVAL_L}}}object")
        st = [s.get("state_ref") for s in t.findall(f"{{{OVAL_L}}}state") if s.get("state_ref")]
        test_info[t.get("id")] = (obj_name.get(obj.get("object_ref")) if obj is not None else None,
                                  [state_evr[x] for x in st if x in state_evr])
    for d in root.iter(f"{{{OVAL_D}}}definition"):
        if d.get("class") != "vulnerability":
            continue
        cve = None
        for c in d.iter(f"{{{OVAL_D}}}cve"):
            cve = (c.text or "").strip(); break
        if cve not in crit_set:
            continue
        oval_defs.add(cve)  # a definition exists even if its packages do not resolve
        for crit in d.iter(f"{{{OVAL_D}}}criterion"):
            tref = crit.get("test_ref")
            if tref in test_info and test_info[tref][0]:
                pkg, fixes = test_info[tref]
                oval_hits.setdefault(cve, {}).setdefault(rel, []).append((pkg, fixes))

for rel in RELEASES:
    parse(rel)

def corresponds(pkg, patterns):
    return any(re.fullmatch(p, pkg) for p in patterns)

status = {}
detail = {}
for cve in critical:
    hits = oval_hits.get(cve)
    if cve not in oval_defs:
        status[cve] = "NO_UBUNTU_OVAL_MATCH"
        continue
    if not hits:
        status[cve] = "NO_RESOLVABLE_PACKAGE"
        continue
    k = kev[cve]
    key = f"{k['vendorProject']}|{k['product']}"
    entry = pmap.get(key)
    if entry is None:
        status[cve] = "UNMAPPED_PRODUCT"
        detail[cve] = {"kev_key": key, "packages_seen": sorted({p for rel in hits for p, _ in hits[rel]})}
        continue
    if entry["class"] == "NO_UBUNTU_PRODUCT":
        status[cve] = "NO_CORRESPONDING_PACKAGE"
        continue
    per_rel = {}
    any_pkg = False
    usable = False
    for rel, pairs in hits.items():
        corr = [(p, f) for p, f in pairs if corresponds(p, entry["packages"])]
        if corr:
            any_pkg = True
        if any(f for _, f in corr):
            usable = True
        per_rel[rel] = {"corresponding": sorted({p for p, _ in corr}),
                        "fixed": sorted({f"{p} < {v}" for p, fs in corr for v in fs})}
    if usable:
        status[cve] = "FIXED_VERSION_CORRESPONDING"
    elif any_pkg:
        status[cve] = "NO_USABLE_FIX_MAPPING"
    elif all(not pairs for pairs in hits.values()) or not any(p for pairs in hits.values() for p, _ in pairs):
        status[cve] = "NO_RESOLVABLE_PACKAGE"
    else:
        status[cve] = "NO_CORRESPONDING_PACKAGE"
    detail[cve] = {"kev_key": key, "class": entry["class"], "per_release": per_rel}

counts = Counter(status.values())
out = {
    "critical_total": len(critical),
    "status_counts": dict(counts),
    "fixed_corresponding_by_class": dict(Counter(
        detail[c]["class"] for c in status if status[c] == "FIXED_VERSION_CORRESPONDING")),
    "detail": {c: {"status": status[c], **detail.get(c, {})} for c in critical if c in status and status[c] != "NO_UBUNTU_OVAL_MATCH"},
}
with open("correspondence.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
print(json.dumps({"critical_total": out["critical_total"], "status_counts": out["status_counts"],
                  "fixed_corresponding_by_class": out["fixed_corresponding_by_class"]}, indent=2))
for c in critical:
    if c in status and status[c] not in ("NO_UBUNTU_OVAL_MATCH", "FIXED_VERSION_CORRESPONDING"):
        print(c, status[c], detail.get(c, {}).get("kev_key", ""))
