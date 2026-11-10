"""Step 1: hand-review support. For each Critical KEV that has any Ubuntu OVAL
match, print the KEV vendor/product and every OVAL package name + fixed
version found in its definitions (per release). Reads only local files."""
import bz2, json, os, sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
OVAL_D = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OVAL_L = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
OVAL_C = "http://oval.mitre.org/XMLSchema/oval-common-5"

res = json.load(open("results.json", encoding="utf-8"))
kev = {v["cveID"]: v for v in json.load(open("kev.json", encoding="utf-8"))["vulnerabilities"]}
matched = [r["cve"] for r in res["rows"] if r["overall"] != "NO_UBUNTU_OVAL_MATCH"]
want = set(matched)
out = {}

for rel in ["focal", "jammy", "noble"]:
    root = ET.parse(bz2.open(f"com.ubuntu.{rel}.cve.oval.xml.bz2", "rb")).getroot()
    # object id -> package name
    # OVAL names are often var_ref -> constant_variable, so resolve both forms.
    const_val = {}
    for cv in root.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5}constant_variable"):
        vals = [(v.text or "").strip() for v in cv.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5}value")]
        if vals:
            const_val[cv.get("id")] = vals[0]
    obj_name = {}
    for o in root.iter(f"{{{OVAL_L}}}dpkginfo_object"):
        n = o.find(f"{{{OVAL_L}}}name")
        if n is None:
            continue
        if n.get("var_ref"):
            obj_name[o.get("id")] = const_val.get(n.get("var_ref"))
        else:
            obj_name[o.get("id")] = (n.text or "").strip()
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
        if cve not in want:
            continue
        pkgs = []
        for crit in d.iter(f"{{{OVAL_D}}}criterion"):
            tref = crit.get("test_ref")
            if tref in test_info:
                pkg, fixes = test_info[tref]
                if pkg:
                    pkgs.append((pkg, fixes))
        out.setdefault(cve, {})[rel] = pkgs

for cve in matched:
    k = kev[cve]
    print(f"\n{cve}  KEV vendor={k['vendorProject']!r} product={k['product']!r} name={k['vulnerabilityName']!r}")
    for rel, pkgs in sorted(out.get(cve, {}).items()):
        fixed = sorted({(p, f) for p, fs in pkgs for f in fs})
        names = sorted({p for p, _ in pkgs})
        print(f"  {rel}: packages={names[:8]}{' ...' if len(names)>8 else ''}")
        for p, f in fixed[:6]:
            print(f"      fixed: {p} < {f}")
