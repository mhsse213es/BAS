"""Step 3b: for each Windows-OS-scope Critical KEV, find its CVRF 1.1 XML month
and collect Windows product entries that carry a FixedBuild (vendor data).
Reads local snapshots only. Writes msrc_results.json."""
import json, os
import xml.etree.ElementTree as ET
os.chdir(os.path.dirname(os.path.abspath(__file__)))

PROD = "{http://www.icasi.org/CVRF/schema/prod/1.1}"
VULN = "{http://www.icasi.org/CVRF/schema/vuln/1.1}"

# CVE -> CVRF month (NVD published month)
WINDOWS_SCOPE = {
    "CVE-2017-7269": "2017-Mar",   # IIS on Windows Server
    "CVE-2017-8543": "2017-Jun",   # Windows Search
    "CVE-2019-0708": "2019-May",   # Remote Desktop Services
    "CVE-2020-0646": "2020-Jan",   # .NET Framework (Windows component)
    "CVE-2020-0796": "2020-Mar",   # SMBv3
    "CVE-2020-1040": "2020-Jul",   # Hyper-V RemoteFX
    "CVE-2020-1350": "2020-Jul",   # Windows DNS Server
}


def product_names(root):
    names = {}
    for fp in root.iter(f"{PROD}FullProductName"):
        names[fp.get("ProductID")] = (fp.text or "").strip()
    return names


cache = {}
results = {}
for cve, month in WINDOWS_SCOPE.items():
    if month not in cache:
        cache[month] = ET.parse(f"msrc-{month}.json").getroot()  # CVRF 1.1 XML, despite the name
    root = cache[month]
    names = product_names(root)
    vuln = None
    for v in root.iter(f"{VULN}Vulnerability"):
        if (v.findtext(f"{VULN}CVE") or "").strip() == cve:
            vuln = v
            break
    if vuln is None:
        results[cve] = {"month": month, "status": "NOT_IN_MONTH_DOC", "entries": []}
        continue
    entries, seen = [], set()
    for rem in vuln.iter(f"{VULN}Remediation"):
        fb = (rem.findtext(f"{VULN}FixedBuild") or "").strip()
        if not fb:
            continue
        kb = (rem.findtext(f"{VULN}Description") or "").strip()
        subtype = (rem.findtext(f"{VULN}SubType") or "").strip()
        for pid_el in rem.findall(f"{VULN}ProductID"):
            pname = names.get((pid_el.text or "").strip(), "")
            if "Windows" not in pname:
                continue
            key = (pname, fb, kb)
            if key in seen:
                continue
            seen.add(key)
            entries.append({"product": pname, "fixed_build": fb, "kb": kb, "subtype": subtype})
    results[cve] = {
        "month": month,
        "status": "FIXED_BUILDS_PRESENT" if entries else "NO_WINDOWS_FIXED_BUILD",
        "windows_product_count": len({e["product"] for e in entries}),
        "entries": entries,
    }

json.dump(results, open("msrc_results.json", "w", encoding="utf-8"), indent=2)
for cve, r in results.items():
    print(cve, r["month"], r["status"], "windows products:", r.get("windows_product_count", 0))
    for e in r["entries"][:5]:
        print("    ", e["product"][:70], "|", e["fixed_build"], "| KB", e["kb"], "|", e["subtype"])
