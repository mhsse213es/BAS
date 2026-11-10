"""Historical KB-to-build step (approved hierarchy: MSRC CVRF -> official KB
article -> UNKNOWN). For each Windows-OS-scope CVE, collect every Windows
security-update remediation with its KB and product, fetch the official
Microsoft KB article, and accept a fixed build only when BOTH hold:
  (a) the KB article's title carries an "OS Build X.Y" for that KB, and
  (b) the KB article text names the same Windows product the CVRF lists.
Otherwise the entry is UNKNOWN. No build is inferred from dates or versions.
Writes kb_results.json. Network: fetches support.microsoft.com only."""
import json, os, re, html, subprocess
import xml.etree.ElementTree as ET
os.chdir(os.path.dirname(os.path.abspath(__file__)))

PROD = "{http://www.icasi.org/CVRF/schema/prod/1.1}"
VULN = "{http://www.icasi.org/CVRF/schema/vuln/1.1}"
SCOPE = json.load(open("msrc_results.json", encoding="utf-8"))  # cve -> month
MONTHS = {cve: r["month"] for cve, r in SCOPE.items()}

def names_of(root):
    return {fp.get("ProductID"): (fp.text or "").strip() for fp in root.iter(PROD + "FullProductName")}

rows = []
cache = {}
for cve, month in MONTHS.items():
    if month not in cache:
        cache[month] = ET.parse(f"msrc-{month}.json").getroot()
    root = cache[month]
    names = names_of(root)
    for v in root.iter(VULN + "Vulnerability"):
        if (v.findtext(VULN + "CVE") or "").strip() != cve:
            continue
        for rem in v.iter(VULN + "Remediation"):
            kb = (rem.findtext(VULN + "Description") or "").strip()
            sub = (rem.findtext(VULN + "SubType") or "").strip()
            if sub != "Security Update" or not re.fullmatch(r"\d{6,8}", kb):
                continue
            for pid in rem.findall(VULN + "ProductID"):
                pname = names.get((pid.text or "").strip(), "")
                if "Windows" in pname:
                    rows.append({"cve": cve, "month": month, "kb": kb, "product": pname,
                                 "cvrf_fixed_build": (rem.findtext(VULN + "FixedBuild") or "").strip()})

# unique KBs to fetch
kbs = sorted({r["kb"] for r in rows})
pages = {}
for kb in kbs:
    p = f"kb{kb}.html"
    if not os.path.exists(p) or os.path.getsize(p) < 1000:
        subprocess.run(["curl", "-sS", "--max-time", "120", "-L", "-o", p,
                        f"https://support.microsoft.com/help/{kb}"], check=False)
    pages[kb] = open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""

def title_build(text, kb):
    t = re.search(r"<title>([^<]*)</title>", text)
    title = html.unescape(t.group(1)) if t else ""
    m = re.search(r"OS Build (\d+\.\d+)", title)
    return (m.group(1) if m else None), title

def product_in_page(text, product):
    plain = html.unescape(re.sub(r"<[^>]+>", " ", text))
    plain = re.sub(r"\s+", " ", plain).lower()
    return product.lower() in plain

out = []
for r in rows:
    text = pages.get(r["kb"], "")
    build, title = title_build(text, r["kb"]) if text else (None, "")
    named = product_in_page(text, r["product"]) if text else False
    if build and named:
        status = "CONFIRMED_KB_BUILD"
    elif not text:
        status = "UNKNOWN_KB_UNAVAILABLE"
    elif not build:
        status = "UNKNOWN_NO_TITLE_BUILD"
    else:
        status = "UNKNOWN_PRODUCT_NOT_IN_KB"
    out.append({**r, "kb_title": title, "kb_build": build, "product_named_in_kb": named, "status": status})

json.dump(out, open("kb_results.json", "w", encoding="utf-8"), indent=2)
from collections import Counter
print("rows", len(out), "unique KBs", len(kbs))
print(Counter(o["status"] for o in out))
for o in out:
    print(o["cve"], o["kb"], o["product"][:50], "|", o["kb_build"], "|", o["status"])
