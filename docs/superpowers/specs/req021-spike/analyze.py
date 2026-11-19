"""REQ-021 spike: Critical KEV x NVD CVSS x Ubuntu OVAL coverage.

Reads only local snapshot files in this directory. Writes results.json and
prints a summary. Classification rules are stated in the output and in the
spike notes; nothing here is a verdict about any endpoint.
"""
import glob
import gzip
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)

RELEASES = ["focal", "jammy", "noble"]
CRITICAL_MIN = 9.0  # Critical = CVSS 9.0-10.0, per the approved spike definition


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- KEV ----------
with open("kev.json", encoding="utf-8") as f:
    kev_doc = json.load(f)
kev_ids = [v["cveID"] for v in kev_doc["vulnerabilities"]]
kev_meta = {
    "catalogVersion": kev_doc.get("catalogVersion"),
    "dateReleased": kev_doc.get("dateReleased"),
    "entries": len(kev_ids),
    "sha256": sha256_file("kev.json"),
}

# ---------- NVD 2.0 bulk (CVSS) ----------
# Preference: CVSS v3.1 Primary, then v3.0 Primary. CVSS v2 is never used to
# decide Critical (v2 has no Critical band). A KEV CVE with no v3 score is
# reported as NO_V3_SCORE and excluded from the Critical denominator.
nvd_cvss = {}  # cve -> {"version","score","source"}
nvd_meta = {}
for gz in sorted(glob.glob("nvdcve-2.0-*.json.gz")):
    year = re.search(r"nvdcve-2\.0-(\d{4})", gz).group(1)
    meta_path = gz.replace(".json.gz", ".meta")
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    meta[k.strip()] = v.strip()
    nvd_meta[year] = {
        "lastModifiedDate": meta.get("lastModifiedDate"),
        "size": meta.get("size"),
        "sha256_of_gz": sha256_file(gz),
    }
    with gzip.open(gz, "rt", encoding="utf-8") as f:
        doc = json.load(f)
    for item in doc.get("vulnerabilities", []):
        cve = item["cve"]
        cid = cve["id"]
        metrics = cve.get("metrics", {})
        best = None
        for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
            for m in metrics.get(key, []):
                if m.get("type") == "Primary":
                    best = {"version": ver, "score": m["cvssData"]["baseScore"],
                            "source": m.get("source")}
                    break
            if best:
                break
        if best:
            nvd_cvss[cid] = best

# ---------- Ubuntu OVAL ----------
NS = {"d": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
      "ld": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"}


def parse_oval(release):
    path = f"com.ubuntu.{release}.cve.oval.xml.bz2"
    import bz2
    with bz2.open(path, "rb") as f:
        tree = ET.parse(f)
    root = tree.getroot()
    gen = root.find("d:generator", NS)
    ts = gen.findtext("{http://oval.mitre.org/XMLSchema/oval-common-5}timestamp") if gen is not None else None
    pv = gen.findtext("{http://oval.mitre.org/XMLSchema/oval-common-5}product_version") if gen is not None else None

    # state id -> fixed evr (only "less than" states are fixed-version evidence)
    state_evr = {}
    for st in root.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}dpkginfo_state"):
        sid = st.get("id")
        evr = st.find("ld:evr", NS)
        if evr is not None and evr.get("operation") == "less than":
            state_evr[sid] = evr.text.strip()
    # test id -> state refs
    test_states = {}
    for tst in root.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}dpkginfo_test"):
        refs = [s.get("state_ref") for s in tst.findall("ld:state", NS) if s.get("state_ref")]
        test_states[tst.get("id")] = refs

    cve_defs = {}  # cve -> {"definitions": n, "fixed": set(), "tests": n}
    for d in root.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition"):
        if d.get("class") != "vulnerability":
            continue
        cve = None
        for c in d.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5}cve"):
            cve = (c.text or "").strip()
            break
        if not cve:
            continue
        rec = cve_defs.setdefault(cve, {"definitions": 0, "fixed": set(), "tests": 0})
        rec["definitions"] += 1
        for crit in d.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion"):
            tref = crit.get("test_ref")
            if not tref:
                continue
            rec["tests"] += 1
            for sref in test_states.get(tref, []):
                if sref in state_evr:
                    rec["fixed"].add(state_evr[sref])
    return {
        "file": path,
        "file_sha256": sha256_file(path),
        "oval_generator_timestamp": ts,
        "oval_product_version": pv,
        "cves": cve_defs,
    }


oval = {r: parse_oval(r) for r in RELEASES}

# ---------- Join and classify ----------
critical = []
no_v3 = []
for cid in kev_ids:
    c = nvd_cvss.get(cid)
    if c is None:
        no_v3.append(cid)
        continue
    if c["score"] >= CRITICAL_MIN:
        critical.append(cid)

rows = []
for cid in critical:
    per_release = {}
    for r in RELEASES:
        o = oval[r]["cves"].get(cid)
        if o is None:
            per_release[r] = "NO_UBUNTU_OVAL_MATCH"
        elif o["fixed"]:
            per_release[r] = "FIXED_VERSION_IDENTIFIED"
        else:
            per_release[r] = "NO_USABLE_FIX_MAPPING"
    # Overall: best outcome across releases.
    order = ["FIXED_VERSION_IDENTIFIED", "NO_USABLE_FIX_MAPPING", "NO_UBUNTU_OVAL_MATCH"]
    overall = next(s for s in order if s in per_release.values())
    rows.append({"cve": cid, "cvss": nvd_cvss[cid], "per_release": per_release, "overall": overall})

total = len(critical)
def count(pred):
    return sum(1 for r in rows if pred(r))

summary = {
    "critical_kev_total": total,
    "kev_without_v3_score_excluded": len(no_v3),
    "overall": {
        "any_ubuntu_oval_match": count(lambda r: r["overall"] != "NO_UBUNTU_OVAL_MATCH"),
        "fixed_version_identified": count(lambda r: r["overall"] == "FIXED_VERSION_IDENTIFIED"),
        "no_usable_fix_mapping": count(lambda r: r["overall"] == "NO_USABLE_FIX_MAPPING"),
        "no_ubuntu_oval_match": count(lambda r: r["overall"] == "NO_UBUNTU_OVAL_MATCH"),
    },
    "per_release": {},
}
for r in RELEASES:
    summary["per_release"][r] = {
        "fixed_version_identified": count(lambda x, r=r: x["per_release"][r] == "FIXED_VERSION_IDENTIFIED"),
        "no_usable_fix_mapping": count(lambda x, r=r: x["per_release"][r] == "NO_USABLE_FIX_MAPPING"),
        "no_ubuntu_oval_match": count(lambda x, r=r: x["per_release"][r] == "NO_UBUNTU_OVAL_MATCH"),
    }
for k in ("any_ubuntu_oval_match", "fixed_version_identified", "no_usable_fix_mapping", "no_ubuntu_oval_match"):
    summary["overall"][k + "_pct"] = round(100.0 * summary["overall"][k] / total, 1) if total else None

provenance = {
    "kev": kev_meta,
    "nvd_years": nvd_meta,
    "ubuntu_oval": {r: {k: oval[r][k] for k in ("file", "file_sha256", "oval_generator_timestamp", "oval_product_version")} for r in RELEASES},
    "critical_threshold": CRITICAL_MIN,
    "cvss_preference": "3.1 Primary, then 3.0 Primary; v2 never used for Critical",
    "analysis_run_utc": __import__("datetime").datetime.utcnow().isoformat() + "Z",
}

out = {"provenance": provenance, "summary": summary, "rows": rows,
       "critical_without_any_ubuntu_match_sample": [r["cve"] for r in rows if r["overall"] == "NO_UBUNTU_OVAL_MATCH"][:50]}
with open("results.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)

print(json.dumps(summary, indent=2))
print("NVD years loaded:", len(nvd_meta), "| CVEs with CVSS v3:", len(nvd_cvss))
