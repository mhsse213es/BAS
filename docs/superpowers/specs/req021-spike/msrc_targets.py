"""Step 3a: list the Microsoft Critical KEVs with their NVD published dates and
the CVRF month each should be looked up in. Reads local snapshots only."""
import glob, gzip, json, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

res = json.load(open("results.json", encoding="utf-8"))
crit = {r["cve"]: r["cvss"]["score"] for r in res["rows"]}
kev = {v["cveID"]: v for v in json.load(open("kev.json", encoding="utf-8"))["vulnerabilities"]}
published = {}
for gz in glob.glob("nvdcve-2.0-*.json.gz"):
    with gzip.open(gz, "rt", encoding="utf-8") as f:
        for it in json.load(f)["vulnerabilities"]:
            c = it["cve"]
            if c["id"] in crit:
                published[c["id"]] = c.get("published", "")

targets = []
for cve in crit:
    k = kev[cve]
    if k["vendorProject"] != "Microsoft":
        continue
    targets.append({"cve": cve, "score": crit[cve], "product": k["product"],
                    "name": k["vulnerabilityName"], "nvd_published": published.get(cve, ""),
                    "kev_dateAdded": k["dateAdded"]})
targets.sort(key=lambda t: t["nvd_published"])
json.dump(targets, open("msrc_targets.json", "w", encoding="utf-8"), indent=2)
for t in targets:
    print(t["cve"], t["score"], t["nvd_published"][:10], "|", t["product"], "|", t["name"][:70])
print("count", len(targets))
