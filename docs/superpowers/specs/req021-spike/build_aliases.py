"""Documented alias register for the 25 product-string cases. An alias is a
PROPOSAL until a reviewer confirms it. Unresolved or ambiguous strings stay
UNKNOWN and are never force-matched. curator = Tausif; designated reviewer =
Zain. review_date is left blank until Zain's actual review. Nothing here is
used by any matcher yet."""
import json, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
kb = json.load(open("kb_results.json", encoding="utf-8"))
q = lambda s: json.dumps(s, ensure_ascii=False)

SERVER_CORE = {
    "Windows Server 2016  (Server Core installation)": "Windows Server 2016",
    "Windows Server 2016 (Server Core installation)": "Windows Server 2016",
    "Windows Server 2019 (Server Core installation)": "Windows Server 2019",
    "Windows Server, version 2004 (Server Core installation)": "Windows Server, version 2004",
}
WIN10 = {
    "Windows 10 for 32-bit Systems": "Windows 10 for 32-bit Systems",
    "Windows 10 for x64-based Systems": "Windows 10 for x64-based Systems",
    "Windows 10 Version 1511 for 32-bit Systems": "Windows 10 Version 1511 for 32-bit Systems",
    "Windows 10 Version 1511 for x64-based Systems": "Windows 10 Version 1511 for x64-based Systems",
    "Windows 10 Version 1607 for 32-bit Systems": "Windows 10 Version 1607 for 32-bit Systems",
    "Windows 10 Version 1607 for x64-based Systems": "Windows 10 Version 1607 for x64-based Systems",
    "Windows 10 Version 1703 for 32-bit Systems": "Windows 10 Version 1703 for 32-bit Systems",
    "Windows 10 Version 1703 for x64-based Systems": "Windows 10 Version 1703 for x64-based Systems",
}

lines = [
    "# REQ-021 product-string alias register. A proposal until reviewed.",
    "# Unresolved or ambiguous strings are UNRESOLVED and remain UNKNOWN.",
    "# No matcher uses this file yet. curator: Tausif. designated reviewer: Zain.",
    "# review_date is blank until the reviewer's actual review; never backdate.",
    "schema: 1",
    "aliases:",
]
seen = set()
n = 0
for r in kb:
    if r["status"] != "UNKNOWN_PRODUCT_NOT_IN_KB":
        continue
    obs = r["product"]
    key = (obs, r["kb"])
    if key in seen:
        continue
    seen.add(key)
    n += 1
    if obs in SERVER_CORE:
        canon, cls = SERVER_CORE[obs], "PROPOSED"
        rationale = ("Server Core installation of the same release; the KB build is the one Microsoft "
                     "lists for this release. Confirm the KB article covers Server Core with the same build.")
    elif obs in WIN10:
        canon, cls = WIN10[obs], "PROPOSED"
        rationale = ("Same Windows 10 release and architecture. Confirm this exact string appears in the "
                     "KB article before the alias is used; if the article uses a different string, keep UNKNOWN.")
    else:
        canon, cls = None, "UNRESOLVED"
        rationale = ("Describes a .NET Framework component on an OS, not the OS build itself. "
                     "The KB build cannot be attributed to the OS product reliably. Remains UNKNOWN.")
    lines += [
        f"  - id: {q('ALIAS-' + r['cve'] + '-' + r['kb'] + '-' + str(n))}",
        f"    cve: {q(r['cve'])}",
        f"    observed_string: {q(obs)}",
        f"    source: {q('MSRC CVRF ' + r['month'] + '; KB article https://support.microsoft.com/help/' + r['kb'])}",
        f"    canonical_product: {q(canon) if canon else 'null'}",
        f"    classification: {q(cls)}",
        f"    mapping_rationale: {q(rationale)}",
        f"    curator: {q('Tausif')}",
        f"    independent_reviewer: {q('Zain')}",
        f"    reviewer_status: {q('designated, review not yet performed')}",
        f"    review_date: {q('')}",
    ]
open("aliases.yaml", "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("alias rows:", n, "| proposed:", sum(1 for l in lines if 'classification: "PROPOSED"' in l),
      "| unresolved:", sum(1 for l in lines if 'classification: "UNRESOLVED"' in l))
