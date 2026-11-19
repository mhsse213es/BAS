"""Documented alias register for the product-string cases. An alias is PROPOSED
only when the exact observed string appears in its official KB article text.
Anything else is UNRESOLVED and remains UNKNOWN; nothing is force-matched.
curator: Tausif. designated reviewer: Zain. review_date stays blank until
Zain's actual review. No matcher reads this file yet."""
import html, json, os, re
os.chdir(os.path.dirname(os.path.abspath(__file__)))

kb = json.load(open("kb_results.json", encoding="utf-8"))
q = lambda s: json.dumps(s, ensure_ascii=False)

SERVER_CORE_BASE = {
    "Windows Server 2016  (Server Core installation)": "Windows Server 2016",
    "Windows Server 2016 (Server Core installation)": "Windows Server 2016",
    "Windows Server 2019 (Server Core installation)": "Windows Server 2019",
    "Windows Server, version 2004 (Server Core installation)": "Windows Server, version 2004",
}


def article_text(kb_number):
    raw = open(f"kb{kb_number}.html", encoding="utf-8", errors="replace").read()
    text = html.unescape(re.sub(r"<[^>]+>", " ", raw))
    return re.sub(r"\s+", " ", text).lower()


lines = [
    "# REQ-021 product-string alias register.",
    "# PROPOSED = the observed string appears in the KB article text (evidence",
    "# only; still needs reviewer approval). UNRESOLVED = not supported; stays UNKNOWN.",
    "# No matcher uses this file yet. curator: Tausif. designated reviewer: Zain.",
    "# review_date is blank until the reviewer's actual review; never backdate.",
    "schema: 1",
    "aliases:",
]
seen, n = set(), 0
counts = {"PROPOSED": 0, "UNRESOLVED": 0}
for r in kb:
    if r["status"] != "UNKNOWN_PRODUCT_NOT_IN_KB":
        continue
    obs, kbn = r["product"], r["kb"]
    if (obs, kbn) in seen:
        continue
    seen.add((obs, kbn))
    n += 1
    text = article_text(kbn)
    in_article = obs.lower() in text
    if obs in SERVER_CORE_BASE:
        canon = SERVER_CORE_BASE[obs]
        if in_article:
            cls = "PROPOSED"
            why = ("Exact string found in the KB article text. Reviewer must still confirm the article "
                   "covers this edition with the same build.")
        else:
            cls, canon = "UNRESOLVED", None
            why = ("Exact string not found in the KB article text. Article does not state coverage of this "
                   "edition, so no alias is supported.")
    elif "microsoft .net framework" in obs.lower():
        cls, canon = "UNRESOLVED", None
        why = ("Describes a .NET Framework component on an OS, not the OS build. The KB build cannot be "
               "attributed to the OS product reliably. Remains UNKNOWN.")
    else:
        canon = obs if in_article else None
        cls = "PROPOSED" if in_article else "UNRESOLVED"
        why = ("Exact string found in the KB article text. Reviewer must still confirm." if in_article else
               "Exact string not found in the KB article text; the article uses different wording. "
               "Remains UNKNOWN unless a reviewer confirms an alias.")
    counts[cls] += 1
    lines += [
        f"  - id: {q('ALIAS-' + r['cve'] + '-' + kbn + '-' + str(n))}",
        f"    cve: {q(r['cve'])}",
        f"    observed_string: {q(obs)}",
        f"    source: {q('MSRC CVRF ' + r['month'] + '; KB article https://support.microsoft.com/help/' + kbn)}",
        f"    canonical_product: {q(canon) if canon else 'null'}",
        f"    classification: {q(cls)}",
        f"    mapping_rationale: {q(why)}",
        f"    curator: {q('Tausif')}",
        f"    independent_reviewer: {q('Zain')}",
        f"    reviewer_status: {q('designated, review not yet performed')}",
        f"    review_date: {q('')}",
    ]
open("aliases.yaml", "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("alias rows:", n, counts)
