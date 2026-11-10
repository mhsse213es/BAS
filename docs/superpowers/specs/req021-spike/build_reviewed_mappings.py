"""Writes reviewed_mappings.yaml: the version-controlled record of every
candidate fixed-version mapping from the spike. Nothing here is promoted:
every entry is PENDING_HUMAN_REVIEW with blank curator and reviewer fields.
A machine-confirmed source is evidence for the curator, not a review.
JSON-quoted scalars are valid YAML, so no YAML library is needed."""
import json, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

corr = json.load(open("correspondence.json", encoding="utf-8"))
kb = json.load(open("kb_results.json", encoding="utf-8"))
ov = json.load(open("results.json", encoding="utf-8"))["provenance"]["ubuntu_oval"]
OPEN = {"CVE-2020-15999", "CVE-2022-26486", "CVE-2025-39682"}
q = lambda s: json.dumps(s, ensure_ascii=False)

lines = [
    "# REQ-021 reviewed product-mapping register (spike).",
    "# Status is PENDING_HUMAN_REVIEW for every entry. No entry is promoted to",
    "# production checks. curator and reviewer must be distinct people; a",
    "# machine-confirmed source is evidence for review, never a review itself.",
    "schema: 1",
    "mappings:",
]
for cve, d in sorted(corr["detail"].items()):
    if d.get("status") != "FIXED_VERSION_CORRESPONDING":
        continue
    lines += [
        f"  - id: {q('UBUNTU-' + cve)}",
        f"    cve: {q(cve)}",
        f"    platform: {q('Ubuntu LTS (focal, jammy, noble)')}",
        f"    kev_product: {q(d['kev_key'])}",
        f"    mapping_class: {q(d['class'])}",
        f"    evidence_source: {q('Canonical Ubuntu OVAL CVE feed (focal, jammy, noble); see req021-spike/results.json for file SHA-256 and generator timestamp')}",
        f"    affected_component: {q('Ubuntu packages named in OVAL: ' + json.dumps(sorted({p for r in d['per_release'].values() for p in r['corresponding']})))}",
        f"    fixed_versions: {json.dumps(d['per_release'], ensure_ascii=False)}",
        f"    vendor_version_build_relationship: {q('Ubuntu OVAL dpkg evr less-than state (vendor fixed version per package)')}",
        f"    status: {q('PENDING_HUMAN_REVIEW')}",
        f"    open_issue: {q('Curator review required (open)') if cve in OPEN else q('none recorded')}",
        f"    curator: {q('')}",
        f"    independent_reviewer: {q('')}",
        f"    review_date: {q('')}",
    ]
listed = {c for c, d in corr["detail"].items() if d.get("status") == "FIXED_VERSION_CORRESPONDING"}
for cve in sorted(OPEN - listed):
    # Open items that produced no usable fixed version: tracked for review, not counted.
    d = corr["detail"].get(cve, {})
    lines += [
        f"  - id: {q('OPEN-' + cve)}",
        f"    cve: {q(cve)}",
        f"    platform: {q('Ubuntu LTS (focal, jammy, noble)')}",
        f"    kev_product: {q(d.get('kev_key', 'see KEV entry'))}",
        f"    mapping_class: {q('NEEDS_REVIEW')}",
        f"    evidence_source: {q('Canonical Ubuntu OVAL CVE feed; spike review notes in 2026-11-10-req021-spike-results.md')}",
        f"    affected_component: {q('no fixed-version mapping (' + str(corr['detail'].get(cve, {}).get('status', 'NO_RESOLVABLE_PACKAGE')) + ')')}",
        f"    fixed_versions: {q('none')}",
        f"    vendor_version_build_relationship: {q('not established')}",
        f"    status: {q('PENDING_HUMAN_REVIEW')}",
        f"    open_issue: {q('Curator review required (open)')}",
        f"    curator: {q('')}",
        f"    independent_reviewer: {q('')}",
        f"    review_date: {q('')}",
    ]
for r in kb:
    if r["status"] != "CONFIRMED_KB_BUILD":
        continue
    lines += [
        f"  - id: {q('WINDOWS-' + r['cve'] + '-' + r['kb'] + '-' + r['product'][:40].replace(' ', '_'))}",
        f"    cve: {q(r['cve'])}",
        f"    platform: {q(r['product'])}",
        f"    kev_product: {q('Microsoft Windows')}",
        f"    mapping_class: {q('PRODUCT')}",
        f"    evidence_source: {q('MSRC CVRF ' + r['month'] + ' (KB ' + r['kb'] + ') and official KB article https://support.microsoft.com/help/' + r['kb'])}",
        f"    affected_component: {q(r['product'])}",
        f"    fixed_versions: {q('OS Build ' + str(r['kb_build']) + ' (KB ' + r['kb'] + ')')}",
        f"    vendor_version_build_relationship: {q('KB article title build; product named in KB article text')}",
        f"    status: {q('PENDING_HUMAN_REVIEW')}",
        f"    open_issue: {q('none recorded')}",
        f"    curator: {q('')}",
        f"    independent_reviewer: {q('')}",
        f"    review_date: {q('')}",
    ]
lines += [
    "# Windows entries not listed here are UNKNOWN: the relationship could not be",
    "# established reliably (no KB title build, or product not named in KB text).",
]
open("reviewed_mappings.yaml", "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("entries:", sum(1 for l in lines if l.startswith("  - id:")), "| reviewed:", 0)
