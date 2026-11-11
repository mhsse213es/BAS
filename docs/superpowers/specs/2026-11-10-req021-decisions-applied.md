# REQ-021 Decisions Applied and Acceptance Report

**Status:** Decisions applied. **No mapping is reviewed or promoted.** Every candidate is `PENDING_HUMAN_REVIEW`.
**Register:** `docs/superpowers/specs/req021-spike/reviewed_mappings.yaml` (24 entries)

## 1. Decisions applied

| Area | Decision | Applied as |
|---|---|---|
| Initial Windows severity | Critical only (CVSS 9.0-10.0) | Windows scope is the 7 historical Critical CVEs. High is a separate expansion after the spike |
| Historical data | Official Microsoft records, in order: MSRC CVRF, official KB article, then UNKNOWN | CVRF for remediations and KB numbers; KB article title build accepted only when the article also names the same product |
| Unresolvable mappings | UNKNOWN | Any Windows row without a reliable title build or product match is UNKNOWN (62 rows) |
| Product mapping | Version-controlled, reviewed YAML | `reviewed_mappings.yaml` in the repo. No database promotion |
| Open mappings | Three require curator review | CVE-2020-15999, CVE-2022-26486, and CVE-2025-39682 are flagged `open_issue` in the register |
| Scope expansion | Consider High after the spike | Not done |

No build was inferred from dates or approximate version comparison.

## 2. Historical KB-to-build result (Windows, Critical only)

Source: `msrc_kb.py`. Each row is one Windows security-update remediation for the 7 in-scope CVEs.

| Status | Rows | Meaning |
|---|---|---|
| CONFIRMED_KB_BUILD | 3 | KB article title build, and the article names the same product |
| UNKNOWN_NO_TITLE_BUILD | 37 | KB article has no build in its title (typical for .NET and some cumulative updates) |
| UNKNOWN_PRODUCT_NOT_IN_KB | 25 | Build found, but the article text does not contain the CVRF product string exactly. Conservative by design; some are likely correct and need a curator |

The 3 confirmed rows cover 2 CVEs:
- CVE-2020-1350, Windows Server 2019, `17763.1339` (KB4558998)
- CVE-2020-1350, Windows Server 2016, `14393.3808` (KB4565511)
- CVE-2017-8543, Windows Server 2016, `14393.1480` (KB4025339)

## 3. Acceptance report (raw counts and reviewed counts, never merged)

| Population | Raw candidates | Independently reviewed and confirmed |
|---|---|---|
| Ubuntu fixed versions, Critical KEVs | **19** | **0** |
| Windows fixed builds, Critical KEVs (Windows OS scope) | **3** (2 CVEs) | **0** |
| Open mappings requiring review | 3 | 0 |

**The raw 19 and 3 are not validated Windows or Ubuntu coverage.** Every mapping awaits a curator and an independent reviewer. The 19 Ubuntu rows were built from the same 22 hand-reviewed matches, so they are not a blind test even after review.

Coverage percentages are not reported as validated until the reviewed count is above zero.

## 4. What is still needed before any mapping is production-eligible

1. A named curator and a different named reviewer for each mapping, with a review date. The register leaves these blank on purpose.
2. Resolution of the three open items.
3. For the Windows rows, a curator decision on the 25 `UNKNOWN_PRODUCT_NOT_IN_KB` rows. The conservative rule may be right, or the product-string match may need a documented alias list, which is itself a reviewed decision.

No automatic promotion. No production checks are built from this register yet.
