# REQ-021 Spike Results: Critical KEV x NVD CVSS x Ubuntu OVAL

**Status:** Measurement result. Not a verdict on any endpoint. The raw "fixed version identified" counts are **upper bounds**, for the reason in section 4.
**Run:** 2026-11-10 (UTC). Script and results: `docs/superpowers/specs/req021-spike/`.

## 1. Snapshots (for repeatability)

| Source | Identifier | Retrieved / produced |
|---|---|---|
| CISA KEV | catalogVersion `2026.11.09`, dateReleased `2026-11-09T19:54:37Z`, 1,773 entries | retrieved 2026-11-10 07:03 UTC |
| NVD 2.0 bulk | yearly `nvdcve-2.0-2002` to `-2026`, 25 files; per-file SHA-256 in `results.json` | retrieved 2026-11-10 UTC; the 2024 file was re-downloaded after a timeout and verified against the server's Content-Length (25,147,050 bytes) |
| Ubuntu OVAL | focal, jammy, noble `cve.oval.xml.bz2`; per-file SHA-256 in `results.json` | noble generator timestamp `2026-11-09T10:39:09`; OVAL product_version `2`; schema 5.11.1 |

## 2. Method

- **Critical** = CVSS base score 9.0 to 10.0. Source: NVD, CVSS v3.1 Primary, else v3.0 Primary. CVSS v2 is never used to decide Critical.
- **KEV with no v3 score** is excluded from the Critical denominator and reported separately.
- **OVAL coverage** = the CVE has at least one `vulnerability` definition in the release's OVAL file.
- **Fixed version identified** = at least one package test in a matching definition references a state with `evr operation="less than"`. That value is the fixed version.
- **No usable fix mapping** = matched in OVAL, but no fixed version is present (for example, existence-only tests with the comment "might be affected and may need fixing").
- **NO_UBUNTU_OVAL_MATCH** = not in the OVAL file. This does **not** mean there is no fix. It is never reported as "no fix available."

## 3. Results

| Measure | Count | % of 500 Critical KEVs |
|---|---|---|
| Critical KEVs (CVSS 9.0-10.0) | **500** | 100% |
| Excluded: KEV with no CVSS v3 score | 456 | (of 1,773 KEVs) |
| Any Ubuntu OVAL match (any release) | 22 | 4.4% |
| Fixed version identified (any release, raw) | 20 | 4.0% |
| No usable fix mapping (matched, no fixed version) | 2 | 0.4% |
| NO_UBUNTU_OVAL_MATCH | 478 | 95.6% |

Per release (raw):

| Release | Fixed version identified | No usable fix mapping | NO_UBUNTU_OVAL_MATCH |
|---|---|---|---|
| focal | 18 | 1 | 481 |
| jammy | 10 | 4 | 486 |
| noble | 7 | 5 | 488 |

KEV vendors among the 500 Critical entries are dominated by non-Ubuntu products: Apache 25, Adobe 22, Cisco 16, Google 15, Citrix 14, D-Link 14, Oracle 14, VMware 14, Fortinet 13, Microsoft 13. Low Ubuntu OVAL coverage is therefore expected, not a defect of the data source.

## 4. Caveats that change how to read the numbers

1. **Package correspondence is not checked.** The script counts a fixed version from any package in a matching definition. Example: CVE-2021-44228 (Log4Shell, affects Log4j 2) matches the focal definition, but its fixed version is for `apache-log4j1.2` (1.2.17-9ubuntu0.1), a different product. That row is a **false positive**. The 20 "fixed identified" rows therefore overstate usable mappings. A manual review of all 22 matches is required before any figure is reported as usable coverage.
2. **Ubuntu OVAL entries are per Ubuntu package, not per vendor product.** A KEV "product" such as "Linux Kernel" or "Adobe Acrobat" does not map to an Ubuntu package without a curated mapping (gap G4). The spike cannot produce a usable product mapping by itself.
3. **Some CVE IDs in the matches carry seven-digit numbers** (for example CVE-2026-111497, CVE-2026-109618). These were not independently verified in this run.
4. **456 of 1,773 KEVs have no CVSS v3 score** in NVD. Excluding them is correct for the approved definition, but it means the Critical population is defined by CVSS v3 availability, not by severity alone.

## 5. What the spike establishes

- The approved measurement works end to end: KEV join, CVSS-based Critical classification, per-release OVAL matching, and reproducible provenance.
- **Ubuntu OVAL alone covers about 4% of current Critical KEVs** before correspondence checks, so Level 1 coverage for a Linux-only verdict would be small. Windows (MSRC) is needed to cover the majority of Critical KEV products. That was the planned next step.
- The raw fixed-version count must not be reported as "usable fixed-version coverage" until package correspondence (gap G4) is implemented and the 22 matches are reviewed.

## 6. Recommended next steps

1. Hand-review the 22 matched CVEs against their KEV product, and record which are true mappings.
2. Implement package correspondence in the spike: a fixed version counts only when the OVAL package name corresponds to the KEV product through a reviewed mapping (G4).
3. Run the MSRC CVRF spike for Windows Critical KEVs, which covers most of the population.
4. Decide with the owner whether a KEV with no CVSS v3 score should be scored from v2 for display only, while staying excluded from the Critical denominator.
