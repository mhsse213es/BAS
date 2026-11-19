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

1. **Correction to the first write-up.** The raw run counted a fixed version from any package in a matching definition, so the raw 20 overstated usable mappings. The example I first gave was **wrong**: CVE-2021-44228 (Log4Shell) is correctly mapped to `liblog4j2-java < 2.15.0`. I had misread an extraction that pulled in a line from a neighbouring Log4j 1.2 definition. The hand review and the correspondence step below supersede the raw count.
2. **Ubuntu OVAL entries are per Ubuntu package, not per vendor product.** A KEV "product" such as "Linux Kernel" or "Adobe Acrobat" does not map to an Ubuntu package without a curated mapping (gap G4). The spike cannot produce a usable product mapping by itself.
3. **Some CVE IDs in the matches carry seven-digit numbers** (for example CVE-2026-111497, CVE-2026-109618). These were not independently verified in this run.
4. **456 of 1,773 KEVs have no CVSS v3 score** in NVD. Excluding them is correct for the approved definition, but it means the Critical population is defined by CVSS v3 availability, not by severity alone.

## 5. Hand review of the 22 matches

Each match was judged on whether the Ubuntu package is the product the KEV entry describes.

| Judgement | Count | Examples |
|---|---|---|
| Product match | 13 | brotli, apache2, firefox, roundcube, activemq, cacti, redis, liblog4j2-java (Log4Shell and CVE-2021-45046), roundcube |
| Family match | 6 | Tomcat (`libtomcat*-java`), Spring (`libspring-*-java`), PHP (`libapache2-mod-php*`), WebKit (`gir1.2-javascriptcoregtk`, `libqt5webkit5`) |
| Needs review | 1 | CVE-2020-15999 (Chrome FreeType) maps to `freetype2-demos`, a demo binary, not the library |
| False match | 1 | CVE-2015-4852 (WebLogic) maps to `openjdk-8-demo`; WebLogic is not an Ubuntu product |
| No resolvable package | 1 | CVE-2025-39682 (Linux kernel): a definition matches but no package name resolves |

One further anomaly: CVE-2022-26486 (Firefox) has a jammy fixed value, `1:1snap1-0ubuntu1`, that looks like a snap transitional version. It was kept, and it needs review.

## 6. Package correspondence result

The reviewed map (`product_map.json`) ties each KEV vendor|product to the Ubuntu package names that count as that product. A fixed version counts only when it comes from a corresponding package.

| Status | Count | % of 500 |
|---|---|---|
| NO_UBUNTU_OVAL_MATCH | 478 | 95.6% |
| **FIXED_VERSION_CORRESPONDING** | **19** | **3.8%** (13 product, 6 family) |
| NO_CORRESPONDING_PACKAGE | 2 | 0.4% |
| NO_RESOLVABLE_PACKAGE | 1 | 0.2% |

**Limitation on these numbers.** The map was built after the hand review of these same 22 matches, so the 19 are validated on the set that informed the map. They are not a blind test. Recall beyond these products is unmeasured: the run found no OVAL match for any Critical KEV outside these 22, and that is a measurement of the matches Ubuntu OVAL contains, not of how many Critical KEVs Ubuntu has a fix for.

## 7. What the spike establishes

- The measurement works end to end: KEV join, CVSS-based Critical classification, per-release OVAL matching, package correspondence, and provenance.
- **Usable Ubuntu fixed-version coverage of Critical KEVs is about 3.8%** (19 of 500). Ubuntu covers a small share of the Critical KEV population, which is mostly non-Ubuntu products. Windows (MSRC) is needed to cover the majority.
- Only the 19 correspondence-checked fixes may be reported as usable. The raw count of 20 must not be used.

## 8. Recommended next steps

1. Owner review of `product_map.json`, plus the three open rows (CVE-2020-15999, CVE-2022-26486, CVE-2025-39682).
2. Run the MSRC spike for Windows Critical KEVs, which covers most of the population.
3. Decide with the owner whether a KEV with no CVSS v3 score should be scored from v2 for display only, while staying excluded from the Critical denominator.
