> **STATUS UPDATE (2026-11-11): superseded in part.** This document was written before the independent review. The current state is:
>
> - Independent review recorded by **Zain** (Senior Security Infrastructure Reviewer), 2026-11-11, from `Review.txt`. Source of truth: `req021-spike/reviewed_mappings.yaml`.
> - **Approved (21 rows):** Ubuntu rows R1, R2 (focal), R3 (focal), R4-R7, R10 (focal), R11-R19 and FreeType CVE-2020-15999 (added); Windows W1-W3.
> - **CONDITIONAL / not eligible:** R8 Redis CVE-2022-0543; O2 kernel CVE-2025-39682 (not counted).
> - **REJECTED:** R9 Spring CVE-2022-22965 for `libspring-aop-java`.
> - **Corrected:** R18 PHP jammy is `libapache2-mod-php8.1` (8.1.2-1ubuntu2.28). ActiveMQ jammy `~esm1` removed. CVE-2022-26486 counted for focal only.
> - **Narrowed:** CVE-2021-1870 and CVE-2021-1871 approvals cover focal only; jammy and noble are UNVERIFIED.
> - **Aliases:** all 25 remain UNRESOLVED.
> - **Limit:** Zain's USN citations could not be opened from the review environment (Ubuntu returned server errors). Version strings were checked against Ubuntu's tracker.
>
> The sections below describe the register as it stood when this was written and are kept for the audit trail.

# REQ-021 Mapping Review Package (for an independent technical reviewer)

**Date prepared:** 2026-11-10
**Prepared by:** Tausif (curator). Technical checks in this package were prepared with AI assistance and are labeled as such.
**Status of every row:** not approved. An independent review has not yet been recorded.

## 1. What you are reviewing

REQ-021 maps known exploited Critical CVEs (CISA KEV, CVSS 9.0 to 10.0) to vendor fixed versions, so that an installed package version can later be compared against a reviewed fixed version. This package covers:

- **19 Ubuntu mapping rows** (focal, jammy, noble releases)
- **2 open items** (CVE-2020-15999, CVE-2025-39682)
- **3 Windows rows** (KB build numbers)
- **25 product-string aliases** (all currently UNRESOLVED; no alias is proposed)
- **The matcher logic** (Debian version comparison and the approval gate)

Source files in the repository, branch `req021-cve-exposure`, folder `docs/superpowers/specs/`:
- `req021-spike/reviewed_mappings.yaml`: the register, with every row
- `req021-spike/aliases.yaml`: the 25 aliases
- `req021-spike/results.json`: NVD and KEV snapshot hashes and Ubuntu OVAL provenance
- `2026-11-10-req021-disputed-evidence.md`: Ubuntu evidence for the three disputed items
- `2026-11-10-req021-crosscheck.md`: version-string cross-check of the 19 Ubuntu rows
- `2026-11-10-req021-external-review-response.md`: a prior external review and the responses to it
- `orchestrator/internal/ubuntumatch/`: the matcher and its tests

## 2. What the register means

- **Ubuntu rows** map a KEV product to the Ubuntu binary packages the CVE affects, and give the fixed version per release.
- **Fixed version values** are read from Ubuntu's public CVE pages (`https://ubuntu.com/security/<CVE>`).
- **Important limit:** Ubuntu's tracker lists **source** packages (for example `php8.1`, `tomcat9`, `webkit2gtk`). The register uses **binary** package names. The public pages confirm the version strings for source packages, but **do not confirm the binary names** for any row. Binary names need confirmation from the Ubuntu security notice (USN) or from the package itself.
- A row with `"none"` or an empty fixed list is not usable for a verdict.
- **Windows rows** use official Microsoft KB article build numbers. The CVE-to-KB association comes from each CVE's MSRC CVRF remediation entries (the raw CVRF files are in the spike scratch folder, not committed).

## 3. Review rows

For each row, record one decision from this set:

- **PASS:** the package, release, and fixed version are all confirmed from a source you can cite.
- **CONDITIONAL:** the evidence supports the decision, but a named dependency remains (state it).
- **REJECT:** the package, release, version, or relationship is wrong (state the correction).
- **UNVERIFIED:** you could not establish the row from evidence (state what is missing).

Each row below lists what the register currently says, what I verified, and what needs your check.

### 3.1 Ubuntu rows

**R1. CVE-2020-12641, Roundcube Webmail (focal)**
- Register: focal `roundcube < 1.4.3+dfsg.1-1ubuntu0.1~esm1`
- Verified: the version string appears on Ubuntu's page.
- Your check: binary name `roundcube`; the `~esm1` value should be an ESM build that the public page lists.

**R2. CVE-2021-1870, Apple WebKit (focal, jammy, noble)**
- Register: focal `gir1.2-javascriptcoregtk-4.0 < 2.30.6-0ubuntu0.20.04.1`. Jammy and noble list `libqt5webkit5` and `libwpewebkit-1.0-3` as corresponding packages, with **no fixed value**.
- Verified: focal version string appears on the page.
- Your check: binary name; disposition of QtWebKit and WPE (the matcher returns UNKNOWN for them, which is the safe outcome).

**R3. CVE-2021-1871, Apple WebKit (focal, jammy, noble)**
- Same structure as R2. Focal `gir1.2-javascriptcoregtk-4.0 < 2.32.0-0ubuntu0.20.04.1`.
- Your check: same as R2.

**R4. CVE-2021-40438, Apache HTTP Server (focal)**
- Register: focal `apache2 < 2.4.41-4ubuntu3.6`
- Verified: version string appears on the page.
- Your check: binary name `apache2`.

**R5. CVE-2021-44026, Roundcube Webmail (focal)**
- Register: focal `roundcube < 1.4.3+dfsg.1-1ubuntu0.1~esm2`
- Verified: version string appears on the page.
- Your check: binary name; confirm `esm2` is listed for focal.

**R6. CVE-2021-44228, Apache Log4j2 (focal)**
- Register: focal `liblog4j2-java < 2.15.0-0.20.04.1`
- Verified: version string appears on the page.
- Your check: binary name `liblog4j2-java`.

**R7. CVE-2021-45046, Apache Log4j2 (focal)**
- Register: focal `liblog4j2-java < 2.16.0-0.20.04.1`
- Verified: version string appears on the page.
- Your check: binary name; the relation between R6 and R7 (the second fix for the same family).

**R8. CVE-2022-0543, Redis (focal)**
- Register: focal `redis < 5:5.0.7-2ubuntu0.1`. KEV product: "Debian-specific Redis Servers".
- Verified: version string appears on the page.
- Your check: **product correspondence.** The KEV describes a Debian-specific issue, and the register maps it to the Ubuntu `redis` package. Decide whether that is the right product.

**R9. CVE-2022-22965, Spring Framework (focal, jammy, noble)**
- Register: `libspring-aop-java` for all three releases.
- Verified: version strings appear on the page.
- Your check: **product scope.** CVE-2022-22965 is in `spring-beans` and `spring-webmvc`, not in `spring-aop`. Decide whether `libspring-aop-java` is in scope. Binary names unverified.

**R10. CVE-2022-26486, Mozilla Firefox (focal and jammy)**
- Register status: COUNTED_FOCAL_ONLY. Focal `firefox < 97.0.2+build1-0ubuntu0.20.04.1` (kept). Jammy `firefox < 1:1snap1-0ubuntu1` (excluded).
- Verified: Ubuntu's jammy Firefox is a snap installer, so the jammy dpkg value does not establish the installed application version. The focal fix is a deb build.
- Your check: confirm the focal deb build for `firefox`; confirm the jammy exclusion.

**R11. CVE-2022-46169, Cacti (focal, jammy)**
- Register: focal `cacti < 1.2.10+ds1-1ubuntu1.1+esm2`; jammy `cacti < 1.2.19+ds1-2ubuntu1.1+esm2`.
- Verified: both version strings appear on the page.
- Your check: binary name `cacti`.

**R12. CVE-2023-46604, Apache ActiveMQ (focal, jammy)**
- Register: focal `activemq < 5.15.11-1ubuntu0.1~esm1`. Jammy `activemq < 5.16.1-1ubuntu0.1` (the `~esm1` value was removed in this pass; it does not appear on Ubuntu's page).
- Verified: focal and jammy values match the page.
- Your check: binary name `activemq`; confirm the jammy value.

**R13. CVE-2024-38475, Apache HTTP Server (focal, jammy, noble)**
- Register: focal `apache2 < 2.4.41-4ubuntu3.19`, jammy `apache2 < 2.4.52-1ubuntu4.10`, noble `apache2 < 2.4.58-1ubuntu8.2`.
- Verified: all three values appear on the page.
- Your check: binary name `apache2`.

**R14. CVE-2024-42009, Roundcube Webmail (noble)**
- Register: noble `roundcube < 1.6.6+dfsg-2ubuntu0.1+esm1`
- Verified: value appears on the page.
- Your check: binary name; the ESM status.

**R15. CVE-2024-9680, Mozilla Firefox (focal)**
- Register: focal `firefox < 131.0.2+build1-0ubuntu0.20.04.1`. Jammy and noble have no entries.
- **Disagreement:** an external reviewer stated that Ubuntu lists focal Firefox as "Not in release" and should be rejected. The Ubuntu page I checked lists focal `firefox` as **"Fixed in 131.0.2+build1-0ubuntu0.20.04.1."** "Not in release" appears only for related `mozjs` packages.
- Your check: check the current page and state which source you rely on. This row must not be approved until the disagreement is resolved.

**R16. CVE-2025-24201, Apple WebKit (jammy, noble)**
- Register: jammy `gir1.2-javascriptcoregtk-4.0 < 2.48.0-0ubuntu0.22.04.1`; noble `gir1.2-javascriptcoregtk-4.1 < 2.48.0-0ubuntu0.24.04.1`. QtWebKit (`libqt5webkit5`) and WPE (`libwpewebkit-1.0-3`) are listed as corresponding with no fixed value.
- Verified: the source `webkit2gtk` versions match the page. The page has no fixed statement for `qtwebkit-source` or `wpewebkit`.
- Your check: binary names (`gir1.2-javascriptcoregtk-*`); disposition of QtWebKit and WPE.

**R17. CVE-2025-24813, Apache Tomcat (focal, jammy, noble)**
- Register: focal `libtomcat9-embed-java < 9.0.31-1ubuntu0.9+esm1`; jammy `libtomcat9-embed-java < 9.0.58-1ubuntu0.2+esm2`; noble `libtomcat10-embed-java < 10.1.16-1ubuntu0.1~esm1` and `libtomcat9-java < 9.0.70-2ubuntu0.1+esm1`.
- Verified: source `tomcat9` versions match the page (focal 9.0.31-1ubuntu0.9+esm1, jammy 9.0.58-1ubuntu0.2+esm2, noble 9.0.70-2ubuntu0.1+esm1).
- **Disagreement on binary names:** an external reviewer cites binaries `libtomcat9-java` and `libtomcat10-java`, while the register uses `*-embed-java` names for focal and jammy. Check against the cited USN.

**R18. CVE-2026-109618, PHP (focal, jammy, noble)**
- Register: focal `libapache2-mod-php7.4 < 7.4.3-4ubuntu2.29+esm5`; jammy `libapache2-mod-php7.4 < 8.1.2-1ubuntu2.28`; noble `libapache2-mod-php8.3 < 8.3.6-0ubuntu0.24.04.13`.
- **Defect found:** Ubuntu lists jammy's PHP 8.1 package as `php8.1`, fixed in `8.1.2-1ubuntu2.28`. The register's jammy package name is **wrong** (`libapache2-mod-php7.4` is the PHP 7.4 module). Focal lists `php7.4` at `7.4.3-4ubuntu2.29+esm5`.
- Your check: correct the jammy package name; confirm the binary names for all three releases; confirm the noble version (the page capture was truncated).

**R19. CVE-2026-111497, Google Brotli (focal, jammy, noble)**
- Register: focal `brotli < 1.0.7-6ubuntu0.1+esm1`; jammy `brotli < 1.0.9-2ubuntu0.1`; noble `brotli < 1.1.0-2ubuntu0.1`.
- Verified: all three values appear on Ubuntu's page for CVE-2026-111497 (the CVE is present in Ubuntu's record).
- Your check: binary name `brotli`; confirm the CVE ID against NVD. The 2026 seven-digit ID was flagged earlier as unverified.

### 3.2 Open items

**O1. CVE-2020-15999, FreeType (Chrome)**
- Current decision: map to source package `freetype`, binary `libfreetype6`. The register has no fixed-version row for this yet (`fixed_versions: "none"`).
- Cited evidence: Ubuntu USN-4593-1 lists `libfreetype6` with focal fixed version `2.10.1-2ubuntu0.1`. The source page lists `freetype` with per-release fixed versions, for example `2.10.2+dfsg-3ubuntu1` for noble.
- Your check: confirm the USN and the binary name; if you approve, a fixed-version row must be added.

**O2. CVE-2025-39682, Linux kernel**
- Current decision: **not counted.** Ubuntu records kernel fixes as release strings (for example `6.8.0-86.87` for noble). The matcher does not compare release strings.
- Your check: agree that it stays out until a kernel comparison method is defined.

### 3.3 Windows rows

**W1. CVE-2017-8543, Windows Server 2016**
- Build: `14393.1480` from KB4025339 (official KB title: "OS Build 14393.1480"; product named in article).
- Your check: confirm CVE-2017-8543 is in the KB4025339 CVRF remediation entry for Windows Server 2016.

**W2. CVE-2020-1350, Windows Server 2019**
- Build: `17763.1339` from KB4558998 (official KB title confirmed).
- Your check: confirm CVRF linkage.

**W3. CVE-2020-1350, Windows Server 2016**
- Build: `14393.3808` from KB4565511 (official KB title confirmed).
- Your check: confirm CVRF linkage.

## 4. Things not in the register that you should know about

- **25 aliases** (`aliases.yaml`): all UNRESOLVED. No alias is proposed. Reviewer should confirm none should be promoted.
- **25 Windows rows** not listed above: UNKNOWN. They have no reliable KB title build, or the product name is not in the KB article.
- **Matcher** (`orchestrator/internal/ubuntumatch/`): the approval gate blocks every row until a human independent review is recorded. Please review the Debian version comparison and the gate logic.

## 5. What to send back

Please return one of these forms:

**Form A: a row table** (preferred)

| Row | Decision (PASS / CONDITIONAL / REJECT / UNVERIFIED) | Evidence (URL, USN number, or package) | Required correction | Notes |
|---|---|---|---|---|

**Form B: a short written note** covering each row ID (R1 to R19, O1, O2, W1 to W3) with its decision and evidence.

**Please also state:**
1. Your name and role, and whether you are independent of the curator (Tausif).
2. The date of your review, written by you.
3. Which Ubuntu source you relied on where it conflicts with another source (R15 and R17 in particular).

**Please do not** fill in the `independent_reviewer` or `review_date` fields in the register yourself. We will record your decision in the register with your name and date after you send it. If you are not independent of the curator, say so, and we will record the review as curator-only.

## 6. What happens after your response

1. We record each decision in the register under your name and the date you give.
2. We make the corrections you request (for example R18's jammy package name, and any binary-name changes).
3. Rows with a PASS decision and a completed evidence trail become eligible for the matcher's gate.
4. The matcher still produces no results for real hosts until a separate decision wires it into a scan or API, and until a release decision is made.

Nothing in this package is approved. Independent review is pending.
