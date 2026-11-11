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

# REQ-021 Review Packet for Zain (designated independent reviewer)

**Purpose:** Everything needed to review the REQ-021 mapping register. Nothing here is approved. Each decision is yours, and you record it in the register with the actual review date. Curator: Tausif.

**Register:** `docs/superpowers/specs/req021-spike/reviewed_mappings.yaml` (24 entries)
**Alias register:** `docs/superpowers/specs/req021-spike/aliases.yaml` (25 entries)

## 1. What to check, per entry

For each mapping, confirm:
- The product and affected component are the ones the KEV entry describes.
- The vendor relationship is supported: an Ubuntu package fixed version, or a Microsoft KB article title build that names the same product.
- The CVE reference and evidence source match.
- Curator and reviewer are different people.

Then record `status` (approve or reject), your name, and the actual review date. Do not backdate.

## 2. Mapping entries

### 2a. Ubuntu candidates (19)
Source: Canonical Ubuntu OVAL (focal, jammy, noble). Snapshot SHA-256 and generator timestamps in `req021-spike/results.json`.
These were built from the same 22 hand-reviewed matches, so your review is the first independent check.

| CVE | KEV product | Ubuntu package(s) | Check |
|---|---|---|---|
| CVE-2020-12641, CVE-2021-44026 | Roundcube Webmail | roundcube | Product match |
| CVE-2021-44228, CVE-2021-45046 | Apache Log4j2 | liblog4j2-java | Product match |
| CVE-2021-40438, CVE-2024-38475 | Apache HTTP Server | apache2 | Product match |
| CVE-2023-46604 | Apache ActiveMQ | activemq | Product match |
| CVE-2022-46169 | Cacti | cacti | Product match |
| CVE-2022-0543 | Redis (Debian-specific) | redis | Product match |
| CVE-2024-9680, CVE-2022-26486 | Mozilla Firefox | firefox | Product match. **CVE-2022-26486 jammy fixed value `1:1snap1-0ubuntu1` looks like a snap transitional version. Check it.** |
| CVE-2026-111497 | Google Brotli | brotli | Product match |
| CVE-2024-42009 | Roundcube Webmail | roundcube | Product match |
| CVE-2026-109618 | PHP | libapache2-mod-php*, php8.3 | Family match. Confirm the PHP runtime package is the affected one |
| CVE-2025-24813 | Apache Tomcat | libtomcat*-java | Family match |
| CVE-2025-24201, CVE-2021-1870, CVE-2021-1871 | Apple WebKit | gir1.2-javascriptcoregtk, libqt5webkit5 | Family match. Confirm that Ubuntu's WebKit packages are affected by these Apple CVEs |
| CVE-2022-22965 | VMware Spring Framework | libspring-aop-java | Family match. CVE-2022-22965 is in spring-beans and spring-webmvc; confirm `aop` is in scope |

**Rejected during hand review (not in the register):** CVE-2015-4852 (WebLogic) matched `openjdk-8-demo`. That is a false match, so it is not counted.

### 2b. Open items (3): curator review required
| CVE | Issue | Current outcome |
|---|---|---|
| CVE-2020-15999 (Chrome FreeType) | OVAL package is `freetype2-demos`, a demo binary, not the library `libfreetype` | Not counted (NO_CORRESPONDING_PACKAGE) |
| CVE-2022-26486 (Firefox) | jammy fixed value looks like a snap version | Counted. Decide whether it stays |
| CVE-2025-39682 (Linux kernel) | Definition matches, but no package name resolves | Not counted (NO_RESOLVABLE_PACKAGE) |

### 2c. Windows candidates (3)
Source: official KB article title build, confirmed against the product name in the article. Each article was fetched from `support.microsoft.com/help/{KB}`.

| CVE | Product | KB | Build | Check |
|---|---|---|---|---|
| CVE-2020-1350 | Windows Server 2019 | KB4558998 | 17763.1339 | Title build and product name confirmed in the article |
| CVE-2020-1350 | Windows Server 2016 | KB4565511 | 14393.3808 | Title build and product name confirmed in the article |
| CVE-2017-8543 | Windows Server 2016 | KB4025339 | 14393.1480 | Title build and product name confirmed in the article |

Windows rows not listed here are UNKNOWN. Most are the .NET Framework KBs, which carry no OS build in their title.

## 3. Alias entries (25): all UNRESOLVED, nothing to approve yet

Each observed product string was checked for an exact match in its KB article. **None matched**, so no alias is supported:
- 4 Server Core strings: the exact string is absent from all four articles. The base product name (for example "Windows Server 2016") is present in each. "Server Core" appears in 0 of the four articles, except one mention in KB4565503.
- 8 Windows 10 version strings: the exact string is absent from their articles. I did not check what wording the articles use instead.
- 13 .NET Framework strings: these describe a component, not the OS build.

**Correction to an earlier commit:** commit `3d64eaa8` described 12 "proposed" aliases. That was wrong. The check above found no source support, so all 25 are UNRESOLVED.

Those strings stay UNKNOWN. Approving any of them would need a new, source-supported proposal first. A reviewer can propose an alias with evidence, but that is a separate decision.

## 4. Open decisions for Zain

1. Approve or reject each of the 19 Ubuntu candidates, and resolve the three open items.
2. Approve or reject each of the 3 Windows candidates.
3. Confirm the alias result: all 25 stay UNRESOLVED unless a new source-supported alias is proposed.

## 5. Recording a decision

Update the register entry: set `status`, `independent_reviewer` (already Zain), `review_date` (the actual date you review it), and `reviewer_status` to reflect the outcome. Then commit the change with your own name on the commit.
