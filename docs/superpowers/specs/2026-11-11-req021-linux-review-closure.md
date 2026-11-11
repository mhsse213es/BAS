# REQ-021 Linux mapping review: closure note

**Date:** 2026-11-11
**Closed by:** Tausif (curator), on the basis of the independent review by Zain dated 2026-11-11 (`Review.txt`).
**Source of truth:** `docs/superpowers/specs/req021-spike/reviewed_mappings.yaml`

## Closed

- Independent review of the Ubuntu mapping register, by Zain, 2026-11-11.
- Approved rows: 21 (18 Ubuntu, 3 Windows). Scope limits from the review are applied, including focal-only for CVE-2021-1870 and CVE-2021-1871.
- Disputed items decided: Firefox jammy excluded (CVE-2022-26486), FreeType binary row added (CVE-2020-15999), kernel not counted (CVE-2025-39682).
- Corrections applied: PHP jammy binary `libapache2-mod-php8.1`; ActiveMQ jammy `~esm1` removed.
- Matcher approval gate tested against the approved set (`orchestrator/internal/ubuntumatch/`).
- Stale review documents marked superseded.

## Deferred (separate work, does not block this closure)

1. **Zain's USN citations unverified.** Ubuntu returned server errors when they were opened. Version strings were checked against Ubuntu's tracker. Re-check when the USN pages load.
2. **FreeType binary version.** `libfreetype6` is taken at the source version. Not checked against dpkg.
3. **CVE-2022-22965 (Spring) coverage gap.** `libspring-aop-java` is rejected. The spring-beans and spring-webmvc binaries are not in the register, so this CVE has no coverage.
4. **Redis CVE-2022-0543.** CONDITIONAL, not eligible. Needs a decision on the Debian-specific mapping.
5. **Kernel CVE-2025-39682.** Not counted. Needs a kernel-release comparator.
6. **Commit `43025b8e` message.** It says "19 Ubuntu rows less R8, R9, and O2"; the correct count is 18 Ubuntu rows. The approved total of 21 is correct. Not amended, since the commit is pushed.
7. **25 Windows UNKNOWN rows.** Separate workstream.
8. **25 product aliases.** All UNRESOLVED. Any alias needs its own evidence and review.
9. **Matcher integration.** Nothing calls `ubuntumatch`. No scan or API path, and no release decision.

## Not a claim

Closing this review does not validate Windows coverage and does not authorize production use.
