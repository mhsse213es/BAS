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

# REQ-021: response to external technical review (AI-assisted check, not an independent review)

**Date:** 2026-11-10. **Independent reviewer:** pending a human. Nothing here is an approval.
**Method:** each claim in the external review was checked against Ubuntu's public CVE page (`https://ubuntu.com/security/<CVE>`), saved in `scratchpad/req021-spike/`.

**Important limit found in this check:** Ubuntu's tracker lists **source** packages (for example `php8.1`, `tomcat9`, `webkit2gtk`). The register uses **binary** package names (for example `libapache2-mod-php7.4`, `libtomcat9-embed-java`, `gir1.2-javascriptcoregtk-4.0`). The pages confirm version strings for the source packages. They do not confirm the binary names. Every Ubuntu row therefore has a binary-name dependency that is **UNVERIFIED** unless a Ubuntu security notice (USN) that names the binaries is checked.

## Row-by-row

| Row | Claim | Check result | Status | Action |
|---|---|---|---|---|
| CVE-2022-26486 Firefox, jammy | Exclude jammy: dpkg value does not establish the installed Firefox version | Ubuntu's jammy `firefox` is a snap installer. Jammy fix is `1:1snap1-0ubuntu1`. Focal `97.0.2+build1-…` is a real deb fix. | CONDITIONAL: exclusion holds for dpkg matching; focal row depends on the binary name `firefox` being checked | None. Jammy stays excluded. |
| CVE-2020-15999 FreeType | Binary `libfreetype6` supported by USN-4593-1 (focal 2.10.1-2ubuntu0.1) | Reviewer cites the USN. I did not open the USN in this pass. The source page lists the `freetype` source package with per-release fixed versions. | UNVERIFIED for the binary name (cited USN not opened here) | Reviewer to confirm from USN-4593-1. Register row is still OPEN; no change made. |
| CVE-2025-39682 kernel | Do not count until kernel comparison defined | Ubuntu records kernel fixes as release strings. The spike's dpkg comparison does not define that. | PASS for "not counted now" | None. |
| CVE-2023-46604 ActiveMQ, jammy | Remove `~esm1` value | Page lists jammy `5.16.1-1ubuntu0.1` only. | PASS | **Done:** `~esm1` removed from the jammy list in `reviewed_mappings.yaml`. |
| CVE-2024-9680 Firefox, focal | Reviewer says Focal is "Not in release" and should be rejected | Ubuntu's page I fetched shows focal `firefox`: **Fixed in 131.0.2+build1-0ubuntu0.20.04.1**. "Not in release" is shown for focal on the `mozjs*` packages, not on `firefox`. | **Disagreement.** The page supports the register value. | No change. Reviewer to re-check their copy against the current page and state which they are relying on. |
| CVE-2026-109618 PHP | Jammy uses PHP 8.1 package, not `libapache2-mod-php7.4` | Ubuntu's page lists `php8.1` jammy **Fixed in 8.1.2-1ubuntu2.28**. The register's version value matches. The register's jammy package name (`libapache2-mod-php7.4`) is wrong for jammy. | CONDITIONAL: version correct, package name wrong for jammy | Correct the jammy package to `php8.1` (source) and confirm the binary name before approval. Not changed in this pass. |
| CVE-2025-24201 WebKit | Fixed version belongs to `webkit2gtk`; QtWebKit and WPE need separate disposition | Page lists `webkit2gtk` jammy **Fixed in 2.48.0-0ubuntu0.22.04.1**, which matches the register's version. `qtwebkit-source` and `wpewebkit` have no fixed statement on the page. The register lists `libqt5webkit5` and `libwpewebkit-1.0-3` as corresponding for jammy with no fixed value. | CONDITIONAL. Matcher returns UNKNOWN for those packages (no fixed value), which is the safe outcome. | No change. Reviewer to decide the disposition of QtWebKit and WPE. |
| CVE-2025-24813 Tomcat | Binary names should be `libtomcat9-java` and `libtomcat10-java` | Page lists source `tomcat9`: focal **9.0.31-1ubuntu0.9+esm1**, jammy **9.0.58-1ubuntu0.2+esm2**, noble **9.0.70-2ubuntu0.1+esm1**. Register versions match these. The binary names are not shown on the page. | UNVERIFIED for binary names; versions CONFIRMED | Reviewer to confirm binary names from the cited USN. |
| Windows KB builds (CVE-2020-1350, CVE-2017-8543) | Builds confirmed; CVE-to-KB association needs CVRF check | Builds were confirmed earlier from official KB titles. The KB association came from each CVE's MSRC CVRF remediation entries. | PASS for builds; association PASS from CVRF data in `msrc-*.json` | Reviewer to confirm the CVRF entries directly. |
| 25 aliases | Not supplied | Now in repo: `docs/superpowers/specs/req021-spike/aliases.yaml`. All 25 are UNRESOLVED. | PASS: none approved | None. |
| Matcher logic | Not supplied | In repo: `orchestrator/internal/ubuntumatch/`. Gate blocks all rows until a human independent review is recorded. | PASS as tested; not approved for use | None. |

## Summary

- **Changed in this pass:** one fix, the ActiveMQ `~esm1` value.
- **Disagreement to resolve:** CVE-2024-9680 focal. The current page supports the register.
- **Corrections still needed before approval:** CVE-2026-109618 jammy package name.
- **Unverified binary names (all Ubuntu rows):** the register's binary names need USN or dpkg confirmation.
- **Source-vs-binary issue:** systemic. It affects every Ubuntu row, not just these.

No row is approved by this document. Independent review remains pending.
