# REQ-021 disputed Linux mappings: Ubuntu evidence (no decisions here)

**Checked:** 2026-11-10, read-only, against Ubuntu's public security tracker (`https://ubuntu.com/security/<CVE>`). Saved copies are in `scratchpad/req021-spike/ubuntu_cve_*.html`.
**Decisions:** none. Each item is for Zain to decide, and his decision must be recorded in his own name.

## CVE-2022-26486 (Firefox, currently counted)

Ubuntu tracker, package `firefox`:

| Release | Status |
|---|---|
| 23.04 lunar, 22.10 kinetic, 22.04 LTS jammy | Fixed in `1:1snap1-0ubuntu1` |
| 21.10 impish | Fixed in `97.0.2+build1-0ubuntu0.21.10.1` |
| 20.04 LTS focal | Fixed in `97.0.2+build1-0ubuntu0.20.04.1` |
| 18.04 LTS bionic | Fixed in `97.0.2+build1-0ubuntu0.18.04.1` |

**Finding:** For jammy, Ubuntu's own record gives a snap-transition string. Its epoch and "snap1" form do not describe a Firefox deb build. The deb builds for other releases are `97.0.2`. A dpkg version comparison against the jammy string is therefore not a meaningful fixed-version check. The mapping is supported for focal, impish, and bionic, but not as currently recorded for jammy.

**Zain's choice:** count the jammy row as is, exclude it for jammy, or count it only after a deb-build source is found.

## CVE-2020-15999 (Chrome FreeType, currently not counted)

Ubuntu tracker, package `freetype`, the source package:

- Fixed in `2.10.2+dfsg-3ubuntu1` for 25.04, 24.10, 24.04 LTS, and 23.10 (other releases listed on the page).
- The page's patch details point to upstream commit `a3b`.
- The `chromium-browser` entries are "Not affected" on the same page.

**Finding:** Ubuntu tracks this CVE against the source package `freetype`. The current register reached `freetype2-demos`, a binary built from the same source, and treated it as a demo binary. The library package is the product the CVE is about. Whether `freetype2-demos` is affected is a question about its contents, not its name.

**Zain's choice:** a mapping to the `freetype` source package, to `libfreetype6` as the library binary, or keep it not counted with this reason recorded.

## CVE-2025-39682 (Linux kernel, currently not counted)

Ubuntu tracker, package `linux`:

| Release | Status |
|---|---|
| 25.04 plucky | Fixed in `6.14.0-34.34` |
| 24.04 LTS noble | Fixed in `6.8.0-86.87` |
| 22.04 LTS jammy, 20.04 LTS focal, others | Not affected |

**Finding:** Ubuntu records kernel fixes as kernel release versions (for example `6.8.0-86.87`), not as a simple package version. The earlier "no package resolves" result came from matching the definition's name. The Ubuntu record gives a usable fixed release for noble and plucky, but the comparison has to use the kernel release form, which the current spike does not do.

**Zain's choice:** how to compare kernel release strings, and whether the kernel row counts at all, given that the register has no kernel mapping logic yet.

## Not decided here

These findings only show what Ubuntu's records say. Each mapping decision belongs to Zain. Nothing in this file changes any register row's status.
