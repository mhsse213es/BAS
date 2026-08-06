# Sidebar Icon Redesign Design

**Goal:** Give every left-sidebar navigation item in `orchestrator/wwwroot/index.html` its own distinct, semantically-relevant icon — fixing the 4 groups of duplicate/near-duplicate icons found this session, and touching up the rest for consistency, without copying any competitor's actual icon glyphs or branding.

## Background

A competitor screenshot (Trend Micro Vision One, `trendvisionUI.PNG`) showed every left-nav item with a distinct, on-topic icon. Comparing against our own sidebar (`orchestrator/wwwroot/index.html:1262-1429`, the `<nav class="sidebar-nav">` block) surfaced real duplication bugs, not just a style gap:

- **Dashboard**, **Variants**, and **Technique Coverage** all share the same 2×2-grid icon.
- **Coverage** and **Exposure Explorer** both use a plain concentric-circle icon.
- **Endpoint Mastery** and **Verification** both use a shield-with-checkmark icon.
- **Settings** and **Integrations** both use a near-identical gear icon.
- **Recommendations** and **Threat Prioritization** both use a near-identical 5-point-star icon.

All icons are hand-authored inline SVG following one consistent style: `viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" class="nav-icon"`, no external icon font/library. This spec keeps that exact convention — it's a content change (which shapes), not a style-system change.

## Scope

Per the approved design (reviewed as a full before/after sidebar mockup), this is a full pass over all ~24 nav items, not just the 8 in direct conflict — so items with weak-but-not-literally-duplicated icons (e.g. Recommendations' star duplicating Threat Prioritization's) also get fixed, avoiding a mismatched result where some icons look freshly designed next to others that still look generic.

**Kept unchanged** (already distinct, no conflict, no rework needed): Dashboard (grid — wins the conflict, most canonical fit), Scenarios (target), Live Runs (play triangle), Campaigns (bar chart), Reports (document), Verification (shield-check — wins the conflict, most apt fit), Attack Paths (node graph), Agents (device), Threat Prioritization (star — wins the conflict, most apt fit), Settings (gear — wins the conflict, most canonical fit), Detections (waveform pulse), Audit Logs (list).

**Redesigned** (11 items):

| Item | Old | New | Rationale |
|---|---|---|---|
| Coverage | concentric circles (dup) | gauge/speedometer with needle | coverage = a measured percentage |
| Variants | 2×2 grid (dup) | stacked layers (diamond + 2 chevrons) | variant = multiple versions of one thing |
| Endpoint Mastery | shield-check (dup) | medal with ribbon tails | mastery = an earned achievement |
| Findings | flag (weak path) | cleaner flag-on-pole | same concept, redrawn cleanly |
| IOC Registry | radiating crosshair | price-tag shape with hole | registry = a tagged/labeled indicator |
| Remediation | bandage-like path | wrench | universal "fix it" tool metaphor |
| Exposure Explorer | concentric circles (dup) | open (unshackled) padlock | exposure = something unprotected |
| Recommendations | 5-point star (dup) | lightbulb | idea/suggestion, frees the star for Threat Prioritization |
| Evidence (disabled) | unclear blob shape | folder + magnifying glass | evidence = collected, examined proof |
| Integrations | gear (dup) | electrical plug | standard "connect two systems" metaphor |
| Exercises | EKG-style zigzag | checkered flag on pole | drill/exercise = a race/finish-line metaphor |
| Technique Coverage | 2×2 grid (dup) | dense 3×3 grid | matrix of many techniques, visually denser than Dashboard's 2 big tiles so the two are never confusable again |

Every new shape was drawn in-browser via the visual companion (side-by-side before/after mockup of the real sidebar, dark theme, actual labels) and approved as a set.

## Implementation

Pure HTML/inline-SVG edits inside the existing `<nav class="sidebar-nav">` block — each changed item's `<svg class="nav-icon">...</svg>` inner markup is replaced with new path/shape data. No new CSS classes, no JS changes, no changes to `data-tab`/`onclick` wiring, no changes to any item's label text or position in the sidebar. The 11 exact SVG replacements (verified in the mockup) are:

- **Coverage**: `<path d="M2 12a6 6 0 0 1 12 0"/><path d="M8 12L11 7"/><circle cx="8" cy="12" r="1" fill="currentColor" stroke="none"/>`
- **Variants**: `<path d="M8 1.5 14.5 5.2 8 8.9 1.5 5.2z"/><path d="M1.5 8.2 8 11.9 14.5 8.2"/><path d="M1.5 11.2 8 14.9 14.5 11.2"/>`
- **Endpoint Mastery**: `<circle cx="8" cy="6" r="4.2"/><path d="M8 3.8l.7 1.6 1.7.2-1.3 1.1.4 1.7L8 7.5l-1.5.9.4-1.7-1.3-1.1 1.7-.2z" fill="currentColor" stroke="none"/><path d="M5.5 9.7L4 15l4-2 4 2-1.5-5.3"/>`
- **Findings**: `<path d="M3 1.5v13"/><path d="M3 2h9l-2 2.5L12 7H3z"/>`
- **IOC Registry**: `<path d="M9 2h4.5c.3 0 .5.2.5.5V7L6.5 14.5 1.5 9.5 9 2z"/><circle cx="11" cy="5" r="1" fill="currentColor" stroke="none"/>`
- **Remediation**: `<path d="M11 2.5a3 3 0 0 0-3.9 3.9L2 11.5 4.5 14l5.1-5.1A3 3 0 0 0 13.5 5l-2.1 2.1-1.5-1.5z"/>`
- **Exposure Explorer**: `<rect x="3" y="7" width="10" height="7" rx="1"/><path d="M5 7V4.5a3 3 0 0 1 5.6-1.5"/><circle cx="8" cy="10.3" r="1" fill="currentColor" stroke="none"/>`
- **Recommendations**: `<path d="M8 1.8a4 4 0 0 0-2.3 7.3c.5.4.8 1 .8 1.6v.3h3v-.3c0-.6.3-1.2.8-1.6A4 4 0 0 0 8 1.8z"/><path d="M6.3 13.2h3.4M6.7 14.8h2.6"/>`
- **Evidence** (disabled item): `<path d="M1.5 4.5h4l1 1.3H14.5v7.7h-13z"/><circle cx="10" cy="9.5" r="2.3"/><path d="M11.7 11.2 13.3 12.8"/>`
- **Integrations**: `<path d="M5.5 1.5v3M10.5 1.5v3M4 4.5h8v3a4 4 0 0 1-8 0z"/><path d="M8 11.5v3"/>`
- **Exercises**: `<path d="M3 1.5v13"/><path d="M3 2.2h9l-2.2 2.3L12 6.8H3z"/><path d="M6.5 2.2v4.6M9.5 2.2v4.6"/>`
- **Technique Coverage**: `<rect x="1" y="1" width="4" height="4"/><rect x="6" y="1" width="4" height="4"/><rect x="11" y="1" width="4" height="4"/><rect x="1" y="6" width="4" height="4"/><rect x="6" y="6" width="4" height="4"/><rect x="11" y="6" width="4" height="4"/><rect x="1" y="11" width="4" height="4"/><rect x="6" y="11" width="4" height="4"/><rect x="11" y="11" width="4" height="4"/>`

Each replaces only the inner content of that item's existing `<svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">` wrapper — the wrapper attributes themselves are unchanged.

## Non-goals

- No changes to icon style/system (still hand-authored inline SVG, not a switch to an icon font or library).
- No changes to nav structure, grouping, labels, `data-tab` values, or click handlers.
- No copying of Trend Micro's actual icon glyphs, colors, or branding — only the "every item gets its own distinct icon" property was the target.
- No changes to disabled items' behavior (Evidence, Detections, Audit Logs stay disabled/coming-soon; only their icons are touched where noted).

## Testing

No automated frontend test framework exists for `wwwroot/index.html` (established pattern in this codebase). Verification: a JS syntax check (`new Function()` on the extracted `<script>` block, per this session's established pattern — though this change is pure markup with no `<script>` edits, so this is a formality) plus a manual visual check in a browser — open the dashboard, confirm all 24 sidebar items render a visible, distinct icon, and spot-check that no two icons look alike anymore.
