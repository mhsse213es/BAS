# Scenario Page Drill-Down Redesign — Design

**Date:** 2026-07-20
**Status:** approved (design), ready for planning
**Scope:** Frontend only — `orchestrator/wwwroot/index.html` (+ its tracked hardlink twin `orchestrator/cmd/server/wwwroot/index.html`). No Go / API / schema changes except one client-side field-mapping fix.

## Purpose

Today the Scenarios tab (`#tab-scenarios`) stacks two sections (Endpoint Mastery,
Standard & Custom), each an `<h3>` title above a full grid of detail-heavy `.card`
tiles. Everything is expanded at once, so the page is a long wall of large cards.

This redesign turns it into a **two-level drill-down**: a compact **category landing**,
then a **category tile view** of small tiles that reveal full detail in a
**click-pinned overlay**. Goal: scan-first navigation, less vertical noise, and detail
on demand — without changing what any scenario action does.

## Approved decisions (locked with the user)

- **Navigation:** drill-in sub-page (landing → category), not an inline accordion.
- **Overlay interaction:** click-to-pin with hover as preview only. Hover shows the
  overlay; click / tap / Enter / Space **pins** it (persistent); ESC or outside-click
  closes. Touch behaves exactly like click. Driven by JS state, not hover-only CSS.
- **Grouping dimension:** **Source** (Built-in / Custom / Threat-Intel) — scenarios have
  no severity field (verified: `stripeColor` is an id-hash palette, `severity` exists
  only on findings/remediations). Source is the one clean, non-overlapping classifier.
- **Landing cards:** show scenario count **plus** the Built-in · Custom · Intel breakdown.
- **Category view:** tiles grouped by Source in **collapsible** sub-sections.
- **OS:** shown as tile badges **and** a filter (not a grouping dimension).
- **MITRE:** shown as tile badges and available to the existing search; **not** the
  primary grouping.
- **Threat Actor Library:** left as its own separate panel, untouched.
- **Animation:** 150–200ms fade on view switches and overlay open.
- **No virtualization** — one category at a time renders few enough tiles.
- **Preserve all existing JS entry points** (Run / Clone / Edit / Customize / Delete /
  Builder / Modal / Picker) — only *where* they render moves.

## Data grounding (verified against source)

| Need | Field | Status |
|---|---|---|
| Source classifier | `s.intelSource ? 'intel' : (s.source \|\| 'builtin')` | Canonical, already at `index.html:5582`. Reuse verbatim. |
| OS badges + filter | `s.supportedOs` (`scenario/types.go:194`, `json:"supportedOs"`) | **API returns it; `loadScenarios` mapper drops it.** One-line fix: add `supportedOs: s.supportedOs || []` to the map at `index.html:5531`. |
| MITRE badges/facet | `s.mitrePhases` (`types.go:162`) | Mapped already (`index.html:5539`). |
| Endpoint Mastery membership | `id` starts `em-` OR tag `endpoint-mastery` | Existing logic at `index.html:5595`. Reuse. |
| Tile stripe | `stripeColor(s.id)` | Decorative id-hash; kept as-is (not severity). |

## Architecture

### View state

One module-level variable drives everything:

```
scenarioView   = 'landing' | 'em' | 'other' | 'search'
overlayPinned  = null | scenarioId          // which tile's overlay is pinned open
collapsedSrc   = { em:{...}, other:{...} }   // per-category, per-source collapse state
```

`renderScenarios()` becomes a **dispatcher** keyed on `scenarioView`:
- `landing` (and search box empty) → render the **category landing**.
- `em` / `other` → render the **category view** (back bar + source-grouped tile grid).
- `search` (search box non-empty) → render the **search-results view** (explicit
  "Search results for: <q> (n)" header + Back), so navigation never changes silently.

Typing in the existing search box sets `scenarioView='search'`; clearing it returns to
`landing`. The existing source-filter `<select>` and the new OS filter apply within
whatever view is showing.

### Browser history (lightweight, self-contained)

Drill-in / search calls `history.pushState({scenarioView, key}, '', …)`; a `popstate`
listener restores `scenarioView` from the entry so the **browser Back button** returns
to the landing. This is scoped entirely to the scenario sub-view and does **not** touch
the global `localStorage` (`bas_last_tab`) tab system. Entering the Scenarios tab resets
to `landing`.

### DOM structure (replaces `#em-section` + `#other-section`)

```
#tab-scenarios
  .sec-hdr  (unchanged: title, search, source filter, +New, Upload, Refresh)
  + OS filter <select> added to the header controls
  #sc-landing          (category cards; shown when scenarioView==='landing')
  #sc-category-view    (shown for 'em' | 'other' | 'search')
     .sc-backbar       ( ‹ Back    <CATEGORY / "Search results for: q"> (n) )
     #sc-tile-grid     (source-grouped collapsible sub-sections of compact tiles)
  #adversary-section   (Threat Actor Library — untouched)
```

### Category landing card

Per category (Endpoint Mastery, Standard & Custom): title + total count + a summary line
`N Built-in · M Custom · K Intel`. `role="button"`, `tabindex="0"`, click/Enter/Space →
`openScenarioCategory(key)`.

### Compact tile

Resting state (small, fixed height): severity **stripe** + scenario **name** + **OS
badge(s)** + optional **MITRE** badge (first phase, "+N" if more). `tabindex="0"`,
`role="button"`, `aria-expanded`. The tile is **not** `overflow:hidden` so the overlay
can escape.

### Detail overlay (click-pinned)

- A `.sc-tile-detail` panel, **~420px wide**, drops from the tile (`position:absolute;
  top:100%`), flush (no gap) so the cursor reaches its buttons. `z-index` above siblings.
  Fades in 150–200ms.
- **Content = the current full card body**, reused verbatim from `scenarioCardHTML`:
  intel badge / custom badge, name, `descHtml(...)` description, tags + OS badges, footer
  meta, and the action buttons (Run / Clone / Edit / Customize / Delete). All existing
  `onclick` handlers unchanged.
- **Reveal logic (JS, not hover-only):**
  - Mouse hover over a tile → show that tile's overlay as a *preview* (unpinned).
  - Click / tap / Enter / Space on a tile → `overlayPinned = s.id` (pinned); a second
    activation, ESC, or outside-click → `overlayPinned = null`.
  - A pinned overlay stays open regardless of mouse movement (fixes the diagonal-exit
    dismiss problem).
  - Only one overlay open at a time.
- Buttons inside the overlay stop click propagation so using an action doesn't toggle the
  pin.

## Rendering split

`scenarioCardHTML(s)` is refactored into:
- `scenarioDetailHTML(s)` — the **existing** card body (both intel and normal variants),
  unchanged output, minus the outer `.card` wrapper.
- `scenarioTileHTML(s)` — compact face + `.sc-tile-detail` wrapper around
  `scenarioDetailHTML(s)`.

`renderScenarios()` partitions matches by category, then within a category by source
group, emitting collapsible `<section>`s of `scenarioTileHTML`.

## Accessibility

- Tiles and category cards are keyboard-operable (`tabindex="0"`, `role="button"`,
  Enter/Space) and expose `aria-expanded`.
- Click-to-pin means touch and keyboard users get the same first-class interaction as
  mouse users — no hover-only trap.
- ESC closes the pinned overlay; focus returns to the originating tile.

## Non-goals

- No backend/API/schema change (the one client-side `supportedOs` mapper line is not a
  backend change — the API already returns the field).
- No severity on scenarios (doesn't exist; not fabricated).
- Threat Actor Library panel unchanged.
- No change to what Run / Clone / Edit / Customize / Delete / Builder actually do.
- No virtualization / lazy rendering.

## Testing & verification

This SPA has no automated browser-test harness (consistent with prior UI work — static
verification only). Verification is:
- **Static:** balanced markup, no duplicate element IDs, every referenced function / CSS
  class / JSON field confirmed to exist, `scenarioDetailHTML` output byte-identical to the
  old card body for both variants.
- **Manual visual spot-check** on the running dashboard: landing counts, drill-in, Back
  (in-app + browser), hover-preview vs click-pin, ESC/outside-close, OS filter, source
  collapse, and every action button still firing its original handler.
- **Twin sync:** edit `wwwroot/index.html`, then confirm `git status` shows **both**
  tracked paths changed (hardlink) and commit both.
