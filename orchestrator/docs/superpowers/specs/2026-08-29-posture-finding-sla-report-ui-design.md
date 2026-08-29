# Posture Finding SLA Report UI — Design

**Status:** Sub-project D2 of the Posture/Compliance SLA initiative (Phase 9
of the original Fleet Job Engine 10-phase proposal,
[[project_endpoint_health_remediation]], Sub-project 6, 2026-08-03). Builds
directly on Sub-project D1 (`2026-08-29-posture-finding-sla-reporting-design.md`,
DONE, commits `b06c654`..`ad1eea9`), which shipped `GET /api/sla/report`.
This is the **first UI work in the entire SLA initiative** — Sub-projects A,
B, C, and D1 were all API-only, zero `wwwroot` changes.

## Goal

Render `GET /api/sla/report`'s fleet-wide compliance data (overall summary,
per-severity breakdown, monthly trend, recently-resolved history) in the
real dashboard (`orchestrator/wwwroot/index.html`), reusing existing visual
patterns exactly — no new CSS, no new frontend conventions, matching the
discipline Sub-project 13b (Initiative layer UI) already established in
this exact codebase.

## Grounding: what already exists

Confirmed by reading the current `wwwroot/index.html` before designing
anything:

- **No existing view renders posture findings or any SLA data anywhere** —
  this is genuinely new UI surface, not an extension of something that
  already shows this data.
- The existing **Remediation** tab (`#tab-remediation`) is thematically
  close but conceptually different: a per-finding, prioritized fix-it list
  (`renderRemTiles`/`renderRemList`), not a fleet-wide compliance trend
  report. Not the right home.
- The **Reports** tab (`#tab-reports`) already has the exact right shape: a
  grid of report cards (`.dash-panel`, e.g. "Posture report", "Audit pack",
  "Compliance evidence"), where one card (`onclick="showTab('compliance')"`)
  opens a dedicated sub-tab (`#tab-compliance`) styled with a `‹ Reports`
  back-link, `.sec-hdr` header, KPI area, and `.tbl-wrap` table. This is the
  template to mirror.
- Reusable components confirmed present and directly applicable:
  `.kpi-row`/`.kpi-card.stat-tile` (the tile shape `renderRemTiles` already
  builds), `.bar-row`/`.bar-label`/`.bar-track`/`.bar-fill` (the hand-rolled
  percentage-bar component already driving the ATT&CK-tactic-coverage and
  top-failures bars, including its severity-threshold color convention:
  `>=80%` success, `>=50%` warning, else danger), `findingSevBadge(sev)`
  (the existing Critical/High/Medium/Low badge helper, same color mapping
  this report's severities already use), `.tbl-wrap`+`<table>`, and the
  global helpers `apicall`, `x` (HTML-escape), `fmtDate`, `showToast`.
- No JS charting library exists anywhere in this codebase (`bar-row` is the
  only "visual bar" pattern, pure CSS) — confirmed by grep, not assumed.
- `showTab(name)` is a single central dispatcher (`if (name === 'X')
  loadX();` for each tab) that fires each tab's load function on open.

## Scope

**In scope:** a new Reports-grid card + a new sub-tab rendering exactly
`GET /api/sla/report`'s 4 data facets (overall, bySeverity, monthlyTrend,
recentlyResolved).

**Explicitly out of scope**, decided during brainstorming:
- **`GET /api/sla/breaches`** (the live currently-breached list) — a
  different job ("what needs attention right now" vs. "how are we
  performing"), belongs on a future operational surface, not this page.
- **`GET`/`PATCH /api/sla/policies`** (severity deadline editing) — a
  configuration action, belongs on a future Admin/settings surface, not
  this page.
- **Any new top-level nav item** — this lives inside the existing Reports
  tab, per the placement decision below.
- **Any new CSS or visual convention** — every component this page uses
  already exists in `wwwroot/index.html`.
- **Any charting library** — the monthly trend renders as a plain table,
  matching this codebase's existing no-JS-charting convention.

## Placement

New card in the Reports grid, alongside the existing three:

```html
<div class="dash-panel" style="cursor:pointer" onclick="showTab('sla-report')">
  <div class="dash-panel-body">
    <div class="kpi-label">SLA Compliance</div>
    <div style="font-weight:600;color:var(--text);margin:0.3rem 0">Fleet SLA report</div>
    <div class="tiny muted">On-time resolution rate by severity, trend, recent history</div>
  </div>
</div>
```

New sub-tab `#tab-sla-report`, structured like `#tab-compliance`: a
`‹ Reports` back-link (`onclick="showTab('reports')"`), an `.sec-hdr` with
title "SLA Compliance" and a Refresh button, then the 4 content sections
below. Wired into `showTab`'s dispatcher:
`if (name === 'sla-report') loadSLAReport();` — auto-loads on open (unlike
`tab-compliance`, which waits for a manual "Generate" because it first
needs an agent+framework selection; this report has no such parameters, so
there's nothing to wait for).

## Content layout

Four sections, top to bottom, each reusing an existing component:

1. **Overall KPI tiles** — `.kpi-row` of 4 `.kpi-card.stat-tile` tiles
   (Compliance Rate, On-Time, Late, Currently Open), colored via the
   existing `>=80` success / `>=50` warning / else danger threshold
   already used for the ATT&CK-tactic bars.
2. **By-severity breakdown** — one `.bar-row` per `bySeverity` entry
   (Critical → Low order), bar width = that severity's `complianceRate`,
   label = severity name (same color as `findingSevBadge`), sub-line =
   "`onTime` on-time · `late` late · `currentlyOpen` open".
3. **Monthly trend** — `.tbl-wrap` + `<table>`, one row per `monthlyTrend`
   entry, columns Month / Resolved / On-Time / Compliance Rate, sorted
   chronologically ascending by the frontend (the API doesn't guarantee
   order).
4. **Recently resolved** — `.tbl-wrap` + `<table>`, one row per
   `recentlyResolved` entry (already newest-first from the API), columns
   Agent / Check / Severity (`findingSevBadge`) / Resolved (`fmtDate`) /
   Outcome (a small green "On time" / red "Late" badge from `onTime`).

Empty state (`overall.totalEpisodes === 0`) renders a single
`<div class="empty" style="padding:2rem">No SLA data yet.</div>` in place of
all 4 sections, matching this codebase's existing empty-state convention.

## JS wiring

```js
function loadSLAReport() {
  apicall('/api/sla/report').then(function(rep) {
    window._slaReport = rep;
    renderSLAKPIs(rep.overall);
    renderSLASeverityBars(rep.bySeverity);
    renderSLAMonthlyTrend(rep.monthlyTrend);
    renderSLARecentlyResolved(rep.recentlyResolved);
  }).catch(function(err) { showToast('Failed to load SLA report: ' + err.message, 'error'); });
}
```

A Refresh button (matching the header-row convention already used
elsewhere, e.g. Variant Executor's `⟳ Refresh`) re-calls `loadSLAReport()`
directly — `window._slaReport` is a cache read on nothing else (nothing else
reads it back), it exists only so future extensions of this page have the
last-fetched data available without re-fetching, same as this codebase's
existing `window._rems`/similar per-tab cache variables.

## Testing

This is UI work with no Go test surface — verification is via `node --check`
on the extracted inline `<script>` content (this session's established quick
syntax-validation method for `wwwroot/index.html` changes) plus a real
browser walkthrough once a dev environment is available: open Reports → SLA
Compliance card → confirm the sub-tab renders real seeded data correctly
(KPI tiles, severity bars, monthly trend table, recently-resolved table),
confirm the empty state when no SLA data exists, confirm the `‹ Reports`
back-link and Refresh button both work. If a dev environment isn't
reasonably available when this is implemented, that must be stated
explicitly rather than claiming untested UI work as verified — matching
this session's established practice.

## Migration

None — pure frontend addition, no backend change.
