# Run Results Investigation Workspace — Sub-project A: Shell — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-29.
**Depends on:** nothing new — this phase only touches `cmd/server/wwwroot/index.html`'s existing `#results-overlay` drawer and reuses existing dashboard visual primitives (`.kpi-row`/`.kpi-card`, `.dash-panel`, `.dash-soon`, `.ring`, `gaugeSVG`, `sparkSVG`).
**Decomposition:** Sub-project A (this doc) builds the shell + relocates existing functionality with zero new data-aggregation code. Sub-project B (separate, later) adds genuinely new visual components (Attack Progression stepper, Detection-vs-Prevention donut, Top Findings list, Weakness Timeline) and real content for the MITRE ATT&CK / Recommendation tabs.

## Problem

`#results-overlay`'s `.drawer` is a single shared, narrow (520px) slide-in panel used for **4 different purposes**: findings detail, technique detail, the Global Search fallback popup, and full run results (`viewRunResults`). For run results specifically, real, substantial functionality — a Results table, an Attack Flow diagram, a Variant Coverage matrix, a SIEM Detection Rate correlation panel, and 3 analytics tiles (Alert Fatigue & Noise, Attack Surface Age, Endpoint Stability) — is crammed into a cramped vertical stack behind a plain 3-button switcher (`switchResultsView`), forcing excessive scrolling and disconnected navigation. The amount of real analysis already available isn't reflected in how it's presented.

## Non-Goals (this sub-project)

- **No new charting/visualization code.** This phase reuses existing primitives verbatim: `gaugeSVG(value, size, stroke)` and `sparkSVG(data, w, h, color)` (`cmd/server/wwwroot/index.html:12053`/`12041`), `.kpi-row`/`.kpi-card`/`.ring`/`.stat-tile` CSS classes, and the `.dash-panel`/`.dash-soon` card system. Genuinely new components (attack progression stepper, donut chart, top findings list, multi-series weakness timeline) are Sub-project B.
- **No real content for Execution Timeline, Indicators (IOCs), or Endpoint Changes tabs.** These render the existing `.dash-soon` "Coming soon" placeholder pattern and stay deferred indefinitely (explicit decision during brainstorming — no real backing data exists for them today).
- **No real content for MITRE ATT&CK or Recommendation tabs in this sub-project**, even though their underlying data (technique/tactic groupings, `c.remediation`) is confirmed real — building their aggregation/rendering logic is Sub-project B's job, kept out of this phase to keep it a pure relocation-and-restyle with no new data logic.
- **No change to findings/technique/search-fallback drawer behavior, width, or content.** The shared `.drawer` element's default 520px width and existing rendering must stay byte-for-byte identical for those 3 callers.
- **No backend changes.** Everything this phase touches is already-fetched client-side data on the `run` object (`run.score`, `run.results[]`, etc.).

## Architecture

### 1. Shared-drawer width modifier — `run-mode`, scoped and reset

`.drawer-overlay .drawer` currently has one CSS rule (`width: 520px; max-width: 94vw`, `cmd/server/wwwroot/index.html:629-636`) shared by 4 callers: `viewRunResults` (run results — this phase's target), `openFinding`, `openTechnique`, and Phase 2/3's `cmdkResultFallback` (Global Search's fallback popup). Widening it unconditionally would break the latter 3, which are meant to stay compact.

Fix: a CSS modifier that only widens the drawer when explicitly toggled on:

```css
.drawer-overlay.run-mode .drawer { width: 90vw; max-width: 1600px; }
```

`viewRunResults(run)` adds `run-mode` to `#results-overlay` the moment it opens. `closeResults()` — confirmed to be the single close path shared by all 4 callers (the backdrop click and the × button both call it regardless of what's currently displayed) — removes `run-mode` unconditionally, so the drawer always resets to its default compact width on close. `openFinding`/`openTechnique`/`cmdkResultFallback` additionally call `classList.remove('run-mode')` defensively at their own top, so none of the three can ever inherit stale wide-mode state even if some future code path bypasses `closeResults()`.

### 2. New DOM regions inside `.drawer-body`, active only in run-mode

Today's `.drawer-body` has 3 flat sinks — `#results-summary`, `#results-export`, `#results-body` — written into directly by all 4 callers. Run-mode needs a structurally different layout (KPI strip + sticky tab bar + per-tab content), so 3 new sibling containers are added, hidden by default:

```html
<div id="run-kpi-strip" style="display:none"></div>
<div id="run-tabbar" style="display:none"></div>
<div id="run-tab-content" style="display:none"></div>
```

`viewRunResults(run)` hides `#results-summary`/`#results-export`/`#results-body` (their content isn't used in run-mode — the equivalent information moves into the new regions, see §3-§5) and un-hides the 3 new ones. The other 3 callers never touch the new IDs and `viewRunResults` is the only function that ever un-hides them, so their behavior is unaffected.

### 3. Header becomes the command center

`.drawer-header` (currently just `<h3 id="results-title">` + a close button) gains a right-aligned action toolbar for run-mode, populated with the *existing* export actions (`exportRunJSON`, `openRunReport`, `downloadRunPDF`, `downloadRunCSV`) relocated from the old `#results-export` bar, plus any existing Compare/Re-run actions already available for a run row (exact source to be confirmed against the Live Runs table during planning). `results-title`'s content becomes the scenario name plus a status pill, reusing whichever status-badge CSS class the Live Runs table already applies to a run's status (to be confirmed during planning, so the same "Completed"/"Failed"/etc. styling is consistent app-wide, not reinvented here). The header itself needs no new CSS — it's already a sibling of `.drawer-body`, not inside its scroll region, so it's already "fixed while scrolling" by construction; only its *contents* differ for run-mode.

### 4. KPI summary strip — reuses `.kpi-row`/`.kpi-card` + `gaugeSVG`/`sparkSVG` verbatim

The 6-card strip reuses the existing dashboard KPI primitives (`.kpi-row`, `.kpi-card`, `.kpi-label`, `.kpi-value`, `.kpi-sub`, `.ring`/`.ring-c` for gauges, `.stat-tile`/`.stat-spark` for sparklines) and the existing `gaugeSVG`/`sparkSVG` helper functions — no new charting code, no new CSS beyond wiring these into `#run-kpi-strip`. Real data sources, all already present on the `run` object (confirmed during brainstorming):

- **Prevention Rate** — `run.score.preventionScore`, gauge via `gaugeSVG`.
- **Exposure Score** — `run.score.exposureScore`, gauge via `gaugeSVG`.
- **Tactic Coverage** — `run.score.killChainCoverage`, gauge via `gaugeSVG`.
- **Risk Level** — `run.score.classification`/`run.score.trend` (already computed as `'Improving'`/`'Degrading'`/`'Stable'`/`'Baseline'` with an existing color mapping in `viewRunResults`, `cmd/server/wwwroot/index.html:9942-9943`).
- **Detection Rate** — derived exactly the way the existing summary line already computes it: `pass / results.length` from `run.results[]`.
- **Overall Security Score** — if a historical run-score series is available for a sparkline (to be confirmed during planning against whatever score-history endpoint the main Dashboard's own `#dash-gauge` already consumes); otherwise this card shows the current score as a plain value with no sparkline, never a fabricated trend line.

Any card whose backing value genuinely isn't available on `run` renders with an em-dash, never an invented number.

### 5. Sticky tab bar — 11 tabs, replacing the 3-button `switchResultsView` switcher

A new full-width tab bar (styled consistently with the app's existing `.cov-seg` segmented-control visual language, adapted from a compact toggle to a full tab row) replaces `switchResultsView`'s old Results/Attack Flow/Variant Coverage buttons. It sits immediately below the KPI strip inside `.drawer-body` and uses `position: sticky; top: 0` so it stays visible while a tab's content scrolls beneath it — matching "the workspace scrolls as one continuous document; only the tab bar stays pinned."

Tab → content mapping for this sub-project:

| Tab | Content | Status |
|---|---|---|
| Overview | Existing summary line (pass/fail/skip/alerts) + the 3 existing analytics tiles (`renderRunReportExtra`'s Alert Fatigue & Noise Analysis / Attack Surface Age / Endpoint Stability Check), restyled into `.dash-panel` cards as a side column | Real, relocated |
| Attack Flow | Existing `renderAttackFlow(nodes, summary)`, relocated verbatim, full width | Real, relocated |
| Variant Analysis | Existing `renderVariantCoverage(data)`/`loadVariantMatrix`, relocated verbatim | Real, relocated |
| Detection Validation | Existing `loadSIEMCorrelationPanel(runId)`, relocated verbatim | Real, relocated |
| Evidence | Today's Results table (per-technique pass/fail/evidence/remediation rows, currently under `switchResultsView('table')`), relocated and relabeled | Real, relocated |
| Reports | Run metadata (ID/agent/operator/started/completed/duration) + the same 4 export actions restated as a dedicated tab | Real, relocated |
| Execution Timeline, MITRE ATT&CK, Indicators (IOCs), Endpoint Changes, Recommendation | Existing `.dash-soon` "Coming soon" placeholder pattern | Deferred (MITRE ATT&CK / Recommendation → Sub-project B; the other 3 → indefinitely deferred, no real data source) |

### 6. Responsive grid, only where a tab actually has a side column

Per-tab content wraps in a grid container that defaults to `1fr` (full width); only the Overview tab additionally requests a `1fr 340px` two-column layout for its side-column analytics tiles. No other tab gets a forced side column — Attack Flow, Variant Analysis, Detection Validation, and Evidence all need their full width for diagrams/tables, matching "the layout should adapt to the content, not force every page into the same structure." Below a reasonable width breakpoint, Overview's two-column grid collapses to one column (the side-column tiles fall below the summary rather than compressing).

## Testing

This is a single-file vanilla-JS frontend with no automated test harness (confirmed across every prior UI phase this session) — verification is manual, in a real browser:

- Open a finding, a technique, and a Global Search fallback result (via ⌘K) — confirm all 3 still render in the original compact 520px drawer, completely unaffected by this change.
- Open a completed run's results — confirm the drawer expands to ~90vw with the Live Runs page still faintly visible behind it (the existing scrim), the header shows scenario name + status pill + relocated toolbar actions, and the KPI strip renders 6 cards with real gauge/sparkline values or em-dashes where data is genuinely unavailable.
- Click through all 11 tabs — confirm Attack Flow/Variant Analysis/Detection Validation/Evidence/Reports show their real (relocated) content unchanged from before this phase, and the 5 remaining tabs show the "Coming soon" placeholder.
- Scroll a tall tab (e.g. Evidence, on a run with many results) — confirm the tab bar stays pinned/visible while the KPI strip and tab content scroll normally beneath the header.
- Resize the browser narrower — confirm the Overview tab's side column collapses to a single column at a reasonable breakpoint, and the KPI strip's grid reflows without overlap.
- Close the run-results drawer, then immediately open a finding — confirm it's still the compact 520px width (`run-mode` was correctly removed on close).
