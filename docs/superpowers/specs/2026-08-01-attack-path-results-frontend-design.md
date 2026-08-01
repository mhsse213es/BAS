# Attack Path Validation — Sub-project B: Results Page & Documentation Redesign

**Status:** Approved for planning
**Depends on:** [2026-07-31-attack-path-results-backend-design.md](2026-07-31-attack-path-results-backend-design.md) (Sub-project A — already shipped)
**Source:** `attackpatvalidtionImprove.txt` (16-point critique, repo root)

## Problem

Sub-project A extended `/api/attackpath/summary` with `scoreDrivers`, `relationshipCounts`, `confidence`, `domainCompromiseStatus`, and coverage fields, and Sub-project A also shipped `pathcorrelation.PrioritizedGap.Remediation` behind the existing `/api/attackpath/correlation` endpoint. None of this is rendered anywhere. The live results page (`wwwroot/index.html`, `renderAttackPath()`) still shows only the pre-Sub-project-A view: four bare KPI cards, a meta bar with a raw "Nodes" count, and three conditional tables — matching the exact "technically accurate but purely descriptive" state the critique document describes. Operators cannot see why the score is what it is, whether the graph is complete, or what to fix first.

The About modal (`openAPAbout()`) separately over-explains collection internals (TCP timeouts, ZIP upload mechanics) that most security analysts don't need, under-organizes prerequisites (flat bullet list, no required/optional distinction), and states a single static Limitations list regardless of what was actually collected.

## Goals

1. Surface every Sub-project A field that currently has zero UI: score drivers, relationship counts, confidence, domain compromise nuance, coverage/completeness.
2. Surface the already-built `pathcorrelation` Gaps/Remediation list — a complete backend capability with no consumer today.
3. Add a top-of-page Findings summary so operators read "what happened" before "what the numbers are."
4. Make results self-interpreting: every metric gets a plain-English reason, not just a number.
5. Restructure the About modal per the critique's documentation points (#12, #13) and replace its static Limitations section with a page-level dynamic one (#14).

## Non-goals

- No change-tracking / diff-across-collections (critique #10) — that's Sub-project C, explicitly deferred.
- No backend changes. Every field this spec renders already exists in `/api/attackpath/summary` or `/api/attackpath/correlation` responses, per the Sub-project A spec's confirmed shapes.
- No modal→drawer conversion or other structural page changes outside what's listed here.
- No new automated frontend test suite — `wwwroot/index.html` has none today and this is a rendering-only change; verification is manual browser QA (tracked in the existing pending-QA backlog memory).

## Data flow

`loadAttackPath()` currently issues one request, `GET /api/attackpath/summary`, and passes the result to `renderAttackPath(d)`. It gains a second, parallel request to `GET /api/attackpath/correlation` (`Promise.all`), and `renderAttackPath` gains a second parameter for the correlation response. Both endpoints already exist and are already used elsewhere in the reporting package — this is a new consumer, not new plumbing. If the correlation call fails or returns no gaps, the new remediation panel is simply omitted (existing conditional-render pattern used by the other three tables today).

## Page sections (top to bottom)

**1. Findings (new, top of page, above the score cards)**
A short bullet list synthesized client-side from fields already on the summary response — domain compromise status, lateral-movement path count, admin-relationship count, session count, AD-relationship presence (from `confidence.missing`). Answers "what happened" before any card. Matches critique #8's example directly. Pure client-side string composition from existing fields; no new data.

**2. Score cards (reworked, same 4-card row layout)**
- *Attack Path Score* — number unchanged; the card becomes expandable (reusing the existing card-click/expand interaction pattern already used elsewhere on the page) to reveal `scoreDrivers` as a ✓/⚠ contributor list with each driver's `Deficit`.
- *Lateral Movement* — sub-labels change from raw "avg 0.5 · max 1" to `Reachable Hosts` / `Average Reach` / `Maximum Reach`, plus a synthesized one-line reason string (critique #2).
- *Domain Compromise* — driven by `domainCompromiseStatus` (`reachable` / `not-observed` / `undetermined`) instead of the current boolean. `undetermined` renders in neutral grey, never green — an absence of AD data must never look identical to "confirmed safe" (critique #11).
- *Graph Scope* — keeps its host/user/group/edge counts, gains one interpretive line beneath them (critique #7), e.g. "Small — 2 hosts observed. No domain relationships collected."

**3. Meta bar (adjusted, not rebuilt)**
The bare "Nodes" count is removed — it's redundant with Graph Scope's breakdown and meaningless out of context (critique #4). "Edges" is relabeled "Relationships" to match section 5's table naming. Graph age gains a Fresh (<24h) / Aging (24h–7d) / Stale (>7d) colored badge next to the existing timestamp text (critique #3, thresholds per your confirmed choice).

**4. Coverage & Confidence (new panel)**
Two side-by-side blocks reusing the existing card/table visual language:
- Coverage: `coverage.targetsRepresented` of `coverage.targetsRequested` ("N of M requested targets represented in the graph" — never "collected," matching the project's established coverage-wording rule), `coverage.completeness` as a colored badge (Full/Limited/Minimal/Unknown), SharpHound availability.
- Confidence: `confidence.level` badge, `confidence.based` as a ✓ list, `confidence.missing` as a ✕ list.
Directly answers critique #5 and #6.

**5. Observed Relationships (new table)**
`relationshipCounts` rendered via the existing `apTable()` helper, one row per edge kind (SMB, WinRM, RDP, admin-to, has-session, and any others the backend returns). All kinds are always shown, including zero-count ones (greyed, not hidden) — a confirmed zero is itself informative (critique #9).

**6. Priority Remediation (new panel, from `/api/attackpath/correlation`)**
Renders `Gaps`, which the backend already ranks by priority. Each row: priority badge, source→target edge pill (reusing `apNodePill`/`apArrow`), `Reason`, `Remediation`. Satisfies critique #15 and #16 directly — this is the one section with zero prior UI precedent on this page, built new but from data the backend has produced since Sub-project A.

**7. This Collection's Limitations (new, page-level, dynamic)**
Composed client-side from `confidence.missing` + `coverage` fields into a short contextual bullet list, e.g. "SharpHound disabled · Only 2 targets supplied — results may underestimate lateral movement" (critique #14's literal example). This is distinct from the About modal's Limitations section below, which stays static/generic documentation — this panel is instance-specific to the collection just viewed.

## Documentation: About modal restructuring

- **Prerequisites** — regrouped from a flat bullet list into three explicit headed groups: Required, Recommended, Optional (critique #13).
- **"What the agent does during collection"** — the step-by-step implementation detail (TCP connect/1.5s timeout, ZIP upload, server-side parsing) moves into a collapsible "Technical Details" subsection, collapsed by default. The section's higher-level what/why content stays inline (critique #12).
- **Limitations section** — stays as-is (static, evergreen, always-true statements about the feature). It is not replaced; it's now complemented by the new page-level dynamic panel in section 7 above, which covers the per-collection case the critique's example (#14) actually describes.
- All other About modal sections (edge-type table, "what the graph tells you," SharpHound enrichment, the blue "Interpreting results" callout, security-impact-of-collection) are already aligned with the critique and are unchanged.

## Implementation notes

- All new panels reuse existing helpers (`apCard`, `apTable`, `apNodePill`, `apArrow`, `apColor`, `apBandColor`, `_fmtDuration`) — no new visual language introduced.
- This is a single-file change (`orchestrator/wwwroot/index.html`): `loadAttackPath()`, `renderAttackPath()`, and the About-modal HTML block (`openAPAbout()` region).
- No backend/API/Go changes of any kind.

## Testing / verification

No automated test suite exists for `wwwroot/index.html`. Verification is manual: load a run with a populated attack-path graph, confirm all 7 sections render correctly including zero-count and missing-data edge cases (undetermined domain compromise, empty gaps list, zero-count relationship kinds). This page will be added to the existing pending-manual-QA backlog once implemented, consistent with how prior sub-projects (Global Search, Run Workspace, Variant Sweep, Dashboard) were tracked.
