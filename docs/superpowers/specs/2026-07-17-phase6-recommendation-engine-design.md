# Phase 6, Subsystem 2 — Recommendation Engine (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Recommendation Engine — second of Phase 6's three subsystems, per `project_platform_roadmap_2026h2`. Sequenced after [Executive Dashboards](2026-07-17-phase6-executive-dashboards-design.md) (done 2026-07-17); Predictive Risk follows.

## Problem
Phase 6 names three recommendation types: best next simulation, highest-value remediation, missing detections/controls. Investigation found the codebase already holds most of the raw material but nothing joins it into a prescriptive answer:

| Existing | What it does | Why it isn't enough |
|---|---|---|
| `reporting.computePriorityScore` | 0–100 per-technique threat score (KEV +40, EPSS percentile, actor count, fail +10) | Per-run only; unexported |
| `reporting.ActionItem` / `buildActionPlan` | Remediation ranked by score points | Per-run, tactic-level, criticality-blind |
| `pathcorrelation.PrioritizedGap` | Ranked detection gaps by edge | Already shipped and surfaced per-asset via Exposure Explorer |
| `/api/ti/suggest-pack` | Suggests technique packs + a runnable `suggestedScenario` | Static curated pack types, not driven by *your* coverage gaps |
| `/api/coverage/analytics` | Per-technique best verdict across runs | Descriptive, not prescriptive |
| `attackdata.All()` / `/api/techniques/unified` | Full ATT&CK universe / what's actually executable | Not joined to coverage or threat priority |

Nothing answers "what should I run next, and why?"

## Decisions
1. **Scope: best next simulation only.** The other two Phase 6 recommendation types are substantially covered already — `pathcorrelation.PrioritizedGap` does missing-detections per-asset, `reporting.ActionItem` does remediation per-run. Building a third surface for either would duplicate a shipped capability rather than add one. A fleet-wide, criticality-aware remediation ranking (genuinely new, since today's `ActionItem` is per-run and tactic-level) is a candidate fast-follow, explicitly not in this slice.
2. **Ranking folds in environment relevance**, not just threat priority + coverage gap. Every input already ships (SP3 graph/paths, SP4 exposure, SP6 criticality). Threat-priority-only would produce the same recommendation for every customer with the same untested set — essentially what a static curated pack already gives. Environment-awareness is the differentiator and the data is free.
3. **Output emits a runnable `suggestedScenario`**, the same shape `/api/ti/suggest-pack` already returns (`{id, name, description, artTechniques[]}`), consumed unchanged by the existing scenario-creation flow. No new dispatch path; the operator still reviews before running. One-click auto-dispatch was considered and rejected for this slice — auto-dispatching real ATT&CK techniques from a recommendation is a meaningful safety/authorization surface deserving its own design conversation.
4. **KEV/EPSS come from the Relationship Store path** (`technique_cve_relationships`, gated `status='Active' AND effective_confidence IN ('High','Medium')`), modeled exactly on `reporting.populatePriorityScores`' existing queries — not the bare `technique_cves` table. Noted as a pre-existing inconsistency: `/api/ti/suggest-pack`'s `kevPackTechs` still queries `technique_cves` directly. **Not fixed in this slice** (out of scope, unrelated to this feature's own correctness) but flagged for a future cleanup pass.
5. **A recently-tested failing technique is deliberately NOT a top "next simulation."** `CoverageGap = 0` keeps it off this list even though `ComputePriorityScore` grants it a +10 fail bonus. Rationale: you already know it fails — re-running teaches nothing until it's remediated, and the ITSM auto-revalidation loop (`StartRevalidationLoop`) already re-tests on ticket-resolve. Failing techniques are a remediation item, not a testing gap. This is a real judgment call, pinned by a dedicated test.

## Architecture

### New package: `internal/recommend`
Pure aggregator, owns no DB tables, same shape as `internal/dashboard`/`internal/exposure`/`internal/pathcorrelation`.

```go
// Build ranks executable ATT&CK techniques by how much value testing them
// next would add. Nil-safe: an empty fleet / unseeded content returns an
// empty Recommendations, never an error.
func Build(ctx context.Context, pool *pgxpool.Pool, limit int) (Recommendations, error)

type Recommendations struct {
    Techniques        []RecommendedTechnique `json:"techniques"`
    SuggestedScenario SuggestedScenario      `json:"suggestedScenario"`
    HasData           bool                   `json:"hasData"`
}

type RecommendedTechnique struct {
    TechniqueID   string   `json:"techniqueId"`
    Name          string   `json:"name"`
    Tactic        string   `json:"tactic"`
    Score         int      `json:"score"`         // 0-100 composite
    Tier          string   `json:"tier"`          // Critical/High/Medium/Low
    CoverageState string   `json:"coverageState"` // never-tested | stale | recent
    LastTestedAt  *time.Time `json:"lastTestedAt,omitempty"`
    LastVerdict   string   `json:"lastVerdict,omitempty"`
    ThreatPriority     int `json:"threatPriority"`
    CoverageGap        int `json:"coverageGap"`
    EnvironmentRisk    int `json:"environmentRisk"`
    KEV           bool     `json:"kev"`
    EPSSPercentile float64 `json:"epssPercentile,omitempty"`
    ThreatActors  int      `json:"threatActors"`
    Reasons       []string `json:"reasons"`
}

type SuggestedScenario struct {
    ID            string   `json:"id"`
    Name          string   `json:"name"`
    Description   string   `json:"description"`
    ARTTechniques []string `json:"artTechniques"`
}
```

### Pipeline
1. **Universe** — `attackdata.All()`: every authoritative ATT&CK technique.
2. **Executable filter** — keep only techniques that have a real Atomic Red Team test: `EXISTS (SELECT 1 FROM art_atomic_tests a WHERE a.technique_id = t.technique_id)`, the same predicate `kevPackTechs` already relies on. Recommending something that can't be run is noise. **ART-only is deliberate, not an oversight:** the emitted `SuggestedScenario` carries `artTechniques[]`, so a Caldera-only or BAS-builtin-only technique could be ranked but not expressed in the scenario object this slice produces. Widening the executable universe to Caldera abilities and BAS builtins requires widening the suggested-scenario shape too — a coherent fast-follow, out of scope here.
3. **Coverage state** — fleet-wide, from `scenario_runs.results` (status IN ('completed','partial')): most-recent test time and verdict per technique.
4. **Threat priority** — `reporting.ComputePriorityScore(kev, epssPct, actors, verdict)`, fed by queries modeled on `populatePriorityScores`: KEV count via `technique_cve_relationships` JOIN `cves (source='cisa-kev')`; EPSS percentile via `technique_cve_relationships` JOIN `cve_epss` (`MAX(percentile) × 100`); actor count via `attackdata.GroupTechniqueIndex()`. All relationship queries gated Active + High/Medium confidence.
5. **Environment relevance** — build the graph (`attackpath.BuildGraphAndAnalyze`), take its critical paths (`pathcorrelation.DefaultPaths`), map each edge to techniques (`pathcorrelation.DefaultEdgeTechniqueMapper{}.Techniques(edge.Kind)`). A technique scores higher when it traverses an edge on a DA/crown-jewel path, and higher still when the edge's target node carries a high SP6 `CriticalityTier`.
6. **Rank and emit** — sort by score desc, take `limit`, build `SuggestedScenario` from those technique IDs.

### Scoring
Weighted sum, matching the house style of `exposure.ExposureScore`:

```
RecommendationScore = 0.50×ThreatPriority + 0.30×CoverageGap + 0.20×EnvironmentRisk
```

- **ThreatPriority** (0–100): `reporting.ComputePriorityScore` verbatim — no new threat-scoring logic.
- **CoverageGap** (0–100), evaluated top-down on age since the most recent test, so boundaries are unambiguous: never tested → 100; age > 90d → 60; age > 30d → 30; otherwise (age ≤ 30d) → 0. `CoverageState` labels these `never-tested` / `stale` (>90d) / `recent` (≤90d).
- **EnvironmentRisk** (0–100): 0 if the technique maps to no edge in the graph; 50 if it maps to an edge present in the graph; 100 if that edge sits on a DA/crown-jewel path from `DefaultPaths`. +20 (clamped at 100) when the edge's target node's `CriticalityTier` is `critical` or `high`.

`Tier` comes from `reporting.PriorityTierFor(score)` — reusing the shipped Critical/High/Medium/Low bands rather than inventing a parallel set.

### Required exports (`internal/reporting`)
`computePriorityScore` → `ComputePriorityScore`; `priorityTierFor` → `PriorityTierFor`. Rename only — no logic change; `engine.go`'s two call sites and `insights_test.go`'s call sites update accordingly. Same rename-to-reuse precedent as SP5's `mergeActors` → `MergeActors` (2026-07-17).

### API
`GET /api/recommend/simulations?limit=20` (Viewer+, matching `/api/ti/suggest-pack`'s tier — this is a smarter sibling of it). `limit` defaults 20, clamped [1,100]. Returns `Recommendations`; empty history returns an empty `techniques` array, not an error.

**The route must also be registered in `rbac_matrix_test.go`'s `routeMatrix` as `tierAny`.** `TestRBACMatrix_NoDrift` caught exactly this omission during the Executive Dashboards slice — it is a known trap in this codebase, not a surprise.

### UI
New "Recommendations" nav item in the Visibility group, beside Executive Dashboard. A ranked table: technique ID + name, tactic, score with a tier badge, coverage-state chip, threat chips (KEV / EPSS percentile / actor count), environment-relevance indicator, and the reasons list. A "Create scenario from top N" action hands `suggestedScenario` to the existing scenario-creation flow.

Deliberately **not** placed on the Executive Dashboard tab: that tab is trend-consumption for an executive audience; this is an operator's worklist. Reuses the file's established `apicall()` / `x()`-escaping / `.kpi-row` / `apColor` conventions. Both hardlinked copies (`wwwroot/index.html`, `cmd/server/wwwroot/index.html`) get edited and committed together.

## Error handling / cold start
- No ART/Caldera content seeded → empty list, `HasData: false`, no error.
- **Fresh install, zero runs** → every executable technique is never-tested, so the list ranks purely on threat priority. This is the correct and useful cold-start answer ("start with the KEV-listed, actor-heavy techniques"), not a degenerate case.
- No attack-path collections → `EnvironmentRisk = 0` across the board; the engine falls back cleanly to threat-priority + coverage-gap. Never fabricates environment signal it doesn't have.
- Relationship Store empty → threat priority degrades to actor-count from embedded STIX (always bundled, always present).
- Nil-safe throughout, matching `exposure.Build` / `pathcorrelation.Correlate`.

## Testing (TDD)
- `internal/recommend/recommend_test.go` (Docker-backed, `testutil.MustSharedTestDB()`):
  - empty fleet / no seeded content → empty `Recommendations`, `HasData: false`, no error;
  - never-tested KEV-listed technique outranks never-tested no-signal technique;
  - recently-tested technique ranks below never-tested at equal threat priority;
  - **recently-tested failing technique does not dominate the list** — pins Decision 5;
  - environment-relevant technique (edge on a DA path) outranks a non-relevant one at equal threat priority and coverage state;
  - `SuggestedScenario.ARTTechniques` carries exactly the top-N ranked IDs, in order;
  - `limit` is respected.
- `internal/api/recommend_handlers_test.go`: live round-trip; `limit` clamping ([1,100], default 20); empty history returns `[]` not null/error.
- `internal/reporting/insights_test.go`: update the renamed `ComputePriorityScore` / `PriorityTierFor` call sites; existing assertions unchanged (rename only).
- Manual: browser spot-check of the new Recommendations tab — flagged as a known gap in the plan, same as SP4/SP6/Executive Dashboards (no browser tool available in this environment).

## Out of scope
Highest-value remediation and missing-detections/controls recommendation types (Decision 1). One-click auto-dispatch of a recommended scenario (Decision 3). Fixing `kevPackTechs`' legacy `technique_cves` query (Decision 4 — pre-existing, unrelated to this feature's correctness). Any new DB table — this package is a pure consumer. Predictive Risk (Phase 6, Subsystem 3 — its own brainstorm cycle).

## Capture
Vault: new `Recommendation Engine` feature note; Roadmap Phase 6 Subsystem 2 marked done; daily note. An ADR is **not** warranted — the scoring-weight choice here is an implementation calibration, not an architectural trade-off, and Decision 5's judgment call is captured in this spec plus a dedicated pinning test.
