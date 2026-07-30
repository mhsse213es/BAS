# Threat Intel Summary — Design Spec

**Sub-project D of the Unified Analytics Layer initiative.** Sub-projects A (`internal/analytics`
foundation), B (Unified Dashboard Shell), and C (Detection Reconciliation) are all done and merged
to `main`. This sub-project builds the "Threat Intel" category the parent initiative's original
decomposition named but never scoped.

## Goal

Unlike Sub-project C (real duplication to reconcile), this is a genuine gap: build a fleet-wide
threat-intel posture summary that doesn't exist today, and surface it on the Operational
dashboard's existing (currently narrow) threat-intel widget.

## Investigation: what threat-intel data exists today, and where

Read the actual current code before proposing anything:

- **The dashboard's only threat-intel content today** is a 2-tile KPI widget (`dash-ti-section` /
  `loadKEVWidget()`, `index.html:6841-6860`) fed by `GET /api/ti/suggest-pack?type=kev`
  (`internal/api/ti_handlers.go:124-191`). That endpoint is a **scenario pack-generation** tool
  (builds a ready-to-POST scenario body from KEV-linked techniques), not a posture summary — the
  widget just happens to extract 2 counts (`techniqueCount`, `totalKevCves`) from its response.
- **`internal/threatpriority.Engine.ScoreAll(ctx) ([]ActorPriority, error)`**
  (`internal/threatpriority/engine.go:274-299`) — the real per-actor prioritization engine,
  already sorted by `Score` descending (then by name, `engine.go:292-297`) — powers the standalone
  "Threat Prioritization" tab (`/api/threat-priority/actors`) and Recommendations
  (`recommend_handlers.go:59`). **Never surfaced on either dashboard.**
- **`internal/intelligence`** (`ListCampaigns`/`ListMalware`/`ListTools`, MISP/OpenCTI-sourced) —
  also never surfaced on the dashboard. Excluded from this sub-project's scope (see Non-goals).
- **`internal/threatgraph`** — confirmed a single-entity knowledge-graph lookup (given one
  technique/actor/campaign/malware/tool ID, return its neighbors:
  `TechniqueNeighborhood`/`ActorNeighborhood`/etc., `internal/threatgraph/assemble.go`). Genuinely
  irrelevant to a fleet-wide summary — there is no "fleet neighborhood" concept.
- **`dashboard.Snapshot`** (Sub-project A) has 4 fields (`AvgRiskScore`, `ExposureScore`,
  `DetectionCoverage`, `AssetCount`) — no threat-intel field, and this sub-project doesn't add one
  to `Snapshot`/`/api/dashboard/current` (see Architecture — this targets the Operational
  dashboard's existing widget, not the Executive KPI row).

**A real architectural wrinkle, unlike every prior `internal/analytics` category**:
`threatpriority.Engine` isn't pool-constructible on demand — it's a pre-built instance carrying
its own `sectors`/`regions` config (`NewEngine(pool, scenarioEngine, sectors, regions)`), already
injected onto `Handler` as `h.threatPriorityEngine` (`internal/api/handlers.go:93`, nilable —
`"nil when not loaded"`). So this category's function signature must accept the Engine as a
parameter, not just a `*pgxpool.Pool` like every prior category.

## Decisions made during brainstorming

1. **Scope: top prioritized actors + KEV exposure only.** Not `internal/intelligence`'s
   campaign/malware/tool counts — a 3rd, less-integrated data source with no existing dashboard
   precedent. Minimal, uses only what's already proven and computed.
2. **This sub-project also touches the frontend**, unlike A and C. The existing `dash-ti-section`
   widget gets extended with the new data, not left as a separate future task — deliberate choice
   to make the new analytics category visibly useful immediately, since (unlike C) this doesn't
   already have a dashboard consumer waiting for it.

## Architecture

### 1. `internal/analytics.ThreatIntelSummary`

```go
func ThreatIntelSummary(ctx context.Context, pool *pgxpool.Pool, tpEngine *threatpriority.Engine) (ThreatIntelSummary, error)
```

- If `tpEngine == nil`, `TopActors` comes back empty rather than erroring — the same "nil when not
  loaded" contract `h.threatPriorityEngine` already follows everywhere else in this codebase.
- Otherwise calls `tpEngine.ScoreAll(ctx)` (already sorted, score descending) and takes the top 5.
- KEV counts come from a new, small, purpose-built SQL query — `COUNT(DISTINCT technique_id)` and
  `COUNT(*)` — using the same `WHERE EXISTS (SELECT 1 FROM art_atomic_tests ...)` filter
  `kevPackTechs` already uses (`ti_handlers.go:202`), for parity with what the existing widget
  currently shows. This is **not** a reuse of `kevPackTechs` itself — that function returns full
  per-technique pack-generation detail (name, tactic, ransomware linkage per technique), a
  different concern from a summary count. Writing a fresh, minimal query here mirrors how
  Sub-project A wrote `FleetRisk`'s SQL fresh rather than reusing a differently-shaped query.

```go
type ThreatIntelSummary struct {
	TopActors            []threatpriority.ActorPriority `json:"topActors"`
	KEVExposedTechniques int                             `json:"kevExposedTechniques"`
	TotalKEVCVEs         int                              `json:"totalKevCves"`
}
```

### 2. New handler `GET /api/analytics/threat-intel-summary`

Thin call: `analytics.ThreatIntelSummary(r.Context(), h.db, h.threatPriorityEngine)`, then
`respond(w, result)`.

### 3. Frontend: extend the existing `dash-ti-section` widget

`loadKEVWidget()` (`index.html:6843-6860`) additionally calls the new endpoint and renders a "Top
Threat Actors" mini-list below the 2 existing KEV tiles, reusing `tpTierBadge()`
(`index.html:4834-4837`) for tier coloring — the same visual language the standalone Threat
Prioritization tab already uses, not a new pattern invented for this widget.

## Non-goals

- No changes to `internal/threatgraph` or `internal/intelligence` — confirmed out of scope per
  your decision.
- No new field on `dashboard.Snapshot` / no change to `GET /api/dashboard/current` or the
  Executive dashboard — this targets the Operational dashboard's existing KEV widget specifically.
- No changes to `GetSuggestPack`/`kevPackTechs` or the pack-generation feature itself — only a new,
  separate, minimal query for summary counts.

## Testing

`internal/analytics/threatintel_test.go` follows the existing Postgres-backed `TestMain`/`sharedDB`
pattern. Since `threatpriority.Engine` requires a `scenario.Engine` and non-trivial setup to
construct meaningfully, tests cover: `tpEngine == nil` → empty `TopActors`, no error (the nilable
contract); KEV count math against seeded `technique_cves`/`cves`/`art_atomic_tests` rows. A test
with a real, non-nil `Engine` scoring actual actor profiles is out of scope for this package's
unit tests — `internal/threatpriority`'s own test suite already covers `ScoreAll`'s correctness;
this package only needs to prove it calls through and slices to top 5 correctly, which can be
verified with a `tpEngine` built from a minimal seeded profile.
