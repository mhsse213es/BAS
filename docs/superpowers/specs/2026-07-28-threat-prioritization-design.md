# Threat Prioritization — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-28
**Depends on:** Threat Intel Phase 1 (`2026-07-27-threat-intel-phase1-design.md`) — reuses `internal/coverage`, `DetectionProfile.TechniqueIDs`

## Problem

Audspect already has real threat-intel-derived scoring, but every piece of it is either **technique-level** or **scoped to one run/one agent**:

- `internal/reporting.ComputePriorityScore` — technique-level composite (KEV/EPSS/actor-count/verdict/sector-region), live via `/api/ti/priority`.
- `internal/reporting.BuildReadinessScores` — per-ATT&CK-group readiness computed from **one run's** technique matrix, live via `/api/ti/readiness`, with per-actor history via `threat_readiness_history` / `/api/ti/readiness/history`.
- `internal/recommend` (Phase 6, shipped) — technique-level ranked recommendations (`ThreatPriority + CoverageGap + EnvironmentRisk`), live "Recommendations" tab.
- `threat_actor_profiles` table — sectors/regions/confidence/last-seen per actor, persisted by `connector.Scheduler` on every sync.

There is no standing, fleet-wide, always-current **actor-level** score. An operator cannot answer "which threat actors pose the highest risk to us right now" without manually cross-referencing the technique-level tools above. This project builds that missing layer: a reusable `internal/threatpriority` engine with a pluggable factor architecture, a "Threat Prioritization" UI page, and one new input wired into the existing (unmodified) Recommendations engine.

## Non-Goals

- **Not** rebuilding `internal/recommend` — it already does technique-level ranking correctly. This project adds ActorPriority as one more input to its existing composite, nothing else changes.
- **Not** the Intelligence Repository or Knowledge Graph — those normalize *ingestion*; this project scores actors from data already normalized into `threat_actor_profiles` + `attackdata.GroupTechniqueIndex()`. Repository/Graph remain future phases.
- **Not** new connectors (Mandiant, Google TI, Recorded Future, CrowdStrike Intel, Microsoft TI) — separate future work; this engine scores whatever actors the currently-wired connectors (MISP/OpenCTI/OTX/Bundle) surface.
- **Not** Campaign or Scenario drill-down tabs on Actor Details — no Campaign entity exists anywhere in the codebase yet; "Scenarios" would just be the existing Scenario Library filtered by technique, not new surface. Both deferred.
- **Not** a `RecommendationImpactFactor` — considered and dropped as circular (Priority → Recommendations → Impact → Priority) with no clean v1 definition.

## Architecture

### Package: `internal/threatpriority`

```
internal/threatpriority/
  models.go    — ActorPriority, ActorPriorityHistory, FactorResult, Context
  factor.go    — ScoreFactor interface
  registry.go  — DefaultFactors() ordered slice, weight validation
  score.go     — adaptive coverage/validation blend, composite math, tier banding
  engine.go    — Engine: Score(ctx, name), ScoreAll(ctx), SnapshotHistory(ctx)
  history.go   — history read/write against threat_priority_history
```

No dependency on `internal/connector` (would create an import cycle once `connector.Scheduler` calls into this package — see "Scheduler integration" below). Actor roster and technique lists come from `attackdata.GroupTechniqueIndex()` + the `threat_actor_profiles` table directly, the same two sources `internal/reporting.SectorRegionRelevantTechniques` already reads.

### Core types

```go
// FactorResult is one factor's contribution to an actor's composite score.
type FactorResult struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	RawScore    float64 `json:"rawScore"`    // 0-100, factor's own scale
	Weighted    float64 `json:"weighted"`    // RawScore * Weight
	Explanation string  `json:"explanation"` // "19 of 24 techniques uncovered"
	Available   bool    `json:"available"`   // false => "Not yet validated", not 0
}

// Context is what every factor needs to score one actor. Built once per
// actor by Engine.Score, passed to every registered factor.
type Context struct {
	ActorName   string
	TechniqueIDs []string          // this actor's ATT&CK techniques (from GroupTechniqueIndex)
	Profile     *ActorProfile      // threat_actor_profiles row; nil if actor has no persisted profile
	Sectors     []string           // org config (config.ThreatIntelSectors)
	Regions     []string           // org config (config.ThreatIntelRegions)
	Now         time.Time
}

type ActorProfile struct {
	Name       string
	Aliases    []string
	Sectors    []string
	Regions    []string
	Confidence string // "high" | "medium" | "low" | ""
	LastSeen   *time.Time
}

// ActorPriority is one actor's composite score plus every factor's
// contribution, so the UI can always show WHY, never just a bare number.
type ActorPriority struct {
	ActorName string          `json:"actorName"`
	Score     int             `json:"score"` // 0-100
	Tier      string          `json:"tier"`  // Critical/High/Medium/Low — reporting.PriorityTierFor bands
	Factors   []FactorResult  `json:"factors"`

	TechniqueCount   int `json:"techniqueCount"`
	CoverageGapCount int `json:"coverageGapCount"` // techniques with none of sim/detect/purple/compliance

	Trend       string `json:"trend"`               // "up"/"down"/"stable"/"" (no prior snapshot)
	TrendDelta  int    `json:"trendDelta,omitempty"` // signed, vs most recent prior snapshot
}

// ActorPriorityHistory is one snapshot row, written on every connector sync.
type ActorPriorityHistory struct {
	ActorName  string    `json:"actorName"`
	Score      int       `json:"score"`
	RecordedAt time.Time `json:"recordedAt"`
}
```

### `ScoreFactor` interface

```go
type ScoreFactor interface {
	Name() string
	Weight(ctx Context) float64 // NOT a constant — see adaptive weighting below
	Score(ctx context.Context, tctx Context) (FactorResult, error)
}
```

`Weight` takes `Context` (not `()`) because the Coverage/Validation split needs the *tested-technique count* to pick a weight band — a constant-weight factor just ignores the parameter.

### The 9 factors

Validation is intentionally **asymmetric** with Coverage (2 factors, not 4) — this was corrected during plan-grounding after checking the actual verdict data model (`internal/scenario/outcome.go`). `scenario_runs.results[].result` is a strict 3-way outcome (`pass`=control blocked it, `fail`=ran through unblocked, `error`/`skipped`=excluded) with no separate "detected but not prevented" state — `ReadinessScore`'s detection/prevention split comes from a richer per-run report-time computation, not this raw field. And `verification_history`'s `Source`/`Provider` fields distinguish *how* an attestation was entered (automatic/manual/api/migration), not *what kind* of validation it represents — there is no existing field to cleanly split "automated EDR/SIEM detection" from "manual purple-team validation." Rather than invent a split the data can't support, Validation collapses to what's real:

| Factor | Group | Data source | v1 formula |
|---|---|---|---|
| `SimulationCoverageFactor` | Coverage | `internal/coverage.BuildSimulationIndex` over `engine.List()` | % of actor's techniques with `SimulationExists` |
| `DetectionCoverageFactor` | Coverage | `internal/coverage.BuildProfileIndex` over `engine.Profiles()` | % with `DetectionProfileExists` |
| `PurpleCoverageFactor` | Coverage | purple index (same construction as `coverage_handlers.go`'s `CoverageMatrix`, from `exercise.BuiltinTemplates[*].Metadata.ExpectedTechniques`) | % with `PurpleExerciseExists` |
| `ComplianceCoverageFactor` | Coverage | `internal/coverage.BuildComplianceIndex` | % with `ComplianceMappingExists` |
| `PreventionSuccessFactor` | Validation | fleet-wide most-recent verdict per technique from `scenario_runs` (see below) | % of *tested* techniques where `result == 'pass'` (a control blocked it); `Available=false` if actor has zero tested techniques |
| `ValidationSuccessFactor` | Validation | `verification_history` table (`internal/verification.Store`), fleet-wide latest `Active && WorkflowState==StateApproved` record per `technique_id`, regardless of `Source` | % of evidence-validated techniques with `Result` in the pass/detected family — deliberately not named "Detection" or "Purple" since the schema doesn't distinguish them; `Available=false` if actor has zero approved attestations |
| `IntelFreshnessFactor` | Standalone | `ActorProfile.LastSeen` | <30d=100, <90d=60, else 20; `Available=false` if `LastSeen` nil |
| `RelevanceFactor` | Standalone | `ActorProfile.Sectors/Regions` ∩ org `Sectors/Regions`, same overlap rule as `reporting.sectorRegionOverlap` | 100 if either sector or region overlaps, else 0; `Available=false` if org has no sectors/regions configured |
| `ConfidenceFactor` | Standalone | `ActorProfile.Confidence` | high=100/medium=60/low=30/""=`Available=false` |

`SimulationSuccessFactor` (from the original 4-factor Validation sketch) is dropped entirely, not merged — "did the BAS engine execute without error" answers a different question ("can we test this") than Actor Priority needs ("how well-defended are we"), and that capability question is already answered by `SimulationCoverageFactor`. A technique that executed cleanly but was missed by the EDR must not score as a validation success.

`IndustryFactor`/`RegionFactor` are similarly collapsed into one `RelevanceFactor` (sector OR region overlap) rather than two separate factors — `threat_actor_profiles` rarely has both populated for the same actor from a single connector, and scoring an absent dimension as 0 would unfairly punish actors with only sector *or* only region data.

**Future extension, explicitly out of scope here:** if `verification_history` later gains a `domain` column (detection/purple/compliance), `ValidationSuccessFactor` can split into finer-grained factors without changing the engine architecture — the `ScoreFactor` registry just gains more implementations. That's a separate validation-taxonomy project, not coupled to this one.

`PreventionSuccessFactor`'s query, mirrors `internal/recommend.loadCoverage`'s exclusion rule intentionally rather than importing it (that function is unexported and `internal/recommend` isn't meant as a shared utility library):

```sql
SELECT DISTINCT ON (UPPER(r->'technique'->>'id'))
       UPPER(r->'technique'->>'id') AS tid,
       r->>'result'                 AS verdict
FROM scenario_runs sr, jsonb_array_elements(sr.results) r
WHERE sr.status IN ('completed', 'partial')
  AND r->'technique'->>'id' IS NOT NULL AND r->'technique'->>'id' <> ''
  AND r->>'result' NOT IN ('error', 'skipped')
ORDER BY UPPER(r->'technique'->>'id'), (r->>'executedAt')::timestamptz DESC
```

`ValidationSuccessFactor`'s query, against `verification_history` (Detection Validation's attestation table — genuinely different data from `scenario_runs`: this is human/API-attested outcomes, not automated on-host verdicts):

```sql
SELECT DISTINCT ON (technique_id) technique_id, result
FROM verification_history
WHERE active AND workflow_state = 'Approved' AND result IN ('Detected', 'NotDetected')
ORDER BY technique_id, verified_at DESC
```

(`NotApplicable` excluded from the denominator, same discipline as `scenario_runs`' error/skipped exclusion — it means the check didn't apply, not that detection failed. Success predicate: `result == verification.ResultDetected`, i.e. the exported `"Detected"` constant, not `"NotDetected"`.)

### Adaptive Coverage/Validation weighting

Reuses `ReadinessScore.ConfidenceBand`'s exact tested-count thresholds (`internal/reporting/insights.go`) so the UI's language stays consistent with the existing Readiness tab:

```go
// blendWeights returns (coverageWeight, validationWeight) for an actor with
// validatedCount techniques carrying a real verdict. Mirrors the tested-count
// bands ReadinessScore.ConfidenceBand already uses (<5 Low, 5-9 Medium, >=10 High).
func blendWeights(validatedCount int) (coverage, validation float64) {
	switch {
	case validatedCount >= 10:
		return 0.20, 0.80
	case validatedCount >= 5:
		return 0.60, 0.40
	default:
		return 0.90, 0.10
	}
}
```

`IntelFreshnessFactor`, `RelevanceFactor`, `ConfidenceFactor` sit outside the Coverage/Validation blend, each fixed at **5% flat weight (15% total)**. The blended `coverage`/`validation` fractions from `blendWeights` are scaled to fill the remaining **85%**: each of the 4 Coverage-group factors gets `coverage*0.85/4` weight, each of the 2 Validation-group factors gets `validation*0.85/2`. Concretely, at the `<5 validated` band (`coverage=0.90, validation=0.10`): each Coverage factor = 19.125%, each Validation factor = 4.25%, each of the 3 flat factors = 5% — `4×19.125 + 2×4.25 + 3×5 = 100%`.

A factor with `Available=false` is excluded from the composite entirely (its weight is redistributed proportionally across the remaining available factors, not scored as 0) — this is what makes "Not yet validated" genuinely neutral instead of a hidden penalty.

### Roster resolution — reuses, doesn't duplicate, existing name-matching

`internal/reporting.SectorRegionRelevantTechniques` already solves "match a `threat_actor_profiles.name/aliases` row against ATT&CK's canonical STIX group name" via its unexported `normalizeActorName`. Rather than write a third copy of this matching (a second copy already exists nowhere else — this would be the second, not third, but still worth avoiding), **export** it:

- Modify `internal/reporting/insights.go`: add `func ResolveActorTechniques(name string, aliases []string) (techIDs []string, canonicalGroup string, ok bool)`, built from the existing `normalizeActorName` + `attackdata.GroupTechniqueIndex()` loop. Refactor `SectorRegionRelevantTechniques` to call it instead of inlining the match.
- `internal/threatpriority.Engine.ScoreAll` queries `SELECT name, aliases, sectors, regions, confidence, last_seen FROM threat_actor_profiles` (the *roster* — only actors real connectors have actually surfaced, not all ~200 MITRE groups `GroupTechniqueIndex` knows about; requires the `confidence` column added above), then calls `reporting.ResolveActorTechniques` per row to get `TechniqueIDs` for the `Context`.

This is one of two cross-cutting changes in this project; everything else is additive.

The second: `threat_actor_profiles` does **not** currently persist confidence — its DDL (`internal/db/postgres.go:1096`) only has `name/aliases/sectors/regions/source/last_seen/updated_at`. `connector.ThreatActor.Confidence` exists on the Go struct but `upsertActorProfiles` (`internal/connector/scheduler.go:248`) never writes it. `ConfidenceFactor` needs this column, so this project adds it:

```sql
ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS confidence text NOT NULL DEFAULT ''
```

and extends `upsertActorProfiles`'s `INSERT`/`ON CONFLICT` to include `a.Confidence`.

### History persistence

New table (same idempotent-DDL style as `threat_actor_profiles`, added to `internal/db/content_schema.go`):

```sql
CREATE TABLE IF NOT EXISTS threat_priority_history (
	id          bigserial   PRIMARY KEY,
	actor_name  text        NOT NULL,
	score       int         NOT NULL,
	tier        text        NOT NULL DEFAULT '',
	tenant_id   text        NOT NULL DEFAULT 'default',
	recorded_at timestamptz NOT NULL DEFAULT NOW()
)
CREATE INDEX IF NOT EXISTS tph_actor_time ON threat_priority_history(actor_name, recorded_at DESC)
```

`tenant_id` included from creation (not bolted on later via `ALTER TABLE`) since the platform's multi-tenancy work is already underway — matches how `threat_readiness_history` had to retrofit it.

### Scheduler integration

`connector.Scheduler.sync()` (`internal/connector/scheduler.go:164`) already calls `s.upsertActorProfiles(actors)` right after merging actors from all sources. Add one call immediately after it:

```go
s.upsertActorProfiles(actors)

if s.priorityEngine != nil {
	if err := s.priorityEngine.SnapshotHistory(context.Background()); err != nil {
		log.Printf("[connector] threat-priority snapshot: %v", err)
	}
}
```

`Scheduler` gains a `priorityEngine *threatpriority.Engine` field, set via a new `NewScheduler` parameter (nil-safe — a `nil` engine just skips scoring, same discipline the rest of `sync()` already applies to a `nil` pool). `internal/connector` importing `internal/threatpriority` is one-directional and safe: `threatpriority` never imports `connector`.

`Engine` separates compute from persist so a GET request never has a side effect:
- `ScoreAll(ctx)` — computes every actor's `ActorPriority` live (read-only), populating `Trend`/`TrendDelta` by reading (not writing) each actor's most recent `threat_priority_history` row. Used by `GET /api/threat-priority/actors` and by the Recommendations handler's max-rollup map.
- `SnapshotHistory(ctx)` — calls `ScoreAll` internally, then writes one `threat_priority_history` row per actor. Called **only** from the Scheduler hook above, so history granularity matches "intelligence changed," not request or run cadence — directly realizing the "Continuous Intelligence" vision item with no separate polling logic, since connector sync already IS the change-detection trigger. A first-ever score for an actor leaves `Trend=""`.

## Recommendation Engine Integration

`internal/recommend.RecommendationScore` (`score.go:81`) changes from a 3-term to a 4-term composite:

```go
// Composite weights — must sum to 1.0.
const (
	wActor       = 0.25
	wThreat      = 0.35 // was 0.50
	wCoverage    = 0.25 // was 0.30
	wEnvironment = 0.15 // was 0.20
)

func RecommendationScore(actorPriority, threatPriority, coverageGap, environmentRisk int) int {
	s := wActor*float64(clamp100(actorPriority)) +
		wThreat*float64(clamp100(threatPriority)) +
		wCoverage*float64(clamp100(coverageGap)) +
		wEnvironment*float64(clamp100(environmentRisk))
	return clamp100(int(math.Round(s)))
}
```

`internal/recommend.Build` gains a new parameter, following the file's own stated convention ("caller builds it once," same pattern as the `*attackpath.Graph`/`Summary` params — `recommend` never builds these itself):

```go
func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int, sectors, regions []string, actorPriorityByTechnique map[string]int) (Recommendations, error)
```

`actorPriorityByTechnique` is `nil`-safe: a missing entry scores 0 on the Actor term, degrading gracefully — identical to how a `nil` graph already makes every technique score 0 on `EnvironmentRisk` today.

The caller (`GetRecommendedSimulations` in `internal/api/recommend_handlers.go`) builds this map by calling `threatpriorityEngine.ScoreAll(ctx)` once, then for every technique ID taking the **max** `Score` among actors whose `TechniqueIDs` include it (per the earlier max-rollup decision — a technique used by even one Critical actor should read as urgent, not averaged down by low-priority actors sharing it).

## API

Two new read-only (Viewer+/`tierAny`, matching every other `/api/ti/*` and `/api/coverage/*` route) endpoints in a new `internal/api/threatpriority_handlers.go`:

```
GET /api/threat-priority/actors
  → []ActorPriority, sorted Score desc then ActorName asc (same determinism
    convention as internal/recommend's sort). Roster = every threat_actor_profiles
    row; empty profile → each factor Available=false, composite still computed
    from whatever factors ARE available.

GET /api/threat-priority/actors/{name}
  → ActorPriorityDetail { ActorPriority; History []ActorPriorityHistory (last 30
    snapshots); UncoveredTechniques []string (this actor's techniques with none
    of sim/detect/purple/compliance — feeds the "Coverage Gap" stat and the
    Actor Details "Techniques" tab) }
```

Route registration in `routes.go`, immediately after the existing `/api/coverage/*` block:

```go
r.Get("/api/threat-priority/actors", h.ThreatPriorityActors)
r.Get("/api/threat-priority/actors/{name}", h.ThreatPriorityActorDetail)
```

Plus the corresponding `routeMatrix` entries in `rbac_matrix_test.go` (`tierAny`) — Phase 1's final regression already demonstrated this is a real, easy-to-miss requirement, not optional.

`Handler` gains `WithThreatPriority(e *threatpriority.Engine) *Handler`, same attachment pattern as `WithReporting`/`WithScheduler`.

## UI

New "Threat Prioritization" tab (`data-tab="threat-priority"`), added to `orchestrator/wwwroot/index.html` following the exact structural pattern the Technique Coverage tab (Phase 1) just established: nav item, tab panel, JS load function, wiring into `TAB_TITLES`/`activateTab()`'s array/`showTab()`.

**Landing (ranked list):**

```
#1  APT29        Critical   Score 91   Trend ▲ +8   Gap: 19 techniques
#2  FIN7         High       Score 74   Trend  —     Gap: 8 techniques
...
```

Each row clickable → drill-down.

**Actor Details drill-down** (v1 scope — Overview / Techniques / Coverage / History / Recommendations only, per Non-Goals):

- **Overview** — composite score, tier, every `FactorResult` with `Explanation` text (this is the "APT29 is ranked #1 because: ..." view), `Available=false` factors rendered as "Not yet validated" not 0%/blank.
- **Techniques** — this actor's `TechniqueIDs`, each flagged covered/uncovered.
- **Coverage** — the `UncoveredTechniques` list from the detail endpoint, i.e. the concrete gap list.
- **History** — line chart from `History []ActorPriorityHistory`.
- **Recommendations** — filtered view of the existing `/api/recommend/simulations` results to just this actor's `TechniqueIDs` (client-side filter of data already fetched for the Recommendations tab; no new endpoint).

Structural verification only (matches every prior tab addition this session) — not live-browser-tested unless requested.

## Testing

- `internal/threatpriority`: unit tests per factor (`Score` with known `Context` inputs → expected `RawScore`/`Available`), `blendWeights` boundary tests (4/5/9/10 validated techniques), `Engine.ScoreAll` against a seeded Postgres testcontainer fixture (mirrors `internal/coverage`'s and `internal/connector`'s existing test patterns).
- `internal/reporting`: `ResolveActorTechniques` unit tests (exact match, alias match, no match) plus re-run of existing `SectorRegionRelevantTechniques` tests unchanged (behavior-preserving refactor).
- `internal/recommend`: existing tests updated for the new `RecommendationScore` signature and `Build` parameter; new tests for `actorPriorityByTechnique` nil-safety and the max-rollup behavior.
- `internal/api`: handler tests for both new endpoints (empty-roster case, populated case), `rbac_matrix_test.go` updated in the same task that adds the routes (not deferred to a "final regression" surprise like Phase 1).
- Full regression (`go test ./... -count=1`, `go build ./...`, `go vet ./...`) as the final plan task, same as every prior deliverable this session.
