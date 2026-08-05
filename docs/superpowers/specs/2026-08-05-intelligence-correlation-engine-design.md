# Intelligence Correlation Engine — Phase 1 (Backend) — Design Spec

**Phase 1 of the Intelligence Correlation initiative** (user's own phased plan, given while
reviewing the completed IOC Registry work). Goal, in the user's words: turn four largely
independent systems — Threat Intelligence (MISP/OpenCTI), IOC Pipeline (`run_iocs`/registry),
Scenario Engine, Detection Validation — into one queryable graph, so that later features
(Threat Coverage Analysis, Coverage Against Active Threats, Threat-aware Recommendations,
Automatic Scenario Updates, Executive Metrics, ATT&CK Drift) become "just queries" over this
layer instead of each reinventing the same joins. This phase is backend-only — clean APIs and
data relationships, no UI. UI (IOC-page and actor-page integration) is Phase 2/3, not detailed
here.

## Investigation: what already exists, and two corrections to the assumed model

Read the actual code before designing, per this session's established discipline (the prior IOC
Registry spec made a similar correction to its own assumed model — this isn't a one-off).

**Confirmed real, directly reusable, zero changes needed:**

- **`internal/threatgraph.TechniqueNeighborhood`** (`assemble.go:99`) already computes
  technique→actors (a linear scan of `attackdata.GroupTechniqueIndex()` per call — not a
  precomputed reverse index, but the *result* is already there), plus technique→campaigns/
  malware/tools (`intelligence_campaigns`/`intelligence_malware`/`intelligence_tools` filtered
  by `technique_ids @> [id]`). **Correction to the initial framing going into this
  investigation**: the assumption was that `threatgraph` would need extending with a
  technique→actor reverse edge. It doesn't — `TechniqueNeighborhood` already has it. The
  original "extend threatgraph" approach (approach C as first proposed) shrinks to "reuse
  threatgraph as-is"; the only relationship threatgraph is missing is technique→scenario,
  below.
- **`internal/threatgraph.ActorNeighborhood`** (`assemble.go:179`) already gives
  actor→technique (via `attackdata.GroupTechniqueIndex()[name]`), actor→campaign/malware/tool.
- **`internal/threatgraph.IOCNeighborhood`** (`assemble.go:399`, shipped in the IOC Registry
  work) already gives ioc→scenario/run/agent/technique via `ioc_sightings`.
- **`ioc_sightings.technique_id`**: the IOC→technique hop, populated at extraction time
  (`SubmitRunDetections`), already real data, not aspirational schema.
- **`internal/threatpriority.Engine`** (`engine.go:77-128`) already computes, fleet-wide,
  "what's the latest verdict for this technique": `loadPreventionVerdicts` (from
  `scenario_runs`, `DISTINCT ON` latest `executedAt`) and `loadValidationVerdicts` (from
  `verification_history`, latest `verified_at` among `active AND workflow_state='Approved'`
  rows). Both are currently **unexported methods**, not reusable from outside the package.

**Two real gaps — genuinely new code:**

1. **Technique→Scenario** (which scenario(s), not just whether one exists). The closest
   existing thing, `internal/coverage.BuildSimulationIndex` (`matrix.go:45`), returns
   `map[string]bool` — it marks a technique covered but discards which scenario did it. No
   index anywhere returns scenario IDs/names for a technique.
2. **Validation timestamp availability**. `loadPreventionVerdicts`'s SQL already selects and
   orders by `executedAt` internally (`engine.go:82-89`) but the returned `map[string]string`
   only carries the verdict string, discarding the timestamp before it reaches the caller.
   Without it, "last validated 132 days ago" (the user's own example) isn't computable from the
   current return type.

**A genuine inconsistency, resolved during investigation (second correction):** `threatgraph`
resolves actor→technique via a **raw, unaliased name lookup**
(`attackdata.GroupTechniqueIndex()[name]` — `ActorNeighborhood`, `assemble.go:194`).
`threatpriority` resolves the same relationship via
**`reporting.ResolveActorTechniques(name, aliases)`** (`insights.go:849`) — normalized,
alias-aware matching (so "APT29" and "Cozy Bear" resolve to the same technique set).
These can disagree for any actor with aliases. **Decision: the correlation engine standardizes
on `ResolveActorTechniques`** for its own actor→technique resolution — it's the more correct of
the two, and matches what `threatpriority` (the system already doing fleet-wide per-actor
scoring) relies on. This doesn't change `threatgraph.ActorNeighborhood` itself (out of scope,
its own existing behavior, not touched by this phase) — the correlation engine does its own
resolution rather than calling `ActorNeighborhood` for the actor→technique hop specifically.

## Decisions (confirmed with the user)

1. **Validation status is fleet-wide**, reusing `threatpriority`'s existing latest-verdict
   logic exactly as-is (not per-agent). Matches what Threat Prioritization already shows;
   per-agent granularity is a later addition if it turns out to matter, not built speculatively
   now. The schema supports it (`verification_history.run_id` → `scenario_runs.agent_id`) but
   nothing needs to compute it that way in Phase 1.
2. **Architecture: reuse `threatgraph` as-is for relationships (no changes to it); add a new,
   small `internal/correlation` package for the two things that aren't graph edges** — the
   technique→scenario index, and `Recommendation` (a judgment call — "never tested" vs.
   "recently failed, re-run" vs. "validated, current" — not a relationship, so it doesn't
   belong in `threatgraph`).
3. **`threatpriority` gains two exported functions**, `LoadPreventionVerdicts`/
   `LoadValidationVerdicts`, replacing the current unexported methods (`loadPreventionVerdicts`/
   `loadValidationVerdicts`), with a widened return type carrying the timestamp
   (`map[string]VerdictEntry{Verdict string, At time.Time}` instead of `map[string]string`).
   Both existing call sites in `engine.go` (`buildSharedIndexes`, `scoreActor`) only ever check
   *existence* in these maps (`if _, ok := shared.preventionVerdict[upper]; ok`), never read the
   string value itself for scoring — so widening the value type doesn't change scoring
   behavior, confirmed by reading every call site, not assumed.

## Architecture

### 1. `internal/threatpriority`: export + widen verdict loaders

```go
// VerdictEntry is one technique's latest fleet-wide verdict plus when it was
// recorded -- exported so internal/correlation (and any future consumer) can
// reuse the exact same "what does fleet-wide validation status mean" logic
// instead of re-deriving it.
type VerdictEntry struct {
	Verdict string
	At      time.Time
}

// LoadPreventionVerdicts returns, per technique ID (uppercase), the verdict
// of its most recent scenario_runs result (completed/partial runs only,
// error/skipped excluded) and when that run executed.
func LoadPreventionVerdicts(ctx context.Context, pool *pgxpool.Pool) (map[string]VerdictEntry, error)

// LoadValidationVerdicts returns, per technique ID (uppercase), the most
// recent active+Approved verification_history verdict (Detected/NotDetected
// only) and when it was verified.
func LoadValidationVerdicts(ctx context.Context, pool *pgxpool.Pool) (map[string]VerdictEntry, error)
```

Implementation: same SQL as today's `loadPreventionVerdicts`/`loadValidationVerdicts`, adding
`r->>'executedAt'`/`verified_at` to the `SELECT` list and scanning it into `VerdictEntry.At`.
`buildSharedIndexes` (`engine.go:62-72`) and `sharedIndexes`'s two map fields update their type
from `map[string]string` to `map[string]VerdictEntry`; the two existence-check call sites in
`scoreActor` (`engine.go:190,194`) are unchanged (`if _, ok := shared.preventionVerdict[upper]; ok`
still compiles and means the same thing against the new value type).

### 2. `internal/correlation` (new package)

```go
package correlation

// ScenarioRef is a scenario's stable identity -- just enough to link to it,
// not a full scenario.Scenario copy.
type ScenarioRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ValidationStatus is nil when a technique has never been validated by
// either path (no scenario_runs result, no verification_history entry).
type ValidationStatus struct {
	Verdict string    `json:"verdict"` // e.g. "pass"/"fail" (prevention) or "Detected"/"NotDetected" (validation)
	Source  string    `json:"source"`  // "prevention" | "detection"
	At      time.Time `json:"at"`
}

// Recommendation is the one judgment call this package makes -- everything
// else here is a fetched/joined relationship.
type Recommendation struct {
	Action string `json:"action"` // "run" | "revalidate" | "none" | "no_scenario"
	Reason string `json:"reason"` // human-readable, e.g. "Never validated" / "Last run 132 days ago, undetected"
}

// TechniqueCorrelation is the full correlated view of one ATT&CK technique.
type TechniqueCorrelation struct {
	TechniqueID    string            `json:"techniqueId"`
	TechniqueName  string            `json:"techniqueName"`
	Actors         []threatgraph.Node `json:"actors"`
	Campaigns      []threatgraph.Node `json:"campaigns"`
	Malware        []threatgraph.Node `json:"malware"`
	Tools          []threatgraph.Node `json:"tools"`
	Scenarios      []ScenarioRef      `json:"scenarios"`
	Validation     *ValidationStatus  `json:"validation,omitempty"`
	Recommendation Recommendation     `json:"recommendation"`
}

// ActorCorrelation is one actor's full technique roster, each individually
// correlated -- NOT aggregated into a coverage percentage. Aggregation
// (Threat Coverage Analysis) is a later phase's job, reading this data, not
// this phase's.
type ActorCorrelation struct {
	ActorName  string                  `json:"actorName"`
	Campaigns  []threatgraph.Node      `json:"campaigns"`
	Malware    []threatgraph.Node      `json:"malware"`
	Tools      []threatgraph.Node      `json:"tools"`
	Techniques []TechniqueCorrelation  `json:"techniques"`
}

// IOCCorrelation walks IOC -> technique(s) (via ioc_sightings, already
// real) -> actor(s)/scenario(s)/validation for each.
type IOCCorrelation struct {
	IOCID      string                  `json:"iocId"`
	Type       string                  `json:"type"`
	Value      string                  `json:"value"`
	Techniques []TechniqueCorrelation  `json:"techniques"`
}

type Engine struct {
	pool           *pgxpool.Pool
	scenarioEngine *scenario.Engine
}

func NewEngine(pool *pgxpool.Pool, scenarioEngine *scenario.Engine) *Engine

func (e *Engine) CorrelateTechnique(ctx context.Context, techniqueID string) (TechniqueCorrelation, error)
func (e *Engine) CorrelateActor(ctx context.Context, actorName string) (ActorCorrelation, error)
func (e *Engine) CorrelateIOC(ctx context.Context, iocID string) (IOCCorrelation, error)
```

**`CorrelateTechnique`** (the core building block; `CorrelateActor`/`CorrelateIOC` both call it
per-technique):

0. **Self-review correction**: `TechniqueNeighborhood` returns a **completely empty**
   `Neighborhood` (no self-node, `assemble.go:160-162`) whenever a technique has zero
   actor/campaign/malware/tool relationships — which is most techniques, since
   `intelligence_campaigns`/`malware`/`tools` and `GroupTechniqueIndex` coverage is inherently
   partial. Relying on `Neighborhood.Nodes[0].Label` for `TechniqueName` (the original draft of
   this section) would leave it blank for any technique without a recorded relationship, even
   though the technique itself is perfectly real and may well have a scenario and a validation
   history. `techniqueLabel` (`assemble.go:19-32`, the function `TechniqueNeighborhood` uses
   internally for its self-node) is unexported and just a one-line
   `SELECT name FROM techniques WHERE technique_id = $1` with an ID fallback if unseeded —
   `internal/correlation` runs the same tiny query itself rather than depending on
   `TechniqueNeighborhood`'s self-node, matching this session's established tolerance for this
   scale of duplication between independent read paths (`internal/db.GetRunIOCsEnriched` vs.
   `GetRunIOCs` is the precedent).
1. `threatgraph.TechniqueNeighborhood(ctx, pool, techniqueID)` → split `Neighborhood.Nodes` by
   `Type` into `Actors`/`Campaigns`/`Malware`/`Tools` (skip the technique's own self-node, when
   present).
2. `scenariosForTechnique(techniqueID)` — new, mirrors `coverage.BuildSimulationIndex`'s
   iteration over `e.scenarioEngine.List()`/`sc.Steps`, but appends `ScenarioRef{sc.ID, sc.Name}`
   per match instead of setting a bool.
3. Look up `techniqueID` (uppercased) in the shared prevention/validation verdict maps (built
   once per `CorrelateActor`/`CorrelateIOC` call across all their techniques — see below — or
   loaded fresh for a single standalone `CorrelateTechnique` call). Prevention checked first,
   then validation, matching `threatpriority.scoreActor`'s own precedence (`engine.go:190-196`).
4. `computeRecommendation(validation, len(scenarios) > 0)`:
   - No validation, has scenario(s) → `{"run", "Never validated"}`.
   - No validation, no scenario → `{"no_scenario", "No scenario available for this technique"}`.
   - Validation exists, verdict is a failure/undetected outcome → `{"revalidate", "Last run <N> days ago, <verdict>"}`.
   - Validation exists, verdict is a pass/prevented/detected outcome → `{"none", "Validated <N> days ago"}`.

**`CorrelateActor`**: `reporting.ResolveActorTechniques(actorName, aliases)` for the technique
roster (aliases loaded from `threat_actor_profiles` if a row exists, empty slice otherwise —
`ResolveActorTechniques` already tolerates that, matching `threatpriority.Score`'s own handling
of an actor with no profile row). Build the two verdict maps **once** via the new exported
`threatpriority.LoadPreventionVerdicts`/`LoadValidationVerdicts` (not once per technique — same
"shared indexes built once per call" discipline `threatpriority.Engine` already established),
then call a shared-indexes variant of the `CorrelateTechnique` body per technique. Also surfaces
campaign/malware/tool from `threatgraph.ActorNeighborhood` at the actor level (not
per-technique — an actor's malware/tools aren't specific to one technique in the existing
`intelligence_malware`/`intelligence_tools` schema).
**Disambiguation**: `ActorNeighborhood` also resolves and returns its own technique nodes/edges
internally (`assemble.go:194`, the unaliased `GroupTechniqueIndex()[name]` path this spec
explicitly does not standardize on) — `CorrelateActor` must filter `ActorNeighborhood`'s
returned `Nodes` to `Type` `campaign`/`malware`/`tool`/`sector`/`region` only, discarding any
`technique`-type nodes it contains, since the actor's technique roster comes exclusively from
`ResolveActorTechniques` (step 1 above), not from this call. An actor with no
`threat_actor_profiles` row returns an empty `Neighborhood` from `ActorNeighborhood`
(`assemble.go:184-186`) — correct, not a bug: no campaign/malware/tool data exists for an actor
nothing has synced a profile for.

**`CorrelateIOC`**: `threatgraph.IOCNeighborhood(ctx, pool, iocID)` for the IOC's own
type/value plus its technique nodes (already real via `ioc_sightings.technique_id`); for each
distinct technique found, run the same per-technique correlation body (shared verdict maps
built once, as above).

### 3. API layer — 3 new endpoints

```go
r.Get("/api/correlation/technique/{id}", h.CorrelateTechnique)
r.Get("/api/correlation/actor/{name}", h.CorrelateActor)
r.Get("/api/correlation/ioc/{id}", h.CorrelateIOC)
```

`tierAny` (Viewer+), matching every other read-only endpoint in this codebase (`GetIOCs`,
`GetIOCAnalytics`, `KnowledgeGraphNeighborhood` are all `tierAny`). Each handler is 5 lines,
mirroring `GetIOCAnalytics`'s shape exactly: parse the URL param, call the engine method, `200`
+ `respond(w, result)` on success, `500` on error (technique/IOC-not-found returns an empty
correlation, not a 404 — matches `threatgraph.Lookup`'s existing "unknown ID → empty
Neighborhood, not an error" convention, so a client doesn't need two different empty-vs-error
code paths).

`Handler` gains a `correlationEngine *correlation.Engine` field and
`WithCorrelation(e *correlation.Engine) *Handler`, mirroring `WithThreatPriority` exactly
(`handlers.go:165-169`). Wired in `cmd/server/main.go` alongside the existing
`threatpriority.NewEngine(pool, scenarioEngine, sectors, regions)` call, using the same `pool`/
`scenarioEngine` already in scope there.

## Non-goals

- **No aggregation/rollup** (coverage percentages, "79% validated against APT29") — reads this
  phase's per-technique data, is a separate later phase (Threat Coverage Analysis).
- **No UI** — Phase 2/3 per the user's own plan.
- **No per-agent validation granularity** — confirmed fleet-wide with the user; schema supports
  it later if needed, not built speculatively now.
- **No recommendation *generation* beyond the 4-state judgment above** (no "new MISP campaign
  contains 3 uncovered techniques" style proactive alerting) — that's Phase 4 (Recommendation
  Engine) in the user's own plan, which consumes this correlation layer, doesn't duplicate it.
- **No changes to `threatgraph` or `threatgraph.ActorNeighborhood`'s existing (unaliased)
  actor→technique behavior** — the correlation engine does its own alias-aware resolution
  instead of calling into `ActorNeighborhood` for that specific hop; `threatgraph`'s existing
  callers (the knowledge-graph UI-facing endpoint) are unaffected.
- **No changes to `ioc_sightings`, `iocs`, or any IOC Registry code** — this phase only reads
  `ioc_sightings.technique_id`, already populated.
- **No OTX/MISP/OpenCTI `adversary_names` → `threat_actor_profiles` name-matching** — flagged
  during investigation as a real gap (OTX-reported adversary names on `ioc_enrichment` don't
  currently join back to `threat_actor_profiles`), but the IOC→technique→actor path above
  already gives a correlation for IOCs whose technique classification is known, without needing
  this second, fuzzier name-matching path. Revisit only if IOC-provided adversary names turn out
  to be a load-bearing signal later.

## Testing

- `internal/threatpriority/engine_test.go`: existing tests referencing
  `loadPreventionVerdicts`/`loadValidationVerdicts` (or `sharedIndexes` built from them) updated
  for the renamed/exported functions and widened `VerdictEntry` return type. New test: a
  verdict's `At` timestamp round-trips correctly (seed two runs for the same technique at
  different times, assert the *later* one's timestamp comes back, matching the existing
  `DISTINCT ON ... ORDER BY ... DESC` "latest wins" behavior already tested for the verdict
  string itself).
- `internal/correlation/engine_test.go` (new), `TestMain`/`sharedDB` pattern (matching every
  Postgres-backed package this session):
  - `CorrelateTechnique` for a technique with a known actor (seed `threat_actor_profiles` +
    rely on `attackdata.GroupTechniqueIndex()`'s real bundled data for a real technique ID),
    asserts `Actors` populated.
  - `CorrelateTechnique` for a technique covered by a real scenario file (via
    `scenarioEngine.List()`) asserts `Scenarios` non-empty; a technique with no scenario
    asserts `Scenarios` empty and `Recommendation.Action == "no_scenario"`.
  - `CorrelateTechnique` with a seeded `scenario_runs` prevention verdict asserts
    `Validation.Source == "prevention"` and `Recommendation.Action` reflects the verdict
    (pass → `"none"`, fail → `"revalidate"`).
  - `CorrelateTechnique` with no verdict at all (never run) asserts `Validation == nil` and
    `Recommendation.Action == "run"` (given a scenario exists) or `"no_scenario"` (given none
    does).
  - `CorrelateActor` for an actor with 2+ techniques asserts each technique's correlation is
    independently correct (mixed validated/unvalidated), and that the verdict maps are built
    once, not once per technique (assert via query count or a similar mechanism already used
    elsewhere in this codebase's tests for "shared indexes built once" claims — check
    `threatpriority`'s own tests for the established pattern before inventing a new one).
  - `CorrelateIOC` for a seeded `ioc_sightings.technique_id` asserts the IOC's technique(s)
    correlate correctly, reusing the same per-technique assertions above.
- `internal/api/correlation_handlers_test.go` (new): each of the 3 endpoints returns 200 with
  the expected shape against seeded data; RBAC matrix gains 3 entries (`tierAny`, no permission
  constant needed — matches `GetIOCs`/`GetIOCAnalytics`'s existing unauthenticated-tier rows).
