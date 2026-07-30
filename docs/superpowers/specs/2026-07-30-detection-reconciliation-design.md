# Detection Reconciliation — Design Spec

**Sub-project C of the Unified Analytics Layer initiative.** Sub-project A (`internal/analytics`
foundation) and Sub-project B (Unified Dashboard Shell) are both done and merged to `main`. This
sub-project addresses the "Detection" category the parent initiative's original decomposition
explicitly deferred: `pathcorrelation.Correlate`, `internal/coverage.Compute`, and
`GetCoverageAnalytics` were flagged as three concepts that might need reconciling.

## Goal

Determine what, if anything, needs unifying across Detection's three "coverage" concepts, and
extract the one that's a real duplication-of-effort problem (`GetCoverageAnalytics`, ~270 lines
of computation inline in a handler) into a proper package, matching the pattern Sub-project A
already established for Campaigns.

## Investigation: are these three concepts actually the same thing?

No. Read all three implementations before proposing anything. They answer three legitimately
different questions:

1. **`pathcorrelation.Correlate().Score`** (`internal/pathcorrelation/correlate.go:36-106`) — a
   graph/attack-path-weighted detection-effectiveness score. Computed over the attack-path
   graph's edges and choke points, using `RunLookup`/`RuleLibrary` to determine per-edge
   `DetectionStatus`, then a weighted score across annotated paths. Already exposed via Sub-project
   A's `analytics.FleetExposure.Correlation()` — no new work needed here.

2. **`coverage.Compute`** (`internal/coverage/matrix.go:28-41`) — a content-existence matrix: for
   a given technique, does a simulation/detection-profile/purple-exercise/compliance-mapping
   *exist at all*. Explicitly documented in its own package doc comment as "a read-only diagnostic
   view, not a new storage model," and its handler (`internal/api/coverage_handlers.go`) already
   has a doc comment stating it is "distinct from `GET /api/coverage/analytics` ... no overlap, no
   shared code path." Already cleanly factored: a well-tested package (`matrix_test.go`) with a
   thin (~45-line) handler. It's actor-parameterized (filtered by ATT&CK group), not a fleet-wide
   snapshot, so it doesn't fit `internal/analytics`'s "one `Compute` call per category" shape the
   way the fleet-wide categories do. **No changes.**

3. **`GetCoverageAnalytics`** (`internal/api/handlers.go:3076-3462`) — real prevented/detectedOnly
   /missed tallying across recent `scenario_runs`, aggregated per-technique, per-tactic, and
   per-privilege-tier, with a computed `PreventionRate`/`DetectionCoverage`. This is the one still
   living inline in a handler (~270 lines: 7 result/summary types, verdict enum + `verdictString`,
   `normPrivTier`, and the query+tally logic itself) instead of a proper package — the exact same
   shape of problem Sub-project A already fixed for `ListCampaigns`. **This is the real target.**

**A genuine naming collision, found during investigation, not fixed here**: `dashboard.Snapshot`'s
`DetectionCoverage` field (Sub-project A, sourced from `pathcorrelation.Correlate().Score`, shown
on the Executive KPI card) and `GetCoverageAnalytics`'s `AnalyticsSummary.DetectionCoverage` field
(sourced from flat run-level tallying, shown on the ATT&CK Coverage tab) share an identical name
for two differently-computed numbers. Both are real, both are legitimate, but a user could
reasonably expect them to agree and they won't always. Flagged as a known follow-up (a frontend
label change) — explicitly out of scope for this sub-project, which stays backend-only, matching
Sub-project A's precedent.

## Prerequisite: consolidate `detectedTechs`, don't triple it

`GetCoverageAnalytics` calls an unexported helper, `detectedTechs` (`internal/api/campaign_handlers.go:157`),
which turns a run's persisted `detection_summary` JSON plus its `SimulationResult` list into a
per-technique detected/not-detected map (sweep data first, falling back to
`reporting.ClassifyDetectionStatus` per FAIL result). It already has 4 call sites inside
`internal/api`: itself (`campaign_handlers.go:212`), `finding_handlers.go:46`, `handlers.go:2091`,
and `GetCoverageAnalytics` (`handlers.go:3248`). Sub-project A already had to create a *second*
copy (`campaign.detectedTechsFromSummary`, `internal/campaign/store.go:132`) because
`internal/campaign` couldn't call an unexported function in a different package. Extracting
`GetCoverageAnalytics` into yet another new package would require a *third* copy.

Instead: promote it to `internal/reporting.DetectedTechniques(detRaw []byte, results
[]models.SimulationResult) map[string]bool` — moved verbatim, exported. `internal/reporting`
already owns `ClassifyDetectionStatus` (which this function's fallback path already calls), and
the original function's own doc comment already says it "mirrors how `reporting.buildKillChain`
decides detected vs missed" — confirming `internal/reporting` is the right home, not an arbitrary
one.

All 5 call sites (4 in `internal/api`, 1 in `internal/campaign`) switch to calling
`reporting.DetectedTechniques(...)`. The local `detectedTechs` in `campaign_handlers.go` and
`detectedTechsFromSummary` in `internal/campaign/store.go` are both deleted. Net effect: one
canonical definition instead of three, consolidating instead of compounding — this is squarely
in scope for a sub-project named "Detection Reconciliation," not unrelated cleanup.

## Architecture

### 1. `internal/reporting.DetectedTechniques` (prerequisite)

Moved verbatim from `campaign_handlers.go:157-182`, exported, same signature and body. No
behavior change — this is a pure relocation confirmed identical across its 3 existing copies.

### 2. New package `internal/detecteffectiveness`

Moves from `handlers.go:3076-3462`, unchanged in shape:

- Types: `CoverageAnalytics`, `PrivilegeCoverage`, `TierStat`, `PrivGapTechnique`,
  `AnalyticsSummary`, `TechniqueAnalytic`, `TacticAnalytic`, `RunAnalyticSummary` (all exported,
  same JSON tags — the API response shape must not change).
- `type Verdict int` (renamed from unexported `analyticsVerdict` since it's now a public API
  surface) with the same 3 constants (`VerdictMissed`, `VerdictDetectedOnly`, `VerdictPrevented`,
  renamed from `verdictMissed`/etc. for the same reason) and `VerdictString(v Verdict) string`.
- `NormPrivTier(executedAs string) string` (exported, same logic).
- `Compute(ctx context.Context, pool *pgxpool.Pool, scenarioID, agentID string, limit int)
  (CoverageAnalytics, error)` — the query + tallying logic from `GetCoverageAnalytics`, unchanged
  except calling `reporting.DetectedTechniques` instead of the deleted local helper.

### 3. `internal/analytics.DetectionEffectiveness`

```go
func DetectionEffectiveness(ctx context.Context, pool *pgxpool.Pool, scenarioID, agentID string, limit int) (detecteffectiveness.CoverageAnalytics, error) {
	return detecteffectiveness.Compute(ctx, pool, scenarioID, agentID, limit)
}
```

Thin pass-through, matching `analytics.Campaigns`' exact shape from Sub-project A.

### 4. `GetCoverageAnalytics` handler shrinks

```go
func (h *Handler) GetCoverageAnalytics(w http.ResponseWriter, r *http.Request) {
	scenarioID := r.URL.Query().Get("scenarioId")
	agentID := r.URL.Query().Get("agentId")
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	result, err := analytics.DetectionEffectiveness(r.Context(), h.db, scenarioID, agentID, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
```

The query-param parsing (including the `limit` clamp) stays in the handler — it's HTTP concern,
not analytics — matching how `ListCampaigns` kept its own response-shaping in Sub-project A.

## Non-goals

- No changes to `pathcorrelation` or `internal/coverage` — both confirmed already correctly
  factored and conceptually distinct.
- No frontend changes — the `DetectionCoverage` naming collision is flagged, not fixed, per your
  decision to stay backend-only matching Sub-project A's precedent.
- No API contract changes — `GET /api/coverage/analytics`'s response shape, query params, and
  JSON field names are unchanged; only where the computation lives moves.
- No change to `finding_handlers.go`, `handlers.go:2091`, or `campaign_handlers.go:212`'s own
  behavior beyond swapping their `detectedTechs` call for `reporting.DetectedTechniques` — same
  inputs, same outputs, verified by existing tests covering those call sites.

## Testing

Confirmed via grep: no existing test in `internal/api` exercises `GetCoverageAnalytics`'s actual
behavior (`rbac_matrix_test.go` only checks the route is registered/permission-gated, not its
response). There is no pre-existing behavioral baseline to protect the way `ListCampaigns` had in
Sub-project A — so this extraction needs new tests written *before* the move, asserting the exact
tallying behavior (prevented/detectedOnly/missed classification, per-tactic/per-tier aggregation,
`PreventionRate`/`DetectionCoverage` math) against the original inline implementation, then
re-run against the extracted `detecteffectiveness.Compute` to prove the move didn't change
behavior. New tests for `detecteffectiveness.Compute` and `reporting.DetectedTechniques` follow
the existing Postgres-backed `TestMain`/`sharedDB` pattern established in `internal/analytics`.
