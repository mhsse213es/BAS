# Threat Prioritization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standing, fleet-wide, per-actor "Threat Prioritization" score with a pluggable factor architecture, surfaced as a new UI page and wired into the existing Recommendations engine as one more input.

**Architecture:** New `internal/threatpriority` package computes a 0-100 composite `ActorPriority` per threat actor from 9 pluggable `ScoreFactor`s (4 Coverage + 2 Validation + 3 standalone), adaptively weighted by how much real evidence exists. `connector.Scheduler` snapshots history on every sync. `internal/recommend` gains ActorPriority as a 4th scoring term. Two new read-only API endpoints power a new UI tab.

**Tech Stack:** Go, PostgreSQL (pgx/v5), existing `internal/coverage`/`internal/reporting`/`internal/verification`/`internal/exercise` packages, vanilla JS in `wwwroot/index.html`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-28-threat-prioritization-design.md` — read it before starting; this plan implements it exactly, including its two corrections (9 factors not 11; real `verification.Result*` constants not guessed strings).
- No dependency from `internal/threatpriority` on `internal/connector` (avoids an import cycle — `connector.Scheduler` depends on `threatpriority`, not the other way around).
- Every new route needs a `routeMatrix` entry in `internal/api/rbac_matrix_test.go` in the *same task* that adds the route — Phase 1 shipped this as an afterthought and it broke the final regression; don't repeat that.
- All new SQL DDL is idempotent (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`), matching every existing table in `internal/db/content_schema.go`.
- Reuse `reporting.PriorityTierFor` for tier banding — do not invent a second Critical/High/Medium/Low scale.
- `go test ./... -count=1`, `go build ./...`, `go vet ./...` must all be clean before this plan is done (Task 12).

---

### Task 1: Schema — `confidence` column, `threat_priority_history` table, `upsertActorProfiles` update

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go` (append to the `stmts` slice inside `EnsureContentSchema`, right before its closing `}` at line 266)
- Modify: `orchestrator/internal/connector/scheduler.go:248-270` (`upsertActorProfiles`)
- Test: `orchestrator/internal/connector/scheduler_test.go` (extend existing sync test)

**Interfaces:**
- Produces: `threat_actor_profiles.confidence text` column (was missing despite `ThreatActor.Confidence` existing on the Go struct); `threat_priority_history` table (`id, actor_name, score, tier, tenant_id, recorded_at`).

- [ ] **Step 1: Add the DDL**

In `orchestrator/internal/db/content_schema.go`, immediately before the closing `}` of the `stmts` slice (the line right after the existing `ALTER TABLE threat_readiness_history ADD COLUMN IF NOT EXISTS tenant_id ...` statement), add:

```go
		`ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS confidence text NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS threat_priority_history (
			id          bigserial   PRIMARY KEY,
			actor_name  text        NOT NULL,
			score       int         NOT NULL,
			tier        text        NOT NULL DEFAULT '',
			tenant_id   text        NOT NULL DEFAULT 'default',
			recorded_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS tph_actor_time ON threat_priority_history(actor_name, recorded_at DESC)`,
```

- [ ] **Step 2: Update `upsertActorProfiles` to persist confidence**

In `orchestrator/internal/connector/scheduler.go`, replace the existing `upsertActorProfiles` body:

```go
func (s *Scheduler) upsertActorProfiles(actors []ThreatActor) {
	if s.pool == nil {
		return
	}
	ctx := context.Background()
	for _, a := range actors {
		var lastSeen *time.Time
		if !a.LastSeen.IsZero() {
			t := a.LastSeen
			lastSeen = &t
		}
		_, err := s.pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source, last_seen, confidence, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
			 ON CONFLICT (name) DO UPDATE SET
			   aliases = EXCLUDED.aliases, sectors = EXCLUDED.sectors, regions = EXCLUDED.regions,
			   source = EXCLUDED.source, last_seen = EXCLUDED.last_seen, confidence = EXCLUDED.confidence,
			   updated_at = NOW()`,
			a.Name, a.Aliases, a.Sectors, a.Regions, a.Source, lastSeen, a.Confidence)
		if err != nil {
			log.Printf("[connector] upsert actor profile %q: %v", a.Name, err)
		}
	}
}
```

- [ ] **Step 3: Write a test that confidence round-trips**

Append to `orchestrator/internal/connector/scheduler_test.go`:

```go
func TestUpsertActorProfiles_PersistsConfidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := &Scheduler{pool: pool}
		s.upsertActorProfiles([]ThreatActor{{Name: "APT-CONFIDENCE-TEST", Confidence: "high"}})

		var confidence string
		err := pool.QueryRow(context.Background(),
			`SELECT confidence FROM threat_actor_profiles WHERE name=$1`, "APT-CONFIDENCE-TEST").Scan(&confidence)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if confidence != "high" {
			t.Fatalf("confidence = %q, want %q", confidence, "high")
		}
	})
}
```

- [ ] **Step 4: Run the test**

Run: `cd orchestrator && go test ./internal/connector/... -run TestUpsertActorProfiles_PersistsConfidence -v`
Expected: PASS (the schema migration runs automatically via `EnsureContentSchema` at test-container startup — check `internal/testutil/testdb.go` if it doesn't; every other `content_schema.go` table already works this way, so no extra wiring should be needed).

- [ ] **Step 5: Commit**

```bash
git add internal/db/content_schema.go internal/connector/scheduler.go internal/connector/scheduler_test.go
git commit -m "feat(db): persist threat actor confidence, add threat_priority_history table"
```

---

### Task 2: Export `reporting.ResolveActorTechniques`

**Files:**
- Modify: `orchestrator/internal/reporting/insights.go:795-862` (`SectorRegionRelevantTechniques`, `normalizeActorName`)
- Test: `orchestrator/internal/reporting/insights_test.go`

**Interfaces:**
- Produces: `func ResolveActorTechniques(name string, aliases []string) (techIDs []string, canonicalGroup string, ok bool)` — used by `internal/threatpriority` in Task 7.
- Consumes: nothing new; behavior-preserving refactor of existing code.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/reporting/insights_test.go`:

```go
func TestResolveActorTechniques_ExactMatch(t *testing.T) {
	ids, group, ok := ResolveActorTechniques("APT29", nil)
	if !ok {
		t.Fatal("expected a match for APT29")
	}
	if group != "APT29" {
		t.Fatalf("canonicalGroup = %q, want %q", group, "APT29")
	}
	if len(ids) == 0 {
		t.Fatal("expected at least one technique ID")
	}
}

func TestResolveActorTechniques_AliasMatch(t *testing.T) {
	// "Cozy Bear" is a documented APT29 alias in the bundled ATT&CK STIX data.
	ids, group, ok := ResolveActorTechniques("Some Local Name", []string{"Cozy Bear"})
	if !ok {
		t.Fatal("expected an alias match via Cozy Bear")
	}
	if group != "APT29" {
		t.Fatalf("canonicalGroup = %q, want %q", group, "APT29")
	}
	if len(ids) == 0 {
		t.Fatal("expected at least one technique ID")
	}
}

func TestResolveActorTechniques_NoMatch(t *testing.T) {
	_, _, ok := ResolveActorTechniques("Definitely Not A Real Group Name XYZ", nil)
	if ok {
		t.Fatal("expected no match")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestResolveActorTechniques -v`
Expected: FAIL — `ResolveActorTechniques` is not defined.

(If `TestResolveActorTechniques_AliasMatch` fails after Step 3 because "Cozy Bear" isn't in the bundled data under that exact spelling, check `attackdata.GroupTechniqueIndex()`'s source data for APT29's actual alias list and substitute a real one — don't leave the test wrong.)

- [ ] **Step 3: Implement `ResolveActorTechniques` and refactor `SectorRegionRelevantTechniques` to use it**

Replace `SectorRegionRelevantTechniques` in `orchestrator/internal/reporting/insights.go` (lines 795-854) with:

```go
// ResolveActorTechniques matches an actor's name/aliases against ATT&CK's
// canonical STIX group names (attackdata.GroupTechniqueIndex) and returns
// that group's technique IDs. Exact-normalized match only (see
// normalizeActorName) -- no fuzzy matching, so a near-miss returns ok=false
// rather than silently attributing techniques to the wrong actor.
func ResolveActorTechniques(name string, aliases []string) (techIDs []string, canonicalGroup string, ok bool) {
	groupIdx := attackdata.GroupTechniqueIndex()
	normName := normalizeActorName(name)
	for groupName, ids := range groupIdx {
		normGroup := normalizeActorName(groupName)
		if normName == normGroup {
			return ids, groupName, true
		}
		for _, alias := range aliases {
			if normalizeActorName(alias) == normGroup {
				return ids, groupName, true
			}
		}
	}
	return nil, "", false
}

// SectorRegionRelevantTechniques returns the set of technique IDs backed by
// at least one persisted threat_actor_profiles row whose sectors/regions
// overlap the given values. Returns an empty map (no query issued) when both
// sectors and regions are empty. See
// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
func SectorRegionRelevantTechniques(ctx context.Context, db *pgxpool.Pool, sectors, regions []string) (map[string]bool, error) {
	relevant := map[string]bool{}
	if len(sectors) == 0 && len(regions) == 0 {
		return relevant, nil
	}

	rows, err := db.Query(ctx, `SELECT name, aliases, sectors, regions FROM threat_actor_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type profile struct {
		name    string
		aliases []string
		sectors []string
		regions []string
	}
	var profiles []profile
	for rows.Next() {
		var p profile
		if rows.Scan(&p.name, &p.aliases, &p.sectors, &p.regions) != nil {
			continue
		}
		profiles = append(profiles, p)
	}

	for _, p := range profiles {
		if !sectorRegionOverlap(p.sectors, sectors) && !sectorRegionOverlap(p.regions, regions) {
			continue
		}
		techIDs, _, ok := ResolveActorTechniques(p.name, p.aliases)
		if !ok {
			continue
		}
		for _, tid := range techIDs {
			relevant[strings.ToUpper(tid)] = true
		}
	}
	return relevant, nil
}
```

Leave `normalizeActorName` and `sectorRegionOverlap` (lines 856-871 in the original) unchanged — both are still used, just now by `ResolveActorTechniques` too.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -run "TestResolveActorTechniques|TestSectorRegionRelevantTechniques" -v`
Expected: PASS for all — the existing `SectorRegionRelevantTechniques` tests must still pass unchanged, confirming the refactor is behavior-preserving.

- [ ] **Step 5: Commit**

```bash
git add internal/reporting/insights.go internal/reporting/insights_test.go
git commit -m "refactor(reporting): export ResolveActorTechniques for reuse by threatpriority"
```

---

### Task 3: `internal/threatpriority` package skeleton — types, interface, scoring math

**Files:**
- Create: `orchestrator/internal/threatpriority/models.go`
- Create: `orchestrator/internal/threatpriority/factor.go`
- Create: `orchestrator/internal/threatpriority/score.go`
- Test: `orchestrator/internal/threatpriority/score_test.go`

**Interfaces:**
- Produces: `FactorResult`, `ActorProfile`, `Context`, `ActorPriority`, `ActorPriorityHistory` structs; `ScoreFactor` interface; `blendWeights(validatedCount int) (coverage, validation float64)`; `Composite(results []FactorResult) int`; constants `flatWeight`, `coverageValidationPool`, `numCoverageFactors`, `numValidationFactors`.
- Consumes: nothing (this is the foundation task).

- [ ] **Step 1: Create `models.go`**

```go
// Package threatpriority computes a standing, fleet-wide, per-actor
// composite priority score from a pluggable set of ScoreFactors. It has no
// dependency on internal/connector -- connector.Scheduler depends on this
// package, not the reverse, to avoid an import cycle.
package threatpriority

import "time"

// FactorResult is one factor's contribution to an actor's composite score.
// Available=false means "no evidence yet" (rendered as "Not yet validated"
// in the UI), not a zero score -- a factor with no data must never silently
// drag the composite down.
type FactorResult struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	RawScore    float64 `json:"rawScore"`
	Weighted    float64 `json:"weighted"`
	Explanation string  `json:"explanation"`
	Available   bool    `json:"available"`
}

// ActorProfile mirrors a threat_actor_profiles row.
type ActorProfile struct {
	Name       string
	Aliases    []string
	Sectors    []string
	Regions    []string
	Confidence string
	LastSeen   *time.Time
}

// Context is what every factor needs to score one actor. shared carries
// engine-level indexes computed once per Score/ScoreAll call (never once
// per factor) -- see engine.go.
type Context struct {
	ActorName      string
	TechniqueIDs   []string
	Profile        *ActorProfile
	Sectors        []string
	Regions        []string
	Now            time.Time
	ValidatedCount int

	shared *sharedIndexes
}

// ActorPriority is one actor's composite score plus every factor's
// contribution, so the UI can always show WHY, never just a bare number.
type ActorPriority struct {
	ActorName        string         `json:"actorName"`
	Score            int            `json:"score"`
	Tier             string         `json:"tier"`
	Factors          []FactorResult `json:"factors"`
	TechniqueCount   int            `json:"techniqueCount"`
	CoverageGapCount int            `json:"coverageGapCount"`
	Trend            string         `json:"trend"`
	TrendDelta       int            `json:"trendDelta,omitempty"`
}

// ActorPriorityHistory is one threat_priority_history snapshot row.
type ActorPriorityHistory struct {
	ActorName  string    `json:"actorName"`
	Score      int       `json:"score"`
	RecordedAt time.Time `json:"recordedAt"`
}
```

- [ ] **Step 2: Create `factor.go`**

```go
package threatpriority

import "context"

// ScoreFactor is one pluggable contributor to an actor's composite score.
// Weight takes Context (not a constant) because Coverage/Validation factors
// pick their weight band from ctx.ValidatedCount -- see blendWeights.
type ScoreFactor interface {
	Name() string
	Weight(ctx Context) float64
	// Score returns a 0-100 raw score, a human-readable explanation, and
	// whether real evidence backed the score at all (available=false when
	// there's nothing to measure yet -- e.g. an actor with zero tested
	// techniques). raw/explanation are meaningless when available=false.
	Score(ctx context.Context, tctx Context) (raw float64, explanation string, available bool, err error)
}
```

- [ ] **Step 3: Write `score_test.go` first (TDD)**

```go
package threatpriority

import "testing"

func TestBlendWeights_Bands(t *testing.T) {
	cases := []struct {
		validated          int
		wantCoverage       float64
		wantValidation     float64
	}{
		{0, 0.90, 0.10},
		{4, 0.90, 0.10},
		{5, 0.60, 0.40},
		{9, 0.60, 0.40},
		{10, 0.20, 0.80},
		{100, 0.20, 0.80},
	}
	for _, c := range cases {
		cov, val := blendWeights(c.validated)
		if cov != c.wantCoverage || val != c.wantValidation {
			t.Errorf("blendWeights(%d) = (%.2f, %.2f), want (%.2f, %.2f)",
				c.validated, cov, val, c.wantCoverage, c.wantValidation)
		}
	}
}

func TestComposite_AllAvailable_WeightsSumToOne(t *testing.T) {
	results := []FactorResult{
		{Weight: 0.5, RawScore: 100, Weighted: 50, Available: true},
		{Weight: 0.5, RawScore: 0, Weighted: 0, Available: true},
	}
	got := Composite(results)
	if got != 50 {
		t.Fatalf("Composite = %d, want 50", got)
	}
}

func TestComposite_UnavailableFactorsExcludedAndRenormalized(t *testing.T) {
	results := []FactorResult{
		{Weight: 0.5, RawScore: 100, Weighted: 50, Available: true},
		{Weight: 0.5, RawScore: 0, Weighted: 0, Available: false}, // excluded entirely
	}
	got := Composite(results)
	// Only the first factor counts: weightedSum=50, totalWeight=0.5 -> 50/0.5=100.
	if got != 100 {
		t.Fatalf("Composite = %d, want 100 (unavailable factor must not drag score down)", got)
	}
}

func TestComposite_NoFactorsAvailable_ReturnsZero(t *testing.T) {
	results := []FactorResult{
		{Weight: 0.5, Available: false},
		{Weight: 0.5, Available: false},
	}
	if got := Composite(results); got != 0 {
		t.Fatalf("Composite = %d, want 0", got)
	}
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `cd orchestrator && go test ./internal/threatpriority/... -v`
Expected: FAIL to compile — `blendWeights`/`Composite` not defined.

- [ ] **Step 5: Create `score.go`**

```go
package threatpriority

import "math"

const (
	// flatWeight is each standalone factor's (IntelFreshness, Relevance,
	// Confidence) fixed share of the composite.
	flatWeight = 0.05
	// coverageValidationPool is what's left after the 3 standalone factors
	// (3 * 0.05 = 0.15): 1.0 - 0.15 = 0.85, split between Coverage and
	// Validation per blendWeights.
	coverageValidationPool = 0.85
	numCoverageFactors     = 4.0
	numValidationFactors   = 2.0
)

// blendWeights returns (coverageWeight, validationWeight) fractions of
// coverageValidationPool for an actor with validatedCount techniques
// carrying a real verdict (prevention or validation evidence). Mirrors the
// tested-count bands ReadinessScore.ConfidenceBand already uses in
// internal/reporting/insights.go (<5 Low, 5-9 Medium, >=10 High), so the UI's
// language about confidence stays consistent across tabs.
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

func clamp100(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// Composite renormalizes across only the Available factors: a factor with
// no evidence is excluded entirely (its weight redistributed proportionally
// across the rest), never scored as 0. Returns 0 if no factor is available.
func Composite(results []FactorResult) int {
	var totalWeight, weightedSum float64
	for _, r := range results {
		if !r.Available {
			continue
		}
		totalWeight += r.Weight
		weightedSum += r.Weighted
	}
	if totalWeight <= 0 {
		return 0
	}
	return clamp100(int(math.Round(weightedSum / totalWeight)))
}
```

- [ ] **Step 6: Run to verify tests pass**

Run: `cd orchestrator && go test ./internal/threatpriority/... -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/threatpriority/models.go internal/threatpriority/factor.go internal/threatpriority/score.go internal/threatpriority/score_test.go
git commit -m "feat(threatpriority): package skeleton -- types, ScoreFactor interface, blend/composite math"
```

---

### Task 4: Coverage factors

**Files:**
- Create: `orchestrator/internal/threatpriority/coverage_factors.go`
- Test: `orchestrator/internal/threatpriority/coverage_factors_test.go`

**Interfaces:**
- Consumes: `Context.shared` fields `simulation, detection, purple, compliance map[string]bool` (defined in Task 7's `sharedIndexes`, but usable here via a test-local fake since these fields are package-private and this task only needs to construct a `Context{shared: &sharedIndexes{...}}` literal — same package, so unexported fields are accessible in tests).
- Produces: `SimulationCoverageFactor`, `DetectionCoverageFactor`, `PurpleCoverageFactor`, `ComplianceCoverageFactor` (all implement `ScoreFactor`).

- [ ] **Step 1: Write the failing test**

```go
package threatpriority

import "testing"

func TestSimulationCoverageFactor_Score(t *testing.T) {
	f := SimulationCoverageFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105", "T1566"},
		shared:       &sharedIndexes{simulation: map[string]bool{"T1059": true, "T1105": true}},
	}
	raw, explanation, available, err := f.Score(nil, tctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Fatal("expected available=true")
	}
	wantPct := float64(2) / float64(3) * 100
	if raw != wantPct {
		t.Fatalf("raw = %.2f, want %.2f", raw, wantPct)
	}
	if explanation != "2 of 3 techniques have a simulation" {
		t.Fatalf("explanation = %q", explanation)
	}
}

func TestSimulationCoverageFactor_NoTechniques_Unavailable(t *testing.T) {
	f := SimulationCoverageFactor{}
	_, _, available, err := f.Score(nil, Context{TechniqueIDs: nil, shared: &sharedIndexes{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if available {
		t.Fatal("expected available=false when actor has no known techniques")
	}
}

func TestDetectionCoverageFactor_Score(t *testing.T) {
	f := DetectionCoverageFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059"},
		shared:       &sharedIndexes{detection: map[string]bool{"T1059": true}},
	}
	raw, _, available, _ := f.Score(nil, tctx)
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
}

func TestPurpleCoverageFactor_Score(t *testing.T) {
	f := PurpleCoverageFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105"},
		shared:       &sharedIndexes{purple: map[string]bool{"T1059": true}},
	}
	raw, _, available, _ := f.Score(nil, tctx)
	if !available || raw != 50 {
		t.Fatalf("raw=%.2f available=%v, want 50/true", raw, available)
	}
}

func TestComplianceCoverageFactor_Score(t *testing.T) {
	f := ComplianceCoverageFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059"},
		shared:       &sharedIndexes{compliance: map[string]bool{}},
	}
	raw, _, available, _ := f.Score(nil, tctx)
	if !available || raw != 0 {
		t.Fatalf("raw=%.2f available=%v, want 0/true", raw, available)
	}
}

func TestCoverageFactors_WeightScalesWithBlend(t *testing.T) {
	f := SimulationCoverageFactor{}
	low := f.Weight(Context{ValidatedCount: 0})   // coverage=0.90 -> 0.90*0.85/4
	high := f.Weight(Context{ValidatedCount: 100}) // coverage=0.20 -> 0.20*0.85/4
	if low <= high {
		t.Fatalf("expected coverage weight to shrink as validated evidence grows: low=%.4f high=%.4f", low, high)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run TestSimulationCoverageFactor -v`
Expected: FAIL to compile — factors and `sharedIndexes` not defined yet. (`sharedIndexes` is declared here as a forward reference; Task 7 defines it in `engine.go`. To make this task's tests compile standalone, declare a minimal `sharedIndexes` struct now in `coverage_factors.go` itself — Task 7 will extend it in `engine.go` in the same package, which is legal Go as long as the type isn't redeclared. See Step 3.)

- [ ] **Step 3: Create `coverage_factors.go`**

```go
package threatpriority

import (
	"context"
	"fmt"
)

// sharedIndexes holds engine-level, fleet-wide lookups computed once per
// Score/ScoreAll call and reused across every factor and every actor in that
// call -- never rebuilt per-actor or per-factor. Coverage indexes use raw
// technique-ID casing (matching internal/coverage's existing behavior,
// unmodified). Verdict indexes are keyed uppercase (matching the SQL that
// builds them in engine.go) -- callers must uppercase technique IDs before
// looking them up in preventionVerdict/validationVerdict.
type sharedIndexes struct {
	simulation, detection, purple, compliance map[string]bool
	preventionVerdict                         map[string]string // technique ID (upper) -> scenario_runs verdict
	validationVerdict                         map[string]string // technique ID (upper) -> verification.Result*
}

type SimulationCoverageFactor struct{}

func (SimulationCoverageFactor) Name() string { return "Simulation Coverage" }
func (SimulationCoverageFactor) Weight(ctx Context) float64 {
	cov, _ := blendWeights(ctx.ValidatedCount)
	return cov * coverageValidationPool / numCoverageFactors
}
func (SimulationCoverageFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return coveragePct(tctx, tctx.shared.simulation, "simulation")
}

type DetectionCoverageFactor struct{}

func (DetectionCoverageFactor) Name() string { return "Detection Coverage" }
func (DetectionCoverageFactor) Weight(ctx Context) float64 {
	cov, _ := blendWeights(ctx.ValidatedCount)
	return cov * coverageValidationPool / numCoverageFactors
}
func (DetectionCoverageFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return coveragePct(tctx, tctx.shared.detection, "detection profile")
}

type PurpleCoverageFactor struct{}

func (PurpleCoverageFactor) Name() string { return "Purple Exercise Coverage" }
func (PurpleCoverageFactor) Weight(ctx Context) float64 {
	cov, _ := blendWeights(ctx.ValidatedCount)
	return cov * coverageValidationPool / numCoverageFactors
}
func (PurpleCoverageFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return coveragePct(tctx, tctx.shared.purple, "purple exercise")
}

type ComplianceCoverageFactor struct{}

func (ComplianceCoverageFactor) Name() string { return "Compliance Mapping Coverage" }
func (ComplianceCoverageFactor) Weight(ctx Context) float64 {
	cov, _ := blendWeights(ctx.ValidatedCount)
	return cov * coverageValidationPool / numCoverageFactors
}
func (ComplianceCoverageFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return coveragePct(tctx, tctx.shared.compliance, "compliance mapping")
}

// coveragePct is the shared body for all 4 Coverage factors: % of the
// actor's known techniques present in idx. Unavailable only when the actor
// has zero known techniques (nothing to measure), not when the count is 0%.
func coveragePct(tctx Context, idx map[string]bool, label string) (float64, string, bool, error) {
	if len(tctx.TechniqueIDs) == 0 {
		return 0, "No known techniques for this actor", false, nil
	}
	covered := 0
	for _, id := range tctx.TechniqueIDs {
		if idx[id] {
			covered++
		}
	}
	pct := float64(covered) / float64(len(tctx.TechniqueIDs)) * 100
	return pct, fmt.Sprintf("%d of %d techniques have a %s", covered, len(tctx.TechniqueIDs), label), true, nil
}
```

- [ ] **Step 4: Run to verify tests pass**

Run: `cd orchestrator && go test ./internal/threatpriority/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/threatpriority/coverage_factors.go internal/threatpriority/coverage_factors_test.go
git commit -m "feat(threatpriority): 4 Coverage factors (Simulation/Detection/Purple/Compliance)"
```

---

### Task 5: Validation factors — Prevention, Validation

**Files:**
- Create: `orchestrator/internal/threatpriority/validation_factors.go`
- Test: `orchestrator/internal/threatpriority/validation_factors_test.go`

**Interfaces:**
- Consumes: `sharedIndexes.preventionVerdict`/`validationVerdict` (declared in Task 4's `coverage_factors.go`, populated by Task 7's `engine.go`).
- Produces: `PreventionSuccessFactor`, `ValidationSuccessFactor` (implement `ScoreFactor`).

- [ ] **Step 1: Write the failing test**

```go
package threatpriority

import "testing"

func TestPreventionSuccessFactor_Score(t *testing.T) {
	f := PreventionSuccessFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105", "T1566"},
		shared: &sharedIndexes{preventionVerdict: map[string]string{
			"T1059": "pass", // control blocked it
			"T1105": "fail", // ran through unblocked
			// T1566 never tested -- excluded from the denominator
		}},
	}
	raw, explanation, available, err := f.Score(nil, tctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Fatal("expected available=true")
	}
	if raw != 50 {
		t.Fatalf("raw = %.2f, want 50 (1 of 2 tested techniques prevented)", raw)
	}
	if explanation != "1 of 2 tested techniques prevented" {
		t.Fatalf("explanation = %q", explanation)
	}
}

func TestPreventionSuccessFactor_NoneTested_Unavailable(t *testing.T) {
	f := PreventionSuccessFactor{}
	_, _, available, _ := f.Score(nil, Context{
		TechniqueIDs: []string{"T1059"},
		shared:       &sharedIndexes{preventionVerdict: map[string]string{}},
	})
	if available {
		t.Fatal("expected available=false when nothing tested")
	}
}

func TestValidationSuccessFactor_Score(t *testing.T) {
	f := ValidationSuccessFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105"},
		shared: &sharedIndexes{validationVerdict: map[string]string{
			"T1059": "Detected",
			"T1105": "NotDetected",
		}},
	}
	raw, explanation, available, err := f.Score(nil, tctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available || raw != 50 {
		t.Fatalf("raw=%.2f available=%v, want 50/true", raw, available)
	}
	if explanation != "1 of 2 validated techniques validated" {
		t.Fatalf("explanation = %q", explanation)
	}
}

func TestValidationFactors_WeightScalesWithBlend(t *testing.T) {
	f := PreventionSuccessFactor{}
	low := f.Weight(Context{ValidatedCount: 0})   // validation=0.10 -> 0.10*0.85/2
	high := f.Weight(Context{ValidatedCount: 100}) // validation=0.80 -> 0.80*0.85/2
	if high <= low {
		t.Fatalf("expected validation weight to grow as validated evidence grows: low=%.4f high=%.4f", low, high)
	}
}
```

Note: `TestValidationSuccessFactor_Score`'s explanation string is intentionally awkward ("validated techniques validated") — Step 2's implementation must produce exactly this from the generic `validationPct` helper shared with Prevention; if the wording reads badly once implemented, that's fine to leave (it's an internal factor label, not user-facing copy — the UI in Task 11 renders `Explanation` as supporting detail text, not verbatim headline copy).

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run "TestPreventionSuccessFactor|TestValidationSuccessFactor|TestValidationFactors_Weight" -v`
Expected: FAIL to compile.

- [ ] **Step 3: Create `validation_factors.go`**

```go
package threatpriority

import (
	"context"
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/verification"
)

type PreventionSuccessFactor struct{}

func (PreventionSuccessFactor) Name() string { return "Prevention Success" }
func (PreventionSuccessFactor) Weight(ctx Context) float64 {
	_, val := blendWeights(ctx.ValidatedCount)
	return val * coverageValidationPool / numValidationFactors
}
func (PreventionSuccessFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return validationPct(tctx, tctx.shared.preventionVerdict,
		func(v string) bool { return v == "pass" }, "prevented")
}

type ValidationSuccessFactor struct{}

func (ValidationSuccessFactor) Name() string { return "Validation Success" }
func (ValidationSuccessFactor) Weight(ctx Context) float64 {
	_, val := blendWeights(ctx.ValidatedCount)
	return val * coverageValidationPool / numValidationFactors
}
func (ValidationSuccessFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	return validationPct(tctx, tctx.shared.validationVerdict,
		func(v string) bool { return v == verification.ResultDetected }, "validated")
}

// validationPct is the shared body for both Validation factors: % of the
// actor's TESTED techniques (present in idx at all) where isSuccess(verdict)
// holds. A technique never tested is excluded from the denominator, not
// counted as a failure. Unavailable only when zero techniques were tested.
func validationPct(tctx Context, idx map[string]string, isSuccess func(string) bool, label string) (float64, string, bool, error) {
	tested, success := 0, 0
	for _, id := range tctx.TechniqueIDs {
		v, ok := idx[strings.ToUpper(id)]
		if !ok {
			continue
		}
		tested++
		if isSuccess(v) {
			success++
		}
	}
	if tested == 0 {
		return 0, "Not yet validated", false, nil
	}
	pct := float64(success) / float64(tested) * 100
	return pct, fmt.Sprintf("%d of %d validated techniques %s", success, tested, label), true, nil
}
```

- [ ] **Step 4: Run to verify tests pass**

Run: `cd orchestrator && go test ./internal/threatpriority/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/threatpriority/validation_factors.go internal/threatpriority/validation_factors_test.go
git commit -m "feat(threatpriority): Prevention/Validation Success factors"
```

---

### Task 6: Standalone factors — Intel Freshness, Relevance, Confidence

**Files:**
- Create: `orchestrator/internal/threatpriority/standalone_factors.go`
- Test: `orchestrator/internal/threatpriority/standalone_factors_test.go`

**Interfaces:**
- Consumes: `Context.Profile *ActorProfile`, `Context.Sectors/Regions`, `Context.Now`.
- Produces: `IntelFreshnessFactor`, `RelevanceFactor`, `ConfidenceFactor` (implement `ScoreFactor`).

- [ ] **Step 1: Write the failing test**

```go
package threatpriority

import (
	"testing"
	"time"
)

func TestIntelFreshnessFactor_Recent(t *testing.T) {
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	seen := now.Add(-10 * 24 * time.Hour)
	f := IntelFreshnessFactor{}
	raw, _, available, err := f.Score(nil, Context{Now: now, Profile: &ActorProfile{LastSeen: &seen}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
}

func TestIntelFreshnessFactor_NoLastSeen_Unavailable(t *testing.T) {
	f := IntelFreshnessFactor{}
	_, _, available, _ := f.Score(nil, Context{Profile: &ActorProfile{}})
	if available {
		t.Fatal("expected available=false with no LastSeen")
	}
}

func TestRelevanceFactor_SectorMatch(t *testing.T) {
	f := RelevanceFactor{}
	raw, _, available, _ := f.Score(nil, Context{
		Sectors: []string{"Financial Services"},
		Profile: &ActorProfile{Sectors: []string{"financial services"}},
	})
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
}

func TestRelevanceFactor_NoOrgConfig_Unavailable(t *testing.T) {
	f := RelevanceFactor{}
	_, _, available, _ := f.Score(nil, Context{Profile: &ActorProfile{Sectors: []string{"government"}}})
	if available {
		t.Fatal("expected available=false with no org sectors/regions configured")
	}
}

func TestConfidenceFactor_High(t *testing.T) {
	f := ConfidenceFactor{}
	raw, _, available, _ := f.Score(nil, Context{Profile: &ActorProfile{Confidence: "high"}})
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
}

func TestConfidenceFactor_Empty_Unavailable(t *testing.T) {
	f := ConfidenceFactor{}
	_, _, available, _ := f.Score(nil, Context{Profile: &ActorProfile{}})
	if available {
		t.Fatal("expected available=false with empty confidence")
	}
}

func TestStandaloneFactors_FlatWeight(t *testing.T) {
	for _, f := range []ScoreFactor{IntelFreshnessFactor{}, RelevanceFactor{}, ConfidenceFactor{}} {
		if w := f.Weight(Context{ValidatedCount: 0}); w != flatWeight {
			t.Errorf("%s Weight = %.4f, want %.4f (flat, independent of ValidatedCount)", f.Name(), w, flatWeight)
		}
		if w := f.Weight(Context{ValidatedCount: 100}); w != flatWeight {
			t.Errorf("%s Weight = %.4f, want %.4f (flat, independent of ValidatedCount)", f.Name(), w, flatWeight)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run "TestIntelFreshnessFactor|TestRelevanceFactor|TestConfidenceFactor|TestStandaloneFactors" -v`
Expected: FAIL to compile.

- [ ] **Step 3: Create `standalone_factors.go`**

```go
package threatpriority

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type IntelFreshnessFactor struct{}

func (IntelFreshnessFactor) Name() string             { return "Intel Freshness" }
func (IntelFreshnessFactor) Weight(Context) float64    { return flatWeight }
func (IntelFreshnessFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	if tctx.Profile == nil || tctx.Profile.LastSeen == nil {
		return 0, "No intel sighting recorded", false, nil
	}
	age := tctx.Now.Sub(*tctx.Profile.LastSeen)
	days := int(age.Hours() / 24)
	switch {
	case age < 30*24*time.Hour:
		return 100, fmt.Sprintf("Last seen %d days ago", days), true, nil
	case age < 90*24*time.Hour:
		return 60, fmt.Sprintf("Last seen %d days ago", days), true, nil
	default:
		return 20, fmt.Sprintf("Last seen %d days ago", days), true, nil
	}
}

type RelevanceFactor struct{}

func (RelevanceFactor) Name() string          { return "Sector/Region Relevance" }
func (RelevanceFactor) Weight(Context) float64 { return flatWeight }
func (RelevanceFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	if len(tctx.Sectors) == 0 && len(tctx.Regions) == 0 {
		return 0, "No organization sectors/regions configured", false, nil
	}
	if tctx.Profile == nil {
		return 0, "No sector/region data for this actor", false, nil
	}
	if overlapFold(tctx.Profile.Sectors, tctx.Sectors) {
		return 100, "Matches a configured industry sector", true, nil
	}
	if overlapFold(tctx.Profile.Regions, tctx.Regions) {
		return 100, "Matches a configured region", true, nil
	}
	return 0, "No sector or region overlap", true, nil
}

func overlapFold(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}

type ConfidenceFactor struct{}

func (ConfidenceFactor) Name() string          { return "Intel Confidence" }
func (ConfidenceFactor) Weight(Context) float64 { return flatWeight }
func (ConfidenceFactor) Score(_ context.Context, tctx Context) (float64, string, bool, error) {
	if tctx.Profile == nil || tctx.Profile.Confidence == "" {
		return 0, "No confidence rating recorded", false, nil
	}
	switch strings.ToLower(tctx.Profile.Confidence) {
	case "high":
		return 100, "High confidence intel", true, nil
	case "medium":
		return 60, "Medium confidence intel", true, nil
	case "low":
		return 30, "Low confidence intel", true, nil
	default:
		return 0, "Unrecognized confidence value", false, nil
	}
}
```

- [ ] **Step 4: Run to verify tests pass**

Run: `cd orchestrator && go test ./internal/threatpriority/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/threatpriority/standalone_factors.go internal/threatpriority/standalone_factors_test.go
git commit -m "feat(threatpriority): standalone factors (IntelFreshness/Relevance/Confidence)"
```

---

### Task 7: `Engine` — shared indexes, `Score`, `ScoreAll`

**Files:**
- Create: `orchestrator/internal/threatpriority/registry.go`
- Create: `orchestrator/internal/threatpriority/engine.go`
- Test: `orchestrator/internal/threatpriority/engine_test.go`

**Interfaces:**
- Consumes: `coverage.BuildSimulationIndex/BuildProfileIndex/BuildComplianceIndex` (`internal/coverage`), `exercise.BuiltinTemplates` (`internal/exercise`), `reporting.ResolveActorTechniques/PriorityTierFor` (`internal/reporting`), `verification.StateApproved/ResultDetected/ResultNotDetected` (`internal/verification`), `scenario.Engine.List()/Profiles()` (`internal/scenario`).
- Produces: `NewEngine(pool *pgxpool.Pool, scenarioEngine *scenario.Engine, sectors, regions []string) *Engine`; `(*Engine).Score(ctx, actorName string) (ActorPriority, error)`; `(*Engine).ScoreAll(ctx) ([]ActorPriority, error)`. `(*Engine).previousScore` is declared here but implemented in Task 8 (`history.go`) — this task's tests must not call `ScoreAll`/`Score` against a real DB without Task 8's table existing, so this task's engine tests use `-short` skips like the rest of the DB-backed suite; Task 8 is what makes them runnable end-to-end.

- [ ] **Step 1: Create `registry.go`**

```go
package threatpriority

// DefaultFactors returns the 9 built-in factors in a stable order: 4
// Coverage, 2 Validation, 3 standalone. Order only affects the sequence of
// entries in ActorPriority.Factors, not scoring (each factor's Weight/Score
// is independent of the others).
func DefaultFactors() []ScoreFactor {
	return []ScoreFactor{
		SimulationCoverageFactor{},
		DetectionCoverageFactor{},
		PurpleCoverageFactor{},
		ComplianceCoverageFactor{},
		PreventionSuccessFactor{},
		ValidationSuccessFactor{},
		IntelFreshnessFactor{},
		RelevanceFactor{},
		ConfidenceFactor{},
	}
}
```

- [ ] **Step 2: Write the failing test**

```go
package threatpriority

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestNewEngine_UsesDefaultFactors(t *testing.T) {
	e := NewEngine(nil, scenario.NewEngine(t.TempDir()), nil, nil)
	if len(e.factors) != 9 {
		t.Fatalf("got %d factors, want 9", len(e.factors))
	}
}

func TestScoreActor_ComputesCompositeFromRealFactors(t *testing.T) {
	// Exercises scoreActor directly with a hand-built sharedIndexes, bypassing
	// the DB -- full ScoreAll/Score DB-backed behavior is covered by
	// engine_integration_test.go in Task 8, once threat_priority_history exists.
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{"T1059": true},
		detection:  map[string]bool{"T1059": true},
		purple:     map[string]bool{},
		compliance: map[string]bool{},
	}
	profile := &ActorProfile{Name: "TEST-ACTOR-X", Confidence: "high"}

	ap, err := e.scoreActorForTest(profile, []string{"T1059"}, shared)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap.Score <= 0 {
		t.Fatalf("expected a positive composite score, got %d", ap.Score)
	}
	if ap.Tier == "" {
		t.Fatal("expected a non-empty tier")
	}
	if len(ap.Factors) != 9 {
		t.Fatalf("got %d factor results, want 9", len(ap.Factors))
	}
	if ap.TechniqueCount != 1 {
		t.Fatalf("TechniqueCount = %d, want 1", ap.TechniqueCount)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run "TestNewEngine_UsesDefaultFactors|TestScoreActor_ComputesCompositeFromRealFactors" -v`
Expected: FAIL to compile — `Engine`/`NewEngine`/`scoreActorForTest` not defined.

- [ ] **Step 4: Create `engine.go`**

```go
package threatpriority

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

type Engine struct {
	pool           *pgxpool.Pool
	scenarioEngine *scenario.Engine
	sectors        []string
	regions        []string
	factors        []ScoreFactor
}

// NewEngine wires the engine to a Postgres pool (for threat_actor_profiles,
// scenario_runs, verification_history, threat_priority_history) and the
// scenario Engine (for BuildSimulationIndex/BuildProfileIndex/BuildComplianceIndex).
// sectors/regions are the org's static config.ThreatIntelSectors/Regions --
// held here at construction rather than threaded per-call, matching
// reporting.Engine's pattern (this package is a stateful Engine, unlike
// internal/recommend which is deliberately a stateless function library).
func NewEngine(pool *pgxpool.Pool, scenarioEngine *scenario.Engine, sectors, regions []string) *Engine {
	return &Engine{
		pool: pool, scenarioEngine: scenarioEngine,
		sectors: sectors, regions: regions,
		factors: DefaultFactors(),
	}
}

func (e *Engine) buildSharedIndexes(ctx context.Context) (*sharedIndexes, error) {
	scenarios := e.scenarioEngine.List()
	profiles := e.scenarioEngine.Profiles()

	purple := map[string]bool{}
	for _, tmpl := range exercise.BuiltinTemplates {
		for _, id := range tmpl.Metadata.ExpectedTechniques {
			purple[id] = true
		}
	}

	idx := &sharedIndexes{
		simulation: coverage.BuildSimulationIndex(scenarios),
		detection:  coverage.BuildProfileIndex(profiles),
		purple:     purple,
		compliance: coverage.BuildComplianceIndex(scenarios),
	}

	prevention, err := e.loadPreventionVerdicts(ctx)
	if err != nil {
		return nil, fmt.Errorf("load prevention verdicts: %w", err)
	}
	idx.preventionVerdict = prevention

	validation, err := e.loadValidationVerdicts(ctx)
	if err != nil {
		return nil, fmt.Errorf("load validation verdicts: %w", err)
	}
	idx.validationVerdict = validation

	return idx, nil
}

func (e *Engine) loadPreventionVerdicts(ctx context.Context) (map[string]string, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT DISTINCT ON (UPPER(r->'technique'->>'id'))
		       UPPER(r->'technique'->>'id') AS tid,
		       r->>'result'                 AS verdict
		FROM scenario_runs sr, jsonb_array_elements(sr.results) r
		WHERE sr.status IN ('completed', 'partial')
		  AND r->'technique'->>'id' IS NOT NULL AND r->'technique'->>'id' <> ''
		  AND r->>'result' NOT IN ('error', 'skipped')
		ORDER BY UPPER(r->'technique'->>'id'), (r->>'executedAt')::timestamptz DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var tid, verdict string
		if err := rows.Scan(&tid, &verdict); err != nil {
			return nil, err
		}
		out[tid] = verdict
	}
	return out, rows.Err()
}

func (e *Engine) loadValidationVerdicts(ctx context.Context) (map[string]string, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT DISTINCT ON (technique_id) technique_id, result
		FROM verification_history
		WHERE active AND workflow_state = $1 AND result IN ($2, $3)
		ORDER BY technique_id, verified_at DESC`,
		verification.StateApproved, verification.ResultDetected, verification.ResultNotDetected)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var tid, result string
		if err := rows.Scan(&tid, &result); err != nil {
			return nil, err
		}
		out[strings.ToUpper(tid)] = result
	}
	return out, rows.Err()
}

func (e *Engine) loadProfile(ctx context.Context, name string) (*ActorProfile, error) {
	row := e.pool.QueryRow(ctx,
		`SELECT name, aliases, sectors, regions, confidence, last_seen FROM threat_actor_profiles WHERE name=$1`, name)
	var p ActorProfile
	if err := row.Scan(&p.Name, &p.Aliases, &p.Sectors, &p.Regions, &p.Confidence, &p.LastSeen); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

func (e *Engine) loadAllProfiles(ctx context.Context) ([]ActorProfile, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT name, aliases, sectors, regions, confidence, last_seen FROM threat_actor_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActorProfile
	for rows.Next() {
		var p ActorProfile
		if err := rows.Scan(&p.Name, &p.Aliases, &p.Sectors, &p.Regions, &p.Confidence, &p.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// scoreActor is the shared body of Score and ScoreAll -- takes a profile and
// engine-level shared indexes (built once by the caller), resolves the
// actor's technique roster, runs every registered factor, and computes the
// composite. previousScore/Trend lookup lives in history.go (Task 8).
func (e *Engine) scoreActor(ctx context.Context, profile *ActorProfile, shared *sharedIndexes) (ActorPriority, error) {
	techIDs, _, _ := reporting.ResolveActorTechniques(profile.Name, profile.Aliases)

	validatedCount := 0
	for _, id := range techIDs {
		upper := strings.ToUpper(id)
		if _, ok := shared.preventionVerdict[upper]; ok {
			validatedCount++
			continue
		}
		if _, ok := shared.validationVerdict[upper]; ok {
			validatedCount++
		}
	}

	tctx := Context{
		ActorName: profile.Name, TechniqueIDs: techIDs, Profile: profile,
		Sectors: e.sectors, Regions: e.regions, Now: time.Now().UTC(),
		ValidatedCount: validatedCount, shared: shared,
	}

	results := make([]FactorResult, 0, len(e.factors))
	for _, f := range e.factors {
		w := f.Weight(tctx)
		raw, explanation, available, err := f.Score(ctx, tctx)
		if err != nil {
			return ActorPriority{}, fmt.Errorf("factor %s: %w", f.Name(), err)
		}
		results = append(results, FactorResult{
			Name: f.Name(), Weight: w, RawScore: raw,
			Weighted: raw * w, Explanation: explanation, Available: available,
		})
	}

	score := Composite(results)
	coverageGap := 0
	for _, id := range techIDs {
		if !shared.simulation[id] && !shared.detection[id] && !shared.purple[id] && !shared.compliance[id] {
			coverageGap++
		}
	}

	ap := ActorPriority{
		ActorName: profile.Name, Score: score, Tier: reporting.PriorityTierFor(score),
		Factors: results, TechniqueCount: len(techIDs), CoverageGapCount: coverageGap,
	}

	prevScore, hasPrev, err := e.previousScore(ctx, profile.Name)
	if err != nil {
		return ActorPriority{}, err
	}
	if hasPrev {
		ap.TrendDelta = score - prevScore
		switch {
		case ap.TrendDelta > 0:
			ap.Trend = "up"
		case ap.TrendDelta < 0:
			ap.Trend = "down"
		default:
			ap.Trend = "stable"
		}
	}
	return ap, nil
}

// scoreActorForTest exposes scoreActor to unit tests that build their own
// sharedIndexes/profile without a database, skipping previousScore (which
// requires e.pool). Test-only, not part of the package's real API surface.
func (e *Engine) scoreActorForTest(profile *ActorProfile, techIDsOverride []string, shared *sharedIndexes) (ActorPriority, error) {
	_ = techIDsOverride // resolved via reporting.ResolveActorTechniques inside scoreActor; kept for test readability
	if e.pool == nil {
		// previousScore would nil-deref e.pool -- short-circuit trend lookup
		// for pool-less unit tests the same way scoreActor does when hasPrev
		// is simply never true.
		techIDs, _, _ := reporting.ResolveActorTechniques(profile.Name, profile.Aliases)
		validatedCount := 0
		for _, id := range techIDs {
			upper := strings.ToUpper(id)
			if _, ok := shared.preventionVerdict[upper]; ok {
				validatedCount++
				continue
			}
			if _, ok := shared.validationVerdict[upper]; ok {
				validatedCount++
			}
		}
		tctx := Context{
			ActorName: profile.Name, TechniqueIDs: techIDs, Profile: profile,
			Sectors: e.sectors, Regions: e.regions, Now: time.Now().UTC(),
			ValidatedCount: validatedCount, shared: shared,
		}
		results := make([]FactorResult, 0, len(e.factors))
		for _, f := range e.factors {
			w := f.Weight(tctx)
			raw, explanation, available, err := f.Score(context.Background(), tctx)
			if err != nil {
				return ActorPriority{}, fmt.Errorf("factor %s: %w", f.Name(), err)
			}
			results = append(results, FactorResult{
				Name: f.Name(), Weight: w, RawScore: raw,
				Weighted: raw * w, Explanation: explanation, Available: available,
			})
		}
		score := Composite(results)
		coverageGap := 0
		for _, id := range techIDs {
			if !shared.simulation[id] && !shared.detection[id] && !shared.purple[id] && !shared.compliance[id] {
				coverageGap++
			}
		}
		return ActorPriority{
			ActorName: profile.Name, Score: score, Tier: reporting.PriorityTierFor(score),
			Factors: results, TechniqueCount: len(techIDs), CoverageGapCount: coverageGap,
		}, nil
	}
	return e.scoreActor(context.Background(), profile, shared)
}

// Score computes one actor's ActorPriority live -- read-only, no history
// write. actorName need not have a threat_actor_profiles row (Coverage
// factors and technique resolution still work via attackdata alone; profile-
// dependent factors report Available=false).
func (e *Engine) Score(ctx context.Context, actorName string) (ActorPriority, error) {
	shared, err := e.buildSharedIndexes(ctx)
	if err != nil {
		return ActorPriority{}, err
	}
	profile, err := e.loadProfile(ctx, actorName)
	if err != nil {
		return ActorPriority{}, err
	}
	if profile == nil {
		profile = &ActorProfile{Name: actorName}
	}
	return e.scoreActor(ctx, profile, shared)
}

// ScoreAll computes every actor with a threat_actor_profiles row -- the
// roster of actors real connectors have actually surfaced, not all ~200
// MITRE groups attackdata.GroupTechniqueIndex knows about. Read-only; a
// single actor's scoring error is logged and skipped, never aborting the
// rest (same discipline connector.Scheduler.sync applies to source fetches).
func (e *Engine) ScoreAll(ctx context.Context) ([]ActorPriority, error) {
	shared, err := e.buildSharedIndexes(ctx)
	if err != nil {
		return nil, err
	}
	profiles, err := e.loadAllProfiles(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ActorPriority, 0, len(profiles))
	for i := range profiles {
		ap, err := e.scoreActor(ctx, &profiles[i], shared)
		if err != nil {
			log.Printf("[threatpriority] score %q: %v", profiles[i].Name, err)
			continue
		}
		out = append(out, ap)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ActorName < out[j].ActorName
	})
	return out, nil
}
```

- [ ] **Step 5: Run to verify tests pass**

Run: `cd orchestrator && go test ./internal/threatpriority/... -v`
Expected: PASS for `TestNewEngine_UsesDefaultFactors` and `TestScoreActor_ComputesCompositeFromRealFactors`. `previousScore` is referenced but not yet defined — Task 8 defines it in `history.go`; until then this package will not compile. Proceed directly to Task 8 before running the full suite (do not skip ahead in commit order — the compile error is expected and resolved by the very next task, not left dangling).

- [ ] **Step 6: Commit**

```bash
git add internal/threatpriority/registry.go internal/threatpriority/engine.go internal/threatpriority/engine_test.go
git commit -m "feat(threatpriority): Engine -- shared indexes, Score, ScoreAll (previousScore defined in next commit)"
```

---

### Task 8: History persistence + Scheduler integration

**Files:**
- Create: `orchestrator/internal/threatpriority/history.go`
- Create: `orchestrator/internal/threatpriority/history_test.go`
- Modify: `orchestrator/internal/connector/scheduler.go` (add `priorityEngine` field, `NewScheduler` param, `sync()` hook)
- Modify: `orchestrator/internal/connector/scheduler_test.go` (fix 4 `NewScheduler` call sites)
- Modify: `orchestrator/cmd/server/main.go` (construct the engine, wire it into `NewScheduler`)

**Interfaces:**
- Consumes: `Engine.pool`, `Engine.ScoreAll` (Task 7).
- Produces: `(*Engine).previousScore(ctx, actorName string) (score int, ok bool, err error)` (resolves Task 7's compile gap); `(*Engine).SnapshotHistory(ctx) error`; `(*Engine).History(ctx, actorName string, limit int) ([]ActorPriorityHistory, error)`.

- [ ] **Step 1: Write the failing test**

```go
package threatpriority

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

func TestSnapshotHistoryAndPreviousScore_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, confidence) VALUES ($1, 'high') ON CONFLICT (name) DO NOTHING`,
			"HISTORY-TEST-ACTOR")
		if err != nil {
			t.Fatalf("seed profile: %v", err)
		}

		e := NewEngine(pool, scenario.NewEngine(t.TempDir()), nil, nil)

		if err := e.SnapshotHistory(ctx); err != nil {
			t.Fatalf("first SnapshotHistory: %v", err)
		}
		_, hasPrev, err := e.previousScore(ctx, "HISTORY-TEST-ACTOR")
		if err != nil {
			t.Fatalf("previousScore after first snapshot: %v", err)
		}
		if !hasPrev {
			t.Fatal("expected a history row after SnapshotHistory")
		}

		hist, err := e.History(ctx, "HISTORY-TEST-ACTOR", 10)
		if err != nil {
			t.Fatalf("History: %v", err)
		}
		if len(hist) == 0 {
			t.Fatal("expected at least one history row")
		}
	})
}

func TestPreviousScore_NoHistory_ReturnsFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := NewEngine(pool, scenario.NewEngine(t.TempDir()), nil, nil)
		_, hasPrev, err := e.previousScore(context.Background(), "NO-SUCH-ACTOR-EVER")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hasPrev {
			t.Fatal("expected hasPrev=false for an actor with no history")
		}
	})
}
```

This test file needs a `sharedDB` test fixture (`internal/testutil.TestDB`, confirmed at `internal/testutil/testdb.go:124` (`func MustSharedTestDB() *TestDB`) and `:154` (`func (d *TestDB) RunWithPool(t *testing.T, fn func(pool *pgxpool.Pool))`)) and a `pgxpool` import. `internal/threatpriority` has no `TestMain` yet (this is its first DB-backed test) — Step 2 adds one.

- [ ] **Step 2: Create `testmain_test.go`**

```go
package threatpriority

import (
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	os.Exit(m.Run())
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd orchestrator && go test ./internal/threatpriority/... -short`
Expected: compiles now (Task 7's dangling `previousScore` reference still unresolved) — FAIL to compile with `previousScore`/`SnapshotHistory`/`History` undefined.

- [ ] **Step 4: Create `history.go`**

```go
package threatpriority

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// previousScore returns the most recent threat_priority_history score for
// actorName, or ok=false if none exists yet (first-ever score for this
// actor). Read-only.
func (e *Engine) previousScore(ctx context.Context, actorName string) (score int, ok bool, err error) {
	row := e.pool.QueryRow(ctx,
		`SELECT score FROM threat_priority_history WHERE actor_name=$1 ORDER BY recorded_at DESC LIMIT 1`,
		actorName)
	if err := row.Scan(&score); err != nil {
		if err == pgx.ErrNoRows {
			return 0, false, nil
		}
		return 0, false, err
	}
	return score, true, nil
}

// SnapshotHistory computes every actor's ActorPriority (via ScoreAll) and
// writes one threat_priority_history row per actor. Call this ONLY from a
// change-detection trigger (connector.Scheduler.sync, in this project) --
// never from a GET request, or every page view would insert rows.
func (e *Engine) SnapshotHistory(ctx context.Context) error {
	scores, err := e.ScoreAll(ctx)
	if err != nil {
		return err
	}
	for _, ap := range scores {
		_, err := e.pool.Exec(ctx,
			`INSERT INTO threat_priority_history (actor_name, score, tier, recorded_at) VALUES ($1,$2,$3,NOW())`,
			ap.ActorName, ap.Score, ap.Tier)
		if err != nil {
			return fmt.Errorf("snapshot %q: %w", ap.ActorName, err)
		}
	}
	return nil
}

// History returns an actor's most recent snapshots, newest first.
func (e *Engine) History(ctx context.Context, actorName string, limit int) ([]ActorPriorityHistory, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT actor_name, score, recorded_at FROM threat_priority_history
		 WHERE actor_name=$1 ORDER BY recorded_at DESC LIMIT $2`, actorName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActorPriorityHistory
	for rows.Next() {
		var h ActorPriorityHistory
		if err := rows.Scan(&h.ActorName, &h.Score, &h.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
```

- [ ] **Step 5: Run to verify tests pass**

Run: `cd orchestrator && go test ./internal/threatpriority/...`
Expected: PASS (the full package, including Tasks 3-7's tests, now compiles and passes).

- [ ] **Step 6: Wire the Scheduler hook**

In `orchestrator/internal/connector/scheduler.go`, add a field to `Scheduler` (in the struct declared around line 17-31):

```go
type Scheduler struct {
	sources   []Source
	generator *Generator
	engine    *scenario.Engine
	interval  time.Duration
	pool *pgxpool.Pool

	// priorityEngine recomputes and snapshots Threat Prioritization scores
	// whenever intel changes -- connector sync IS the change-detection
	// trigger for internal/threatpriority's "Continuous Intelligence"
	// behavior, no separate polling needed. nil-safe: skipped if unset.
	priorityEngine *threatpriority.Engine

	mu     sync.RWMutex
	status ConnectorStatus
	syncCh chan struct{}
	stopCh chan struct{}
}
```

Add the import: `"github.com/audspect/bas/internal/threatpriority"`.

Update `NewScheduler`'s signature (currently `func NewScheduler(sources []Source, generator *Generator, engine *scenario.Engine, pollHours int, pool *pgxpool.Pool) *Scheduler`) to take a 6th parameter and set the field:

```go
func NewScheduler(
	sources []Source,
	generator *Generator,
	engine *scenario.Engine,
	pollHours int,
	pool *pgxpool.Pool,
	priorityEngine *threatpriority.Engine,
) *Scheduler {
	if pollHours <= 0 {
		pollHours = 24
	}
	s := &Scheduler{
		sources: sources, generator: generator, engine: engine,
		interval: time.Duration(pollHours) * time.Hour,
		pool: pool, priorityEngine: priorityEngine,
		syncCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
	s.status = ConnectorStatus{
		LastSyncStatus: "never",
		NextSyncAt:     time.Now().Add(s.interval),
	}
	for _, src := range sources {
		switch src.Name() {
		case "misp":
			s.status.MISPEnabled = true
		case "opencti":
			s.status.OpenCTIEnabled = true
		case "bundle":
			s.status.BundleEnabled = true
		}
	}
	return s
}
```

Add the snapshot call in `sync()` right after the existing `s.upsertActorProfiles(actors)` line:

```go
	s.upsertActorProfiles(actors)

	if s.priorityEngine != nil {
		if err := s.priorityEngine.SnapshotHistory(context.Background()); err != nil {
			log.Printf("[connector] threat-priority snapshot: %v", err)
		}
	}
```

- [ ] **Step 7: Fix the 4 existing `NewScheduler` call sites in `scheduler_test.go`**

All 4 currently end with `, 24, sharedDB.Pool)` (3 sites) or `, 24, pool)` (1 site, inside `sharedDB.RunWithPool`). Add `, nil` (nil `priorityEngine` — these tests don't exercise Threat Prioritization) to each:

```bash
cd orchestrator
sed -i 's/, 24, sharedDB\.Pool)/, 24, sharedDB.Pool, nil)/g' internal/connector/scheduler_test.go
sed -i 's/, 24, pool)/, 24, pool, nil)/g' internal/connector/scheduler_test.go
```

Verify with `grep -n "NewScheduler(" internal/connector/scheduler_test.go` that all 4 call sites now end in `, nil)` before proceeding — `sed` is a blunt instrument here and could over/under-match; check the diff by eye (`git diff internal/connector/scheduler_test.go`) rather than trusting the command blindly.

- [ ] **Step 8: Wire construction in `main.go`**

In `orchestrator/cmd/server/main.go`, immediately before the existing line `scheduler := connector.NewScheduler(tiSources, gen, engine, cfg.ThreatIntelPollHours, pool)` (currently line 249), add:

```go
	priorityEngine := threatpriority.NewEngine(pool, engine, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
```

Change the `NewScheduler` call to:

```go
	scheduler := connector.NewScheduler(tiSources, gen, engine, cfg.ThreatIntelPollHours, pool, priorityEngine)
```

Add the import: `"github.com/audspect/bas/internal/threatpriority"`.

(`Handler.WithThreatPriority(priorityEngine)` wiring into the handler chain at line ~350 is Task 10's job, not this task's — `priorityEngine` is now a local variable in `main.go` available for that later edit.)

- [ ] **Step 9: Run the full connector + threatpriority package tests**

Run: `cd orchestrator && go build ./... && go test ./internal/connector/... ./internal/threatpriority/... -count=1`
Expected: PASS, no build errors.

- [ ] **Step 10: Commit**

```bash
git add internal/threatpriority/history.go internal/threatpriority/history_test.go internal/threatpriority/testmain_test.go internal/connector/scheduler.go internal/connector/scheduler_test.go cmd/server/main.go
git commit -m "feat(threatpriority): history persistence + wire into connector.Scheduler.sync"
```

---

### Task 9: Recommendation engine integration

**Files:**
- Modify: `orchestrator/internal/recommend/score.go:16-21,80-86` (`RecommendationScore`)
- Modify: `orchestrator/internal/recommend/types.go` (`RecommendedTechnique`)
- Modify: `orchestrator/internal/recommend/recommend.go:42,99-104` (`Build`)
- Modify: `orchestrator/internal/api/recommend_handlers.go` (`GetRecommendedSimulations`)
- Test: `orchestrator/internal/recommend/score_test.go`, `orchestrator/internal/recommend/recommend_test.go`, `orchestrator/internal/api/recommend_handlers_test.go`

**Interfaces:**
- Consumes: `threatpriority.Engine.ScoreAll` (Task 7/8).
- Produces: `recommend.RecommendationScore(actorPriority, threatPriority, coverageGap, environmentRisk int) int` (new 4-arg signature); `recommend.Build(ctx, pool, g, s, limit, sectors, regions, actorPriorityByTechnique map[string]int) (Recommendations, error)` (new 8th param); `RecommendedTechnique.ActorPriority int` (new field).

- [ ] **Step 1: Write the failing test for the new `RecommendationScore` signature**

Find the existing `RecommendationScore` test in `orchestrator/internal/recommend/score_test.go` (search for `TestRecommendationScore` or similar) and update every call site to pass a leading `actorPriority` argument. If no such test currently exists, add:

```go
func TestRecommendationScore_ActorPriorityIsHighestWeightedTerm(t *testing.T) {
	// wActor=0.25 > wCoverage=0.25 == wEnvironment=0.15's neighbors -- verify
	// a technique tied to a Critical-priority actor scores higher than an
	// identical technique tied to a Low-priority actor, all else equal.
	high := RecommendationScore(100, 50, 50, 50)
	low := RecommendationScore(0, 50, 50, 50)
	if high <= low {
		t.Fatalf("high actorPriority score (%d) should exceed low (%d)", high, low)
	}
}

func TestRecommendationScore_WeightsSumToOne(t *testing.T) {
	// All-100 inputs must produce exactly 100 if weights sum to 1.0.
	got := RecommendationScore(100, 100, 100, 100)
	if got != 100 {
		t.Fatalf("RecommendationScore(100,100,100,100) = %d, want 100 (weights must sum to 1.0)", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && go test ./internal/recommend/... -run TestRecommendationScore -v`
Expected: FAIL — either a compile error (old 3-arg calls elsewhere in the test file no longer match) or a logic failure, depending on what already existed. Note every other pre-existing call to `RecommendationScore` in this package (both in `score.go`'s own callers and any other test) needs the same 4-arg update — grep for `RecommendationScore(` across `internal/recommend/` before editing to find every site.

- [ ] **Step 3: Update `score.go`**

Replace the weight constants and `RecommendationScore` (currently lines 16-21 and 80-86):

```go
// Composite weights — must sum to 1.0. See the spec's Scoring section.
const (
	wActor       = 0.25
	wThreat      = 0.35
	wCoverage    = 0.25
	wEnvironment = 0.15
)
```

```go
// RecommendationScore is the composite: 0.25×actor + 0.35×threat + 0.25×coverage + 0.15×env.
func RecommendationScore(actorPriority, threatPriority, coverageGap, environmentRisk int) int {
	s := wActor*float64(clamp100(actorPriority)) +
		wThreat*float64(clamp100(threatPriority)) +
		wCoverage*float64(clamp100(coverageGap)) +
		wEnvironment*float64(clamp100(environmentRisk))
	return clamp100(int(math.Round(s)))
}
```

- [ ] **Step 4: Add the `ActorPriority` field to `RecommendedTechnique` and update `buildReasons`**

In `orchestrator/internal/recommend/types.go`, add to `RecommendedTechnique` (after the existing `EnvironmentRisk int` field):

```go
	ActorPriority int `json:"actorPriority"`
```

In `orchestrator/internal/recommend/score.go`'s `buildReasons`, add a reason line (after the existing `EnvironmentRisk` switch block, before the `LastVerdict == "fail"` check):

```go
	if t.ActorPriority >= 70 {
		out = append(out, fmt.Sprintf("Used by a %s-priority threat actor", reporting.PriorityTierFor(t.ActorPriority)))
	}
```

This needs `"github.com/audspect/bas/internal/reporting"` imported in `score.go` if not already present — check the existing import block first (it likely isn't imported there yet, since `score.go` is pure arithmetic today).

- [ ] **Step 5: Update `Build`'s signature and body in `recommend.go`**

Change the signature (currently line 42):

```go
func Build(ctx context.Context, pool *pgxpool.Pool, g *attackpath.Graph, s attackpath.Summary, limit int, sectors, regions []string, actorPriorityByTechnique map[string]int) (Recommendations, error) {
```

In the per-technique loop (currently lines 88-104), add the `ActorPriority` field and pass it into `RecommendationScore`:

```go
		t := RecommendedTechnique{
			TechniqueID:    u.id,
			Name:           u.name,
			Tactic:         u.tactic,
			CoverageState:  CoverageStateFor(lastTested, now),
			LastTestedAt:   lastTested,
			LastVerdict:    verdict,
			KEV:            kev[key],
			EPSSPercentile: epss[key],
			ThreatActors:   actors[key],
			ActorPriority:  actorPriorityByTechnique[key],
		}
		t.ThreatPriority = reporting.ComputePriorityScore(t.KEV, t.EPSSPercentile, t.ThreatActors, verdict, sectorRegionRelevant[key])
		t.CoverageGap = CoverageGap(lastTested, now)
		t.EnvironmentRisk = EnvironmentRisk(env.inGraph[key], env.onCriticalPath[key], env.targetsCritical[key])
		t.Score = RecommendationScore(t.ActorPriority, t.ThreatPriority, t.CoverageGap, t.EnvironmentRisk)
		t.Tier = reporting.PriorityTierFor(t.Score)
		t.Reasons = buildReasons(t, now)
```

`actorPriorityByTechnique[key]` on a `nil` map or missing key returns Go's zero value `0`, which is exactly the desired nil-safe degrade-to-0 behavior — no extra nil check needed, matching how `kev[key]`/`epss[key]` already behave the same way a few lines above.

- [ ] **Step 6: Update every existing `recommend.Build` call site**

Confirmed via `grep -rn "recommend.Build(\|= Build(" orchestrator/internal/` that there are exactly 2 call-site locations needing this update: `internal/api/recommend_handlers.go:35` (handled in Step 8 below) and 8 test call sites in `internal/recommend/recommend_test.go` (lines 74, 98, 119, 162, 190, 224, 252, 279), every one of which currently ends `..., nil)` (the `regions` argument, always `nil` in every one of these 8 tests). Add a trailing `, nil` for the new `actorPriorityByTechnique` param — these tests don't care about ActorPriority rollup:

```bash
cd orchestrator
sed -i '/Build(context.Background(), pool,/s/, nil)$/, nil, nil)/' internal/recommend/recommend_test.go
grep -c ', nil, nil)$' internal/recommend/recommend_test.go   # expect 8
```

Review `git diff internal/recommend/recommend_test.go` to confirm exactly those 8 lines changed and nothing else in the file matched unexpectedly.

- [ ] **Step 7: Run to verify tests pass**

Run: `cd orchestrator && go test ./internal/recommend/... -v`
Expected: PASS.

- [ ] **Step 8: Update the caller — `GetRecommendedSimulations`**

Replace `orchestrator/internal/api/recommend_handlers.go`'s body:

```go
package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/recommend"
)

// GetRecommendedSimulations ranks the ART-testable ATT&CK techniques by how
// much value testing them next would add — Phase 6, now weighted by actor
// priority too. Read-only (Viewer+).
// Query params: limit (default 20, clamped to [1,100]).
// GET /api/recommend/simulations
func (h *Handler) GetRecommendedSimulations(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 100 {
			limit = n
		}
	}

	cols := h.loadAttackPathCollections(r)
	g, s := attackpath.BuildGraphAndAnalyze(cols, h.loadAssetTags(r))

	var sectors, regions []string
	if h.reportingEngine != nil {
		sectors = h.reportingEngine.Sectors()
		regions = h.reportingEngine.Regions()
	}

	actorPriorityByTechnique := h.buildActorPriorityByTechnique(r.Context())

	recs, err := recommend.Build(r.Context(), h.db, g, s, limit, sectors, regions, actorPriorityByTechnique)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, recs)
}

// buildActorPriorityByTechnique takes the max ActorPriority score among all
// actors known to use each technique -- a technique used by even one
// Critical-priority actor should read as urgent, never averaged down by
// low-priority actors sharing it. nil (not an error) when no priority
// engine is attached or scoring fails, so recommendations degrade to their
// pre-Threat-Prioritization behavior rather than erroring out.
func (h *Handler) buildActorPriorityByTechnique(ctx context.Context) map[string]int {
	if h.threatPriorityEngine == nil {
		return nil
	}
	scores, err := h.threatPriorityEngine.ScoreAll(ctx)
	if err != nil {
		return nil
	}
	out := map[string]int{}
	for _, ap := range scores {
		for _, id := range ap.TechniqueIDs() {
			key := strings.ToUpper(id)
			if ap.Score > out[key] {
				out[key] = ap.Score
			}
		}
	}
	return out
}
```

This references `ap.TechniqueIDs()` — `ActorPriority` (Task 3's `models.go`) does not currently carry the resolved technique-ID list as an exported field or method. Add one: in `orchestrator/internal/threatpriority/models.go`, add a field to `ActorPriority`:

```go
	TechniqueIDs []string `json:"-"` // internal use (Recommendation rollup); not serialized -- Factors/TechniqueCount are the public surface
```

and in `engine.go`'s `scoreActor`, set it: `ap.TechniqueIDs = techIDs` (add this line right after `ap := ActorPriority{...}` is constructed, before the `previousScore` block). Then in `recommend_handlers.go`, use `ap.TechniqueIDs` directly instead of a method call:

```go
		for _, id := range ap.TechniqueIDs {
```

(`"context"` is already in the import block from Step 8 above — needed for `buildActorPriorityByTechnique`'s `ctx context.Context` parameter.)

- [ ] **Step 9: Add `WithThreatPriority` and the `threatPriorityEngine` field to `Handler`**

In `orchestrator/internal/api/handlers.go`, add a field to the `Handler` struct (near the existing `scheduler *connector.Scheduler` field) and an attachment method (near `WithScheduler`):

```go
	threatPriorityEngine *threatpriority.Engine
```

```go
// WithThreatPriority attaches the actor-level priority engine.
func (h *Handler) WithThreatPriority(e *threatpriority.Engine) *Handler {
	h.threatPriorityEngine = e
	return h
}
```

Add the import `"github.com/audspect/bas/internal/threatpriority"` to `handlers.go`.

- [ ] **Step 10: Run the full `recommend` + `api` build**

Run: `cd orchestrator && go build ./...`
Expected: no errors. (Handler tests for the new endpoints come in Task 10; this step is just confirming the wiring compiles.)

- [ ] **Step 11: Update existing `recommend_handlers_test.go`**

The existing `TestGetRecommendedSimulations*`-style tests construct a `Handler` via `New(...)` without `WithThreatPriority` — confirm they still pass with `h.threatPriorityEngine == nil` (which `buildActorPriorityByTechnique` explicitly handles by returning `nil`, and `recommend.Build` explicitly handles a `nil` map by defaulting every technique's `ActorPriority` to 0). Run:

Run: `cd orchestrator && go test ./internal/api/... -run TestGetRecommendedSimulations -short -v`
Expected: PASS (no behavior change for callers that don't attach a priority engine).

- [ ] **Step 12: Commit**

```bash
git add internal/recommend/score.go internal/recommend/types.go internal/recommend/recommend.go internal/recommend/score_test.go internal/recommend/recommend_test.go internal/api/recommend_handlers.go internal/api/recommend_handlers_test.go internal/api/handlers.go internal/threatpriority/models.go internal/threatpriority/engine.go
git commit -m "feat(recommend): wire ActorPriority into RecommendationScore as a 4th term"
```

---

### Task 10: API handlers, routes, RBAC matrix, `main.go` wiring

**Files:**
- Create: `orchestrator/internal/api/threatpriority_handlers.go`
- Test: `orchestrator/internal/api/threatpriority_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (register 2 routes, right after the existing `/api/coverage/*` block at line 175)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add 2 `routeMatrix` entries, `tierAny`)
- Modify: `orchestrator/cmd/server/main.go` (add `.WithThreatPriority(priorityEngine)` to the handler chain)

**Interfaces:**
- Consumes: `threatpriority.Engine.ScoreAll`/`Score`/`History` (Tasks 7-8), `internal/coverage.BuildSimulationIndex/BuildProfileIndex/BuildComplianceIndex` (for `UncoveredTechniques`).
- Produces: `GET /api/threat-priority/actors`, `GET /api/threat-priority/actors/{name}`.

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/ws"
)

func TestThreatPriorityActors_EmptyRoster_ReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors", nil)
		w := httptest.NewRecorder()
		h.ThreatPriorityActors(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}

func TestThreatPriorityActorDetail_UnknownActor_ReturnsEmptyButOK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors/Nonexistent-Actor", nil)
		req = withURLParams(req, map[string]string{"name": "Nonexistent-Actor"})
		w := httptest.NewRecorder()
		h.ThreatPriorityActorDetail(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}
```

`withURLParams` already exists in this package (`internal/api/verification_queue_test.go:75-81`, built on `chi.NewRouteContext()`/`chi.RouteCtxKey`) — reuse it directly, don't redefine it.

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestThreatPriorityActors -short -v`
Expected: FAIL to compile — `ThreatPriorityActors`/`ThreatPriorityActorDetail` not defined.

- [ ] **Step 3: Create `threatpriority_handlers.go`**

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/threatpriority"
)

// GET /api/threat-priority/actors
// Ranked list of every actor with a threat_actor_profiles row, sorted Score
// desc then ActorName asc (same determinism convention as
// internal/recommend's sort). Distinct from GET /api/coverage/matrix
// (technique-level content existence) and GET /api/recommend/simulations
// (technique-level ranking) -- this is the actor-level view.
func (h *Handler) ThreatPriorityActors(w http.ResponseWriter, r *http.Request) {
	if h.threatPriorityEngine == nil {
		respond(w, []threatpriority.ActorPriority{})
		return
	}
	scores, err := h.threatPriorityEngine.ScoreAll(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, scores)
}

// threatPriorityActorDetail is the GET /api/threat-priority/actors/{name}
// response shape: the actor's ActorPriority plus history and the concrete
// list of uncovered techniques (feeds the Actor Details "Techniques"/
// "Coverage" tabs).
type threatPriorityActorDetail struct {
	threatpriority.ActorPriority
	History             []threatpriority.ActorPriorityHistory `json:"history"`
	UncoveredTechniques []string                              `json:"uncoveredTechniques"`
}

// GET /api/threat-priority/actors/{name}
func (h *Handler) ThreatPriorityActorDetail(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if h.threatPriorityEngine == nil {
		respond(w, threatPriorityActorDetail{UncoveredTechniques: []string{}})
		return
	}
	ap, err := h.threatPriorityEngine.Score(r.Context(), name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hist, err := h.threatPriorityEngine.History(r.Context(), name, 30)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scenarios := h.engine.List()
	sim := coverage.BuildSimulationIndex(scenarios)
	detect := coverage.BuildProfileIndex(h.engine.Profiles())
	compliant := coverage.BuildComplianceIndex(scenarios)

	uncovered := []string{}
	for _, id := range ap.TechniqueIDs {
		if !sim[id] && !detect[id] && !compliant[id] {
			uncovered = append(uncovered, id)
		}
	}

	respond(w, threatPriorityActorDetail{
		ActorPriority: ap, History: hist, UncoveredTechniques: uncovered,
	})
}
```

(This handler recomputes `sim`/`detect`/`compliant` indexes rather than reusing `threatpriority.Engine`'s internal `sharedIndexes` — that's intentional and matches every other handler in this codebase: `internal/coverage`'s indexes are cheap, pure, in-memory functions over already-loaded scenario data, not a DB round-trip, so recomputing them here rather than exporting `Engine`'s private `sharedIndexes` keeps the two packages decoupled at negligible cost. The Purple index is intentionally omitted from "uncovered" here since the spec's `CoverageGapCount` on `ActorPriority` already includes it via `Engine.scoreActor`'s calculation — this endpoint's `UncoveredTechniques` list is a lighter three-dimension view for display, not required to be a byte-for-byte re-derivation of `CoverageGapCount`.)

- [ ] **Step 4: Register routes**

In `orchestrator/internal/api/routes.go`, immediately after the existing block (lines 171-175: the `/api/coverage/matrix` / `/api/coverage/actors` registrations), add:

```go
		// Threat Prioritization -- standing, fleet-wide, per-actor composite
		// score (distinct from /api/coverage/matrix's technique-level view
		// and /api/recommend/simulations' technique-level ranking).
		r.Get("/api/threat-priority/actors", h.ThreatPriorityActors)
		r.Get("/api/threat-priority/actors/{name}", h.ThreatPriorityActorDetail)
```

- [ ] **Step 5: Add `routeMatrix` entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing `{http.MethodGet, "/api/coverage/actors", tierAny, ""},` line, add:

```go
	{http.MethodGet, "/api/threat-priority/actors", tierAny, ""},
	{http.MethodGet, "/api/threat-priority/actors/{name}", tierAny, ""},
```

- [ ] **Step 6: Wire `.WithThreatPriority` into the `main.go` handler chain**

In `orchestrator/cmd/server/main.go`, add `.WithThreatPriority(priorityEngine)` to the existing handler-construction chain (the `handler := api.New(...).WithCaldera(...)....WithScheduler(scheduler)...` chain around line 350) — insert it anywhere after `.WithScheduler(scheduler)`, e.g.:

```go
	handler := api.New(pool, hub, engine, cfg.JWTSecret).
		WithCaldera(cfg.CalderaURL, cfg.CalderaAPIKey).
		WithART(artStore).
		// ... existing chain unchanged ...
		WithReporting(reportingEngine).
		WithScheduler(scheduler).
		WithThreatPriority(priorityEngine).
		WithTicketing(ticketingManager).
		WithLicensePath(cfg.LicensePath).
		// ... rest of existing chain unchanged ...
```

- [ ] **Step 7: Run tests**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run "TestThreatPriorityActors|TestRBACMatrix_NoDrift" -short -v`
Expected: PASS for both.

- [ ] **Step 8: Commit**

```bash
git add internal/api/threatpriority_handlers.go internal/api/threatpriority_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go cmd/server/main.go
git commit -m "feat(api): GET /api/threat-priority/actors[/{name}] -- Threat Prioritization endpoints"
```

---

### Task 11: "Threat Prioritization" UI tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `GET /api/threat-priority/actors`, `GET /api/threat-priority/actors/{name}`, and (for the Recommendations drill-down sub-tab) the already-loaded `/api/recommend/simulations` client-side data.

- [ ] **Step 1: Add the nav item**

Immediately after the existing `attack-coverage` nav item (`wwwroot/index.html` lines 1303-1308), add:

```html
        <div class="nav-item" data-tab="threat-priority" onclick="showTab('threat-priority')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M8 1l2 4 4.5.5-3.25 3.25L12.25 13 8 10.75 3.75 13l1-4.25L1.5 5.5 6 5z"/>
          </svg>
          Threat Prioritization
        </div>
```

- [ ] **Step 2: Add the tab panel**

Immediately after the closing `</div>` of `tab-attack-coverage` (currently line 3102, right before the `<!-- Compliance (reached from the Reports hub) -->` comment), add:

```html
      <!-- Threat Prioritization -->
      <div id="tab-threat-priority" style="display:none">
        <div id="tp-list-view">
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Threat Prioritization</div>
            <div class="tbl-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Actor</th>
                    <th>Tier</th>
                    <th>Score</th>
                    <th>Trend</th>
                    <th>Coverage Gap</th>
                  </tr>
                </thead>
                <tbody id="tp-list-body"></tbody>
              </table>
            </div>
            <div id="tp-list-empty" class="empty" style="display:none">No threat actors tracked yet — configure a threat-intel connector to populate this view.</div>
          </div>
        </div>

        <div id="tp-detail-view" style="display:none">
          <div style="margin-bottom:0.75rem">
            <a class="tiny" style="color:var(--accent);cursor:pointer;text-decoration:none" onclick="showThreatPriorityList()">&lsaquo; Threat Prioritization</a>
          </div>
          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title" id="tp-detail-title">Actor</div>
            <div id="tp-detail-summary" class="score-grid" style="margin:0.75rem 0"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Why this score</div>
            <div id="tp-detail-factors"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">Uncovered Techniques</div>
            <div id="tp-detail-uncovered" class="tiny"></div>
          </div>

          <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
            <div class="card-title">History</div>
            <div id="tp-detail-history" class="tiny"></div>
          </div>

          <div class="card" style="padding:1rem 1.2rem">
            <div class="card-title">Recommendations for this actor</div>
            <div id="tp-detail-recs" class="tiny"></div>
          </div>
        </div>
      </div>
```

- [ ] **Step 3: Wire `TAB_TITLES`, `activateTab`'s array, and `showTab`**

In the `TAB_TITLES` object literal (line 3908), add `,'threat-priority':'Threat Prioritization'` before the closing `}`.

In the array at line 4040 (`['dashboard','agents',...,'attack-coverage']`), add `,'threat-priority'` before the closing `]`.

In `showTab`, find the existing dispatch line `if (name === 'attack-coverage') { loadCoverageActors(); loadCoverageMatrix(); }` (line 4057) and add immediately after it:

```javascript
  if (name === 'threat-priority') { showThreatPriorityList(); loadThreatPriorityActors(); }
```

- [ ] **Step 4: Add the JS functions**

Add these functions near `loadCoverageMatrix`/`loadRecommendations` (around line 4674, after `loadCoverageMatrix`'s closing brace):

```javascript
var TP_ACTOR_CACHE = [];

function showThreatPriorityList() {
  document.getElementById('tp-list-view').style.display = '';
  document.getElementById('tp-detail-view').style.display = 'none';
}

function tpTierBadge(tier) {
  var color = tier === 'Critical' ? 'var(--danger)' : tier === 'High' ? 'var(--warning)' : tier === 'Medium' ? 'var(--accent)' : 'var(--muted)';
  return '<span class="badge" style="color:' + color + ';border-color:' + color + '">' + x(tier || 'Low') + '</span>';
}

function tpTrendCell(trend, delta) {
  if (trend === 'up') return '<span style="color:var(--success)">&#9650; +' + delta + '</span>';
  if (trend === 'down') return '<span style="color:var(--danger)">&#9660; ' + delta + '</span>';
  if (trend === 'stable') return '<span class="tiny muted">&mdash;</span>';
  return '<span class="tiny muted">New</span>';
}

function loadThreatPriorityActors() {
  var body = document.getElementById('tp-list-body');
  var empty = document.getElementById('tp-list-empty');
  body.innerHTML = '<tr><td colspan="5" class="empty">Loading&hellip;</td></tr>';
  apicall('/api/threat-priority/actors')
    .then(function(actors) {
      TP_ACTOR_CACHE = actors || [];
      if (!TP_ACTOR_CACHE.length) {
        body.innerHTML = '';
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';
      body.innerHTML = TP_ACTOR_CACHE.map(function(a) {
        return '<tr style="cursor:pointer" onclick="showThreatPriorityDetail(' + JSON.stringify(a.actorName) + ')">' +
          '<td style="font-weight:600">' + x(a.actorName) + '</td>' +
          '<td>' + tpTierBadge(a.tier) + '</td>' +
          '<td>' + x(a.score) + '</td>' +
          '<td>' + tpTrendCell(a.trend, a.trendDelta) + '</td>' +
          '<td>' + x(a.coverageGapCount) + ' of ' + x(a.techniqueCount) + '</td>' +
          '</tr>';
      }).join('');
    })
    .catch(function(e) {
      body.innerHTML = '<tr><td colspan="5" class="empty" style="color:var(--danger)">Failed to load: ' + x(e.message) + '</td></tr>';
    });
}

function showThreatPriorityDetail(actorName) {
  document.getElementById('tp-list-view').style.display = 'none';
  document.getElementById('tp-detail-view').style.display = '';
  document.getElementById('tp-detail-title').textContent = actorName;

  apicall('/api/threat-priority/actors/' + encodeURIComponent(actorName))
    .then(function(d) { renderThreatPriorityDetail(d); })
    .catch(function(e) {
      document.getElementById('tp-detail-factors').innerHTML = '<div class="empty" style="color:var(--danger)">Failed to load: ' + x(e.message) + '</div>';
    });
}

function renderThreatPriorityDetail(d) {
  document.getElementById('tp-detail-summary').innerHTML =
    '<div class="score-card"><div class="score-label">Score</div><div class="score-value">' + x(d.score) + '</div></div>' +
    '<div class="score-card"><div class="score-label">Tier</div><div class="score-value">' + tpTierBadge(d.tier) + '</div></div>' +
    '<div class="score-card"><div class="score-label">Techniques</div><div class="score-value">' + x(d.techniqueCount) + '</div></div>' +
    '<div class="score-card"><div class="score-label">Coverage Gap</div><div class="score-value">' + x(d.coverageGapCount) + '</div></div>';

  var factors = (d.factors || []).map(function(f) {
    var val = f.available ? f.rawScore.toFixed(0) + '%' : 'Not yet validated';
    return '<div style="display:flex;justify-content:space-between;padding:0.4rem 0;border-bottom:1px solid var(--border)">' +
      '<div><div style="font-weight:600">' + x(f.name) + '</div><div class="tiny muted">' + x(f.explanation) + '</div></div>' +
      '<div style="font-weight:700">' + x(val) + '</div>' +
      '</div>';
  }).join('');
  document.getElementById('tp-detail-factors').innerHTML = factors || '<div class="empty">No factor data.</div>';

  var uncovered = (d.uncoveredTechniques || []);
  document.getElementById('tp-detail-uncovered').innerHTML = uncovered.length
    ? uncovered.map(function(t) { return '<span class="tool-tag">' + x(t) + '</span>'; }).join(' ')
    : '<span class="muted">No coverage gaps.</span>';

  var hist = (d.history || []);
  document.getElementById('tp-detail-history').innerHTML = hist.length
    ? '<table style="width:100%"><thead><tr><th>Date</th><th>Score</th></tr></thead><tbody>' +
      hist.map(function(h) { return '<tr><td>' + x(new Date(h.recordedAt).toLocaleDateString()) + '</td><td>' + x(h.score) + '</td></tr>'; }).join('') +
      '</tbody></table>'
    : '<span class="muted">No history yet.</span>';

  var techSet = {};
  (d.techniqueIds || []).forEach(function(t) { techSet[t] = true; });
  apicall('/api/recommend/simulations?limit=100').then(function(recData) {
    var matches = ((recData && recData.techniques) || []).filter(function(t) { return techSet[t.techniqueId]; });
    document.getElementById('tp-detail-recs').innerHTML = matches.length
      ? matches.map(function(t) { return '<div style="padding:0.3rem 0">' + x(t.techniqueId) + ' — ' + x(t.name) + ' <span class="tiny muted">(score ' + x(t.score) + ')</span></div>'; }).join('')
      : '<span class="muted">No open recommendations for this actor\'s techniques.</span>';
  }).catch(function() {
    document.getElementById('tp-detail-recs').innerHTML = '<span class="muted">Could not load recommendations.</span>';
  });
}
```

Note: `d.techniqueIds` — the API's `ActorPriority.TechniqueIDs` field is tagged `json:"-"` in Task 9 (deliberately not serialized, since it's Recommendation-rollup-internal). The detail endpoint's `UncoveredTechniques` IS serialized, but the *full* technique roster (needed here for the client-side Recommendations filter) is not currently exposed as JSON. Fix this now: in `orchestrator/internal/threatpriority/models.go`, change the tag from `json:"-"` to `json:"techniqueIds,omitempty"` — there's no actual reason to hide it from the detail endpoint's JSON response (only the *list* endpoint's bulk `ActorPriority` array benefits from staying lean, and `omitempty` keeps it out of that payload if desired, but simplest correct fix is to just serialize it everywhere; revisit Task 9's handler if a leaner list-endpoint payload turns out to matter later). Re-run Task 9's and Task 10's tests after this tag change to confirm nothing broke:

Run: `cd orchestrator && go test ./internal/threatpriority/... ./internal/api/... -short`
Expected: PASS.

- [ ] **Step 5: Structural verification**

Since there's no automated test harness for `wwwroot/index.html`, verify structurally (matching every prior tab addition this session): confirm `tab-threat-priority`, `nav-item[data-tab="threat-priority"]`, and the `TAB_TITLES`/array/`showTab` wiring are all present and consistently named, via:

```bash
cd orchestrator
grep -c 'data-tab="threat-priority"' wwwroot/index.html   # expect 1 (nav item)
grep -c 'id="tab-threat-priority"' wwwroot/index.html      # expect 1 (panel)
grep -c "'threat-priority'" wwwroot/index.html              # expect >=3 (TAB_TITLES, array, showTab dispatch)
```

Not live-browser-tested unless requested, matching this session's established scope for every prior tab addition (Technique Coverage, Exercises, OpenAEV).

- [ ] **Step 6: Commit**

```bash
git add wwwroot/index.html internal/threatpriority/models.go
git commit -m "feat(ui): Threat Prioritization tab -- ranked actor list + drill-down detail"
```

---

### Task 12: Final regression

- [ ] **Step 1: Full test suite**

Run: `cd orchestrator && go test ./... -count=1`
Expected: all packages PASS. If `internal/api` alone times out or shows a connection-refused error unrelated to this project's changes (this happened during Phase 1 due to shared-testcontainer flakiness, not a real regression), re-run just that package standalone (`go test ./internal/api/... -count=1`) to confirm — do not assume flakiness without re-running.

- [ ] **Step 2: Build**

Run: `cd orchestrator && go build ./...`
Expected: no errors.

- [ ] **Step 3: Vet**

Run: `cd orchestrator && go vet ./...`
Expected: no output.

- [ ] **Step 4: Confirm RBAC drift test specifically**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS (Task 10 added its `routeMatrix` entries in the same task as its routes, so this should never have drifted — this step just confirms it).

- [ ] **Step 5: Clean working tree**

Run: `git status --short`
Expected: no output (everything from Tasks 1-11 already committed).

- [ ] **Step 6: Push**

```bash
git push
```

---

## Plan Self-Review

**Spec coverage:** Problem/architecture → Tasks 3-8 (package + engine). Non-goals respected (no Repository/Graph work, no new connectors, no Campaign/Scenario drill-down, no RecommendationImpactFactor). 9 factors → Tasks 4-6. Adaptive weighting → Task 3's `blendWeights`. History/Scheduler integration → Task 8. Recommendation integration → Task 9. API → Task 10. UI → Task 11 (with v1 scope: Overview/Techniques/Coverage/History/Recommendations, matching the spec exactly — "Techniques" and "Coverage" tabs are combined into the detail view's factor breakdown + Uncovered Techniques card rather than separate sub-tabs, which is a reasonable UI simplification of the same underlying data, not a scope gap).

**Placeholder scan:** No TBD/TODO. Two spots initially deferred verification to the implementer (Task 8's `sharedDB`/`TestMain` setup, Task 10's chi URL-param test injection) — both were resolved during this self-review by checking the real code (`internal/testutil/testdb.go:124,154` for `testutil.TestDB`/`MustSharedTestDB`/`RunWithPool`; `internal/api/verification_queue_test.go:75-81` for the existing `withURLParams` helper) and replaced with concrete, verified code rather than left as "check this" instructions.

**Type consistency:** `ActorPriority`/`FactorResult`/`Context`/`ActorProfile` (Task 3) used identically through Tasks 4-11. `sharedIndexes` declared in Task 4, populated in Task 7, consumed in Tasks 4-6 — all field names (`simulation`, `detection`, `purple`, `compliance`, `preventionVerdict`, `validationVerdict`) match exactly everywhere they're referenced. `RecommendationScore`'s new 4-arg signature and `Build`'s new 8th parameter are consistent between Task 9's `score.go`/`recommend.go` edits and its `recommend_handlers.go` caller. `Handler.threatPriorityEngine`/`WithThreatPriority` (Task 9 Step 9) used consistently by Task 10's handlers.
