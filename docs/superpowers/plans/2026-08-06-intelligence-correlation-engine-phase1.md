# Intelligence Correlation Engine — Phase 1 (Backend) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Threat Intelligence, IOC Pipeline, Scenario Engine, and Detection Validation into one queryable correlation layer — `internal/correlation`, backend-only, no UI — so later features (Threat Coverage Analysis, Threat-aware Recommendations, Executive Metrics) become queries over this layer instead of each reinventing the joins.

**Architecture:** Three layers. Relationship Discovery (reused as-is: `threatgraph.TechniqueNeighborhood`/`ActorNeighborhood`/`IOCNeighborhood`, `reporting.ResolveActorTechniques`, new `scenariosForTechnique`) finds raw facts without normalizing. Canonical Resolution (`resolveCanonicalTechnique`, wrapping `attackdata.Lookup`) is the sole place technique identity — name/description/platforms/tactics — gets resolved; every `TechniqueCorrelation` the engine emits carries a fully-populated `CanonicalTechnique`, never inferred from how sparse a technique's relationship data happens to be. Correlation Output (`Engine.CorrelateTechnique`/`CorrelateActor`/`CorrelateIOC`) assembles layers 1+2 and adds the one judgment call, `Recommendation`.

**Tech Stack:** Go, `pgx/v5` (`*pgxpool.Pool`), Postgres, chi router. New package `internal/correlation`. Consumes `internal/threatgraph`, `internal/threatpriority`, `internal/reporting`, `internal/reporting/attackdata`, `internal/scenario`, `internal/verification`.

## Global Constraints

- Module path: `github.com/audspect/bas`. All new code lives under `orchestrator/`.
- No schema/migration changes — this phase only reads existing tables (`threat_actor_profiles`, `intelligence_campaigns/malware/tools`, `scenario_runs`, `verification_history`, `iocs`, `ioc_sightings`) and the embedded `attackdata` bundle.
- New API endpoints are `tierAny` (Viewer+), matching every other read-only endpoint (`GetIOCs`, `GetIOCAnalytics`, `KnowledgeGraphNeighborhood`).
- No changes to `threatgraph`'s existing behavior (including `ActorNeighborhood`'s unaliased technique nodes) — the correlation engine works around it, doesn't modify it.
- DB-backed tests use the `sharedDB`/`TestMain`/`RunWithPool` pattern already established in `internal/threatgraph`, `internal/api`, `internal/analytics` — never a fresh pattern.
- Commit after each task (steps say exactly when).

---

### Task 1: `internal/threatpriority` — export and widen the verdict loaders

**Files:**
- Modify: `orchestrator/internal/threatpriority/models.go` (add `VerdictEntry`, widen `sharedIndexes` field types)
- Modify: `orchestrator/internal/threatpriority/engine.go` (rename+export `loadPreventionVerdicts`/`loadValidationVerdicts`, widen SQL+scan)
- Test: `orchestrator/internal/threatpriority/engine_test.go`

**Interfaces:**
- Produces: `type VerdictEntry struct { Verdict string; At time.Time }`; `func LoadPreventionVerdicts(ctx context.Context, pool *pgxpool.Pool) (map[string]VerdictEntry, error)`; `func LoadValidationVerdicts(ctx context.Context, pool *pgxpool.Pool) (map[string]VerdictEntry, error)`. Task 6 (`internal/correlation`) is the first outside consumer.

- [ ] **Step 1: Write the failing test for `LoadPreventionVerdicts`'s timestamp**

Add to `orchestrator/internal/threatpriority/engine_test.go`:

```go
func TestLoadPreventionVerdicts_LatestWinsAndCarriesTimestamp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		older := time.Now().UTC().Add(-48 * time.Hour)
		newer := time.Now().UTC().Add(-1 * time.Hour)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('vt-run-old', 'vt-scn', 'VT Old', 'vt-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1059"},"result":"fail","executedAt":"`+older.Format(time.RFC3339)+`"}]`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('vt-run-new', 'vt-scn', 'VT New', 'vt-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1059"},"result":"pass","executedAt":"`+newer.Format(time.RFC3339)+`"}]`)

		verdicts, err := LoadPreventionVerdicts(ctx, pool)
		if err != nil {
			t.Fatalf("LoadPreventionVerdicts: %v", err)
		}
		v, ok := verdicts["T1059"]
		if !ok {
			t.Fatal("expected T1059 in the verdict map")
		}
		if v.Verdict != "pass" {
			t.Errorf("Verdict = %q, want %q (the later run)", v.Verdict, "pass")
		}
		if v.At.Sub(newer).Abs() > time.Second {
			t.Errorf("At = %v, want ~%v (the later run's executedAt)", v.At, newer)
		}
	})
}
```

Add a `mustExec` test helper to the same file if the package doesn't already have one (check first — `internal/threatpriority` has no existing DB-backed tests, so it won't):

```go
func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}
```

Add a `TestMain`/`sharedDB` to the same package (it currently has none — every other DB-backed package in this codebase does):

```go
var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}
```

Add imports to `engine_test.go`: `"flag"`, `"os"`, `"time"`, `"github.com/jackc/pgx/v5/pgxpool"`, `"github.com/audspect/bas/internal/testutil"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run TestLoadPreventionVerdicts_LatestWinsAndCarriesTimestamp -v`
Expected: FAIL with "undefined: LoadPreventionVerdicts"

- [ ] **Step 3: Add `VerdictEntry` and widen `sharedIndexes`**

In `orchestrator/internal/threatpriority/models.go`, add after the `FactorResult` struct:

```go
// VerdictEntry is one technique's latest fleet-wide verdict plus when it was
// recorded -- exported so internal/correlation (and any future consumer) can
// reuse the exact same "what does fleet-wide validation status mean" logic
// instead of re-deriving it.
type VerdictEntry struct {
	Verdict string
	At      time.Time
}
```

Change `sharedIndexes`'s two verdict fields:

```go
type sharedIndexes struct {
	simulation, detection, purple, compliance map[string]bool
	preventionVerdict                         map[string]VerdictEntry // technique ID (upper) -> latest scenario_runs verdict+timestamp
	validationVerdict                         map[string]VerdictEntry // technique ID (upper) -> latest verification.Result*+timestamp
}
```

- [ ] **Step 4: Export and widen the loaders in `engine.go`**

Replace `loadPreventionVerdicts`:

```go
// LoadPreventionVerdicts returns, per technique ID (uppercase), the verdict
// of its most recent scenario_runs result (completed/partial runs only,
// error/skipped excluded) and when that run executed. Exported for
// internal/correlation (see docs/superpowers/specs/2026-08-05-intelligence-correlation-engine-design.md).
func LoadPreventionVerdicts(ctx context.Context, pool *pgxpool.Pool) (map[string]VerdictEntry, error) {
	if pool == nil {
		return map[string]VerdictEntry{}, nil
	}
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (UPPER(r->'technique'->>'id'))
		       UPPER(r->'technique'->>'id') AS tid,
		       r->>'result'                 AS verdict,
		       (r->>'executedAt')::timestamptz AS at
		FROM scenario_runs sr, jsonb_array_elements(sr.results) r
		WHERE sr.status IN ('completed', 'partial')
		  AND r->'technique'->>'id' IS NOT NULL AND r->'technique'->>'id' <> ''
		  AND r->>'result' NOT IN ('error', 'skipped')
		ORDER BY UPPER(r->'technique'->>'id'), (r->>'executedAt')::timestamptz DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]VerdictEntry{}
	for rows.Next() {
		var tid string
		var v VerdictEntry
		if err := rows.Scan(&tid, &v.Verdict, &v.At); err != nil {
			return nil, err
		}
		out[tid] = v
	}
	return out, rows.Err()
}
```

Replace `loadValidationVerdicts`:

```go
// LoadValidationVerdicts returns, per technique ID (uppercase), the most
// recent active+Approved verification_history verdict (Detected/NotDetected
// only) and when it was verified. Exported for internal/correlation.
func LoadValidationVerdicts(ctx context.Context, pool *pgxpool.Pool) (map[string]VerdictEntry, error) {
	if pool == nil {
		return map[string]VerdictEntry{}, nil
	}
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (technique_id) technique_id, result, verified_at
		FROM verification_history
		WHERE active AND workflow_state = $1 AND result IN ($2, $3)
		ORDER BY technique_id, verified_at DESC`,
		verification.StateApproved, verification.ResultDetected, verification.ResultNotDetected)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]VerdictEntry{}
	for rows.Next() {
		var tid string
		var v VerdictEntry
		if err := rows.Scan(&tid, &v.Verdict, &v.At); err != nil {
			return nil, err
		}
		out[strings.ToUpper(tid)] = v
	}
	return out, rows.Err()
}
```

Update `buildSharedIndexes` (the two call sites, `engine.go:62-72`) to call the exported names:

```go
	prevention, err := LoadPreventionVerdicts(ctx, e.pool)
	if err != nil {
		return nil, fmt.Errorf("load prevention verdicts: %w", err)
	}
	idx.preventionVerdict = prevention

	validation, err := LoadValidationVerdicts(ctx, e.pool)
	if err != nil {
		return nil, fmt.Errorf("load validation verdicts: %w", err)
	}
	idx.validationVerdict = validation
```

The two existence-check call sites in `scoreActor` (`engine.go:190,194`, `if _, ok := shared.preventionVerdict[upper]; ok`) need no change — they still compile and mean the same thing against `map[string]VerdictEntry`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run TestLoadPreventionVerdicts_LatestWinsAndCarriesTimestamp -v`
Expected: PASS

- [ ] **Step 6: Run the full package test suite to check for fallout**

Run: `cd orchestrator && go build ./... && go test ./internal/threatpriority/... -v`
Expected: build succeeds; `TestNewEngine_UsesDefaultFactors` and `TestScoreActor_ComputesCompositeFromRealFactors` still pass unchanged (they don't touch `preventionVerdict`/`validationVerdict`). `validation_factors_test.go`'s 4 tests will fail to compile at this point (`map[string]string` literal against a `map[string]VerdictEntry` field) — that's expected, fixed in Task 2. Confirm the failure is exactly a type mismatch on `preventionVerdict:`/`validationVerdict:` struct literals, nothing else.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/threatpriority/models.go orchestrator/internal/threatpriority/engine.go orchestrator/internal/threatpriority/engine_test.go
git commit -m "feat(threatpriority): export+widen verdict loaders with timestamps"
```

---

### Task 2: `internal/threatpriority` — fix `validationPct` for the widened verdict type

**Files:**
- Modify: `orchestrator/internal/threatpriority/validation_factors.go`
- Modify: `orchestrator/internal/threatpriority/validation_factors_test.go`

**Interfaces:**
- Consumes: `VerdictEntry{Verdict string, At time.Time}` from Task 1.
- Produces: `validationPct(tctx Context, idx map[string]VerdictEntry, isSuccess func(string) bool, label string) (float64, string, bool, error)` — same signature shape as before except `idx`'s value type.

- [ ] **Step 1: Update the 4 existing tests to build `VerdictEntry` maps**

In `orchestrator/internal/threatpriority/validation_factors_test.go`, replace all 4 map literals:

```go
func TestPreventionSuccessFactor_Score(t *testing.T) {
	f := PreventionSuccessFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105", "T1566"},
		shared: &sharedIndexes{preventionVerdict: map[string]VerdictEntry{
			"T1059": {Verdict: "pass"}, // control blocked it
			"T1105": {Verdict: "fail"}, // ran through unblocked
			// T1566 never tested -- excluded from the denominator
		}},
	}
	raw, explanation, available, err := f.Score(context.Background(), tctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Fatal("expected available=true")
	}
	if raw != 50 {
		t.Fatalf("raw = %.2f, want 50 (1 of 2 tested techniques prevented)", raw)
	}
	if explanation != "1 of 2 validated techniques prevented" {
		t.Fatalf("explanation = %q", explanation)
	}
}

func TestPreventionSuccessFactor_NoneTested_Unavailable(t *testing.T) {
	f := PreventionSuccessFactor{}
	_, _, available, _ := f.Score(context.Background(), Context{
		TechniqueIDs: []string{"T1059"},
		shared:       &sharedIndexes{preventionVerdict: map[string]VerdictEntry{}},
	})
	if available {
		t.Fatal("expected available=false when nothing tested")
	}
}

func TestValidationSuccessFactor_Score(t *testing.T) {
	f := ValidationSuccessFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105"},
		shared: &sharedIndexes{validationVerdict: map[string]VerdictEntry{
			"T1059": {Verdict: "Detected"},
			"T1105": {Verdict: "NotDetected"},
		}},
	}
	raw, explanation, available, err := f.Score(context.Background(), tctx)
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
```

`TestValidationFactors_WeightScalesWithBlend` (the 4th test) doesn't touch either map — leave it as-is.

Add one new test proving the `.Verdict` extraction (not the whole struct) drives the comparison, independent of `At`:

```go
func TestValidationPct_IgnoresAtWhenComparingVerdict(t *testing.T) {
	f := PreventionSuccessFactor{}
	oldTime := time.Now().Add(-999 * time.Hour)
	tctx := Context{
		TechniqueIDs: []string{"T1059"},
		shared: &sharedIndexes{preventionVerdict: map[string]VerdictEntry{
			"T1059": {Verdict: "fail", At: oldTime}, // stale timestamp, but Verdict is what's compared
		}},
	}
	raw, _, available, _ := f.Score(context.Background(), tctx)
	if !available || raw != 0 {
		t.Fatalf("raw=%.2f available=%v, want 0/true (fail is not success regardless of At)", raw, available)
	}
}
```

Add `"time"` to the file's imports.

- [ ] **Step 2: Run tests to verify they fail (compile error)**

Run: `cd orchestrator && go test ./internal/threatpriority/... -run TestPreventionSuccessFactor -v`
Expected: FAIL to compile — `validationPct`'s `idx map[string]string` parameter doesn't match `map[string]VerdictEntry` arguments yet.

- [ ] **Step 3: Fix `validationPct` in `validation_factors.go`**

```go
func validationPct(tctx Context, idx map[string]VerdictEntry, isSuccess func(string) bool, label string) (float64, string, bool, error) {
	tested, success := 0, 0
	for _, id := range tctx.TechniqueIDs {
		v, ok := idx[strings.ToUpper(id)]
		if !ok {
			continue
		}
		tested++
		if isSuccess(v.Verdict) {
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

(Only two changes from the original: the parameter type, and `isSuccess(v)` → `isSuccess(v.Verdict)`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/threatpriority/... -v`
Expected: PASS, whole package. This also confirms Task 1's build-fallout from Step 6 is now resolved.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/threatpriority/validation_factors.go orchestrator/internal/threatpriority/validation_factors_test.go
git commit -m "fix(threatpriority): read VerdictEntry.Verdict in validationPct"
```

---

### Task 3: `internal/correlation` — package skeleton, types, and Canonical Resolution

**Files:**
- Create: `orchestrator/internal/correlation/types.go`
- Create: `orchestrator/internal/correlation/canonical.go`
- Test: `orchestrator/internal/correlation/canonical_test.go`

**Interfaces:**
- Consumes: `attackdata.Lookup(id string) *attackdata.Enrichment` (existing, `internal/reporting/attackdata`).
- Produces: `type CanonicalTechnique struct { ID, Name, Description string; Platforms, Tactics []string; URL string }`; `func resolveCanonicalTechnique(id string) CanonicalTechnique`. Every later task in this plan depends on `CanonicalTechnique` and `resolveCanonicalTechnique`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/correlation/canonical_test.go`:

```go
package correlation

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

func TestResolveCanonicalTechnique_KnownID_MatchesAttackdata(t *testing.T) {
	want := attackdata.Lookup("T1059.001")
	if want == nil {
		t.Fatal("test fixture assumption broken: T1059.001 not in the bundled ATT&CK data")
	}
	got := resolveCanonicalTechnique("T1059.001")
	if got.ID != "T1059.001" {
		t.Errorf("ID = %q, want %q", got.ID, "T1059.001")
	}
	if got.Name != want.Name {
		t.Errorf("Name = %q, want %q (must match attackdata.Lookup exactly, never drift)", got.Name, want.Name)
	}
	if len(got.Platforms) != len(want.Platforms) {
		t.Errorf("Platforms = %v, want %v", got.Platforms, want.Platforms)
	}
}

func TestResolveCanonicalTechnique_UnknownID_NeverBlank(t *testing.T) {
	got := resolveCanonicalTechnique("T9999.999")
	if got.ID != "T9999.999" {
		t.Errorf("ID = %q, want %q", got.ID, "T9999.999")
	}
	if got.Name == "" {
		t.Fatal("Name must never be blank -- the never-blank invariant -- want ID-echo fallback")
	}
	if got.Name != "T9999.999" {
		t.Errorf("Name = %q, want the ID itself as the fallback", got.Name)
	}
}

func TestResolveCanonicalTechnique_SubTechniqueFallback_KeepsQueriedID(t *testing.T) {
	// attackdata.go's own Lookup docstring documents T1003.099 as an example
	// of a sub-technique with no enrichment of its own, falling back to its
	// parent T1003's data. This test proves resolveCanonicalTechnique keeps
	// the ORIGINALLY QUERIED ID (T1003.099), not the parent's ID (T1003) that
	// attackdata.Lookup's returned Enrichment.TechniqueID would carry -- using
	// the fallback entry's own ID here would misidentify which technique this is.
	parent := attackdata.Lookup("T1003")
	if parent == nil {
		t.Fatal("test fixture assumption broken: T1003 not in the bundled ATT&CK data")
	}
	got := resolveCanonicalTechnique("T1003.099")
	if got.ID != "T1003.099" {
		t.Errorf("ID = %q, want %q (the queried sub-technique, not the parent it fell back to)", got.ID, "T1003.099")
	}
	if got.Name != parent.Name {
		t.Errorf("Name = %q, want %q (inherited from parent, per attackdata's documented fallback)", got.Name, parent.Name)
	}
}

func TestResolveCanonicalTechnique_NormalizesCase(t *testing.T) {
	got := resolveCanonicalTechnique(strings.ToLower("T1059.001"))
	if got.ID != "T1059.001" {
		t.Errorf("ID = %q, want uppercase %q", got.ID, "T1059.001")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/correlation/... -v`
Expected: FAIL — package `internal/correlation` doesn't exist yet.

- [ ] **Step 3: Create `types.go`**

```go
package correlation

import (
	"time"

	"github.com/audspect/bas/internal/threatgraph"
)

// CanonicalTechnique is the Canonical Resolution layer's output -- the one
// place technique identity (name/description/platforms/tactics) is
// resolved. Every TechniqueCorrelation embeds one; nothing downstream
// re-derives these fields from relationship data. Sourced exclusively from
// attackdata.Lookup (the same authoritative ATT&CK bundle
// GET /api/attack/technique/{id} already serves) -- never inferred from
// threatgraph neighborhoods. See resolveCanonicalTechnique.
type CanonicalTechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	Tactics     []string `json:"tactics,omitempty"`
	URL         string   `json:"url,omitempty"`
}

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
// else is a fetched/joined relationship.
type Recommendation struct {
	Action string `json:"action"` // "run" | "revalidate" | "none" | "no_scenario"
	Reason string `json:"reason"` // human-readable, e.g. "Never validated" / "Last run 132 days ago, fail"
}

// TechniqueCorrelation is the full correlated view of one ATT&CK technique.
// Technique is always fully populated -- see resolveCanonicalTechnique. The
// only place this type is constructed is inside internal/correlation itself.
type TechniqueCorrelation struct {
	Technique      CanonicalTechnique `json:"technique"`
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
	IOCID      string                 `json:"iocId"`
	Type       string                 `json:"type"`
	Value      string                 `json:"value"`
	Techniques []TechniqueCorrelation `json:"techniques"`
}
```

- [ ] **Step 4: Create `canonical.go`**

```go
package correlation

import (
	"strings"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// resolveCanonicalTechnique is the package's single Canonical Resolution
// entry point -- the only function permitted to set a TechniqueCorrelation's
// Technique field. attackdata.Lookup already sub-technique-falls-back to a
// parent's data (attackdata.go:224-228) when a sub-technique has no
// enrichment of its own; ID is always set to the originally-queried,
// normalized id -- NOT attackdata.Enrichment.TechniqueID, which on a
// parent-fallback would be the PARENT's ID and would misidentify which
// technique this is. When even the fallback misses (an ID with relationship
// or scenario data but no bundle entry at all), this still returns a
// non-empty CanonicalTechnique{ID: id, Name: id}, so "every technique
// leaving the engine is canonicalized" holds even in the miss case.
func resolveCanonicalTechnique(id string) CanonicalTechnique {
	id = strings.ToUpper(strings.TrimSpace(id))
	e := attackdata.Lookup(id)
	if e == nil {
		return CanonicalTechnique{ID: id, Name: id}
	}
	return CanonicalTechnique{
		ID:          id,
		Name:        e.Name,
		Description: e.Description,
		Platforms:   e.Platforms,
		Tactics:     e.Tactics,
		URL:         e.URL,
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/correlation/... -v`
Expected: PASS, all 4 tests.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/correlation/types.go orchestrator/internal/correlation/canonical.go orchestrator/internal/correlation/canonical_test.go
git commit -m "feat(correlation): package skeleton, types, and Canonical Resolution layer"
```

---

### Task 4: `internal/correlation` — `scenariosForTechnique`

**Files:**
- Create: `orchestrator/internal/correlation/scenarios.go`
- Test: `orchestrator/internal/correlation/scenarios_test.go`

**Interfaces:**
- Consumes: `scenario.Engine.List() []*scenario.Scenario`, `scenario.Scenario{ID, Name string; Steps []scenario.Step}`, `scenario.Step{TechniqueID string}` (all existing, `internal/scenario`).
- Produces: `func scenariosForTechnique(scenarioEngine *scenario.Engine, techniqueID string) []ScenarioRef`. Task 6's `correlateTechnique` calls this.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/correlation/scenarios_test.go`:

```go
package correlation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func writeScenarioFixture(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatalf("write scenario fixture: %v", err)
	}
}

func TestScenariosForTechnique_MatchesAndDeduplicatesPerScenario(t *testing.T) {
	dir := t.TempDir()
	writeScenarioFixture(t, dir, "sc-match.yaml",
		"id: sc-match\nname: Matching Scenario\nsteps:\n"+
			"  - name: step one\n    technique_id: T1059.001\n"+
			"  - name: step two\n    technique_id: T1059.001\n") // same technique twice -- must not double-count
	writeScenarioFixture(t, dir, "sc-nomatch.yaml",
		"id: sc-nomatch\nname: Unrelated Scenario\nsteps:\n"+
			"  - name: step one\n    technique_id: T1003\n")

	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}

	got := scenariosForTechnique(eng, "T1059.001")
	if len(got) != 1 {
		t.Fatalf("got %d scenarios, want exactly 1 (deduplicated within the matching scenario)", len(got))
	}
	if got[0].ID != "sc-match" || got[0].Name != "Matching Scenario" {
		t.Errorf("got %+v, want {sc-match, Matching Scenario}", got[0])
	}
}

func TestScenariosForTechnique_NoMatch_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeScenarioFixture(t, dir, "sc-nomatch.yaml",
		"id: sc-nomatch\nname: Unrelated Scenario\nsteps:\n"+
			"  - name: step one\n    technique_id: T1003\n")
	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}

	got := scenariosForTechnique(eng, "T9999.999")
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestScenariosForTechnique_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	writeScenarioFixture(t, dir, "sc-match.yaml",
		"id: sc-match\nname: Matching Scenario\nsteps:\n"+
			"  - name: step one\n    technique_id: T1059.001\n")
	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}

	got := scenariosForTechnique(eng, "t1059.001")
	if len(got) != 1 {
		t.Fatalf("got %d scenarios, want 1 (case-insensitive match)", len(got))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/correlation/... -run TestScenariosForTechnique -v`
Expected: FAIL with "undefined: scenariosForTechnique"

- [ ] **Step 3: Implement `scenarios.go`**

```go
package correlation

import (
	"strings"

	"github.com/audspect/bas/internal/scenario"
)

// scenariosForTechnique mirrors coverage.BuildSimulationIndex's iteration
// over scenarioEngine.List()/sc.Steps, but appends a ScenarioRef per
// matching scenario instead of setting a bool -- the correlation engine
// needs to know WHICH scenario(s) cover a technique, not just whether one
// does. A scenario with multiple steps for the same technique contributes
// exactly one ScenarioRef (the inner break), matching BuildSimulationIndex's
// own per-scenario-not-per-step semantics.
func scenariosForTechnique(scenarioEngine *scenario.Engine, techniqueID string) []ScenarioRef {
	var out []ScenarioRef
	for _, sc := range scenarioEngine.List() {
		for _, step := range sc.Steps {
			if strings.EqualFold(step.TechniqueID, techniqueID) {
				out = append(out, ScenarioRef{ID: sc.ID, Name: sc.Name})
				break
			}
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/correlation/... -v`
Expected: PASS, all tests (Task 3's + this task's).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/correlation/scenarios.go orchestrator/internal/correlation/scenarios_test.go
git commit -m "feat(correlation): scenariosForTechnique (Relationship Discovery)"
```

---

### Task 5: `internal/correlation` — validation lookup and `Recommendation`

**Files:**
- Create: `orchestrator/internal/correlation/recommendation.go`
- Test: `orchestrator/internal/correlation/recommendation_test.go`

**Interfaces:**
- Consumes: `threatpriority.VerdictEntry{Verdict string, At time.Time}` (Task 1); `verification.ResultDetected` (existing, `internal/verification`).
- Produces: `func lookupValidation(techniqueID string, prevention, validation map[string]threatpriority.VerdictEntry) *ValidationStatus`; `func computeRecommendation(v *ValidationStatus, hasScenario bool) Recommendation`. Task 6's `correlateTechnique` calls both.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/correlation/recommendation_test.go`:

```go
package correlation

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/verification"
)

func TestLookupValidation_PreventionCheckedFirst(t *testing.T) {
	now := time.Now()
	prevention := map[string]threatpriority.VerdictEntry{"T1059": {Verdict: "pass", At: now}}
	validation := map[string]threatpriority.VerdictEntry{"T1059": {Verdict: verification.ResultDetected, At: now.Add(-time.Hour)}}

	got := lookupValidation("T1059", prevention, validation)
	if got == nil || got.Source != "prevention" || got.Verdict != "pass" {
		t.Fatalf("got %+v, want prevention/pass (prevention takes precedence)", got)
	}
}

func TestLookupValidation_FallsBackToDetection(t *testing.T) {
	prevention := map[string]threatpriority.VerdictEntry{}
	validation := map[string]threatpriority.VerdictEntry{"T1059": {Verdict: verification.ResultDetected}}

	got := lookupValidation("T1059", prevention, validation)
	if got == nil || got.Source != "detection" || got.Verdict != verification.ResultDetected {
		t.Fatalf("got %+v, want detection/%s", got, verification.ResultDetected)
	}
}

func TestLookupValidation_NeitherPresent_ReturnsNil(t *testing.T) {
	got := lookupValidation("T1059", map[string]threatpriority.VerdictEntry{}, map[string]threatpriority.VerdictEntry{})
	if got != nil {
		t.Fatalf("got %+v, want nil (never validated)", got)
	}
}

func TestLookupValidation_CaseInsensitive(t *testing.T) {
	prevention := map[string]threatpriority.VerdictEntry{"T1059": {Verdict: "pass"}}
	got := lookupValidation("t1059", prevention, map[string]threatpriority.VerdictEntry{})
	if got == nil {
		t.Fatal("expected a match regardless of input case")
	}
}

func TestComputeRecommendation_NeverValidated_HasScenario(t *testing.T) {
	got := computeRecommendation(nil, true)
	if got.Action != "run" || got.Reason != "Never validated" {
		t.Errorf("got %+v, want {run, Never validated}", got)
	}
}

func TestComputeRecommendation_NeverValidated_NoScenario(t *testing.T) {
	got := computeRecommendation(nil, false)
	if got.Action != "no_scenario" {
		t.Errorf("got %+v, want action=no_scenario", got)
	}
}

func TestComputeRecommendation_FailedPrevention_Revalidate(t *testing.T) {
	v := &ValidationStatus{Verdict: "fail", Source: "prevention", At: time.Now().Add(-72 * time.Hour)}
	got := computeRecommendation(v, true)
	if got.Action != "revalidate" {
		t.Errorf("Action = %q, want revalidate", got.Action)
	}
}

func TestComputeRecommendation_NotDetected_Revalidate(t *testing.T) {
	v := &ValidationStatus{Verdict: verification.ResultNotDetected, Source: "detection", At: time.Now()}
	got := computeRecommendation(v, true)
	if got.Action != "revalidate" {
		t.Errorf("Action = %q, want revalidate", got.Action)
	}
}

func TestComputeRecommendation_PassedPrevention_None(t *testing.T) {
	v := &ValidationStatus{Verdict: "pass", Source: "prevention", At: time.Now()}
	got := computeRecommendation(v, true)
	if got.Action != "none" {
		t.Errorf("Action = %q, want none", got.Action)
	}
}

func TestComputeRecommendation_Detected_None(t *testing.T) {
	v := &ValidationStatus{Verdict: verification.ResultDetected, Source: "detection", At: time.Now()}
	got := computeRecommendation(v, true)
	if got.Action != "none" {
		t.Errorf("Action = %q, want none", got.Action)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/correlation/... -run 'TestLookupValidation|TestComputeRecommendation' -v`
Expected: FAIL with "undefined: lookupValidation" / "undefined: computeRecommendation"

- [ ] **Step 3: Implement `recommendation.go`**

```go
package correlation

import (
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/verification"
)

// lookupValidation checks the prevention verdict map first, then the
// validation (detection) map -- matching threatpriority.scoreActor's own
// precedence (engine.go:190-196). Returns nil when a technique has never
// been validated by either path.
func lookupValidation(techniqueID string, prevention, validation map[string]threatpriority.VerdictEntry) *ValidationStatus {
	id := strings.ToUpper(strings.TrimSpace(techniqueID))
	if v, ok := prevention[id]; ok {
		return &ValidationStatus{Verdict: v.Verdict, Source: "prevention", At: v.At}
	}
	if v, ok := validation[id]; ok {
		return &ValidationStatus{Verdict: v.Verdict, Source: "detection", At: v.At}
	}
	return nil
}

// isSuccessVerdict mirrors validation_factors.go's own two isSuccess
// predicates (v == "pass" for prevention, v == verification.ResultDetected
// for validation) collapsed into one function, since Recommendation doesn't
// need to know which path produced the verdict to judge success/failure.
func isSuccessVerdict(v string) bool {
	return v == "pass" || v == verification.ResultDetected
}

// computeRecommendation is the one judgment call this package makes.
func computeRecommendation(v *ValidationStatus, hasScenario bool) Recommendation {
	if v == nil {
		if hasScenario {
			return Recommendation{Action: "run", Reason: "Never validated"}
		}
		return Recommendation{Action: "no_scenario", Reason: "No scenario available for this technique"}
	}
	days := int(time.Since(v.At).Hours() / 24)
	if isSuccessVerdict(v.Verdict) {
		return Recommendation{Action: "none", Reason: fmt.Sprintf("Validated %d days ago", days)}
	}
	return Recommendation{Action: "revalidate", Reason: fmt.Sprintf("Last run %d days ago, %s", days, v.Verdict)}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/correlation/... -v`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/correlation/recommendation.go orchestrator/internal/correlation/recommendation_test.go
git commit -m "feat(correlation): validation lookup and Recommendation judgment"
```

---

### Task 6: `internal/correlation` — `Engine` and `CorrelateTechnique`

**Files:**
- Create: `orchestrator/internal/correlation/engine.go`
- Test: `orchestrator/internal/correlation/engine_test.go`

**Interfaces:**
- Consumes: `threatgraph.TechniqueNeighborhood(ctx, pool, id) (threatgraph.Neighborhood, error)`, `threatgraph.Node{ID, Type, Label string}`, `threatgraph.NodeTypeActor/Campaign/Malware/Tool/Technique` (existing, `internal/threatgraph`); `threatpriority.LoadPreventionVerdicts`/`LoadValidationVerdicts` (Task 1); `resolveCanonicalTechnique` (Task 3); `scenariosForTechnique` (Task 4); `lookupValidation`/`computeRecommendation` (Task 5).
- Produces: `type Engine struct{...}`; `func NewEngine(pool *pgxpool.Pool, scenarioEngine *scenario.Engine) *Engine`; `func (e *Engine) CorrelateTechnique(ctx context.Context, techniqueID string) (TechniqueCorrelation, error)`; the unexported `func (e *Engine) correlateTechnique(ctx context.Context, techniqueID string, prevention, validation map[string]threatpriority.VerdictEntry) (TechniqueCorrelation, error)` that Task 7/8 (`CorrelateActor`/`CorrelateIOC`) call directly to share verdict maps across many techniques in one call.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/correlation/engine_test.go`:

```go
package correlation

import (
	"context"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// findTechniqueWithNoGroupAttribution returns a real bundled technique ID
// that has a Name but zero attackdata.GroupTechniqueIndex() attribution --
// dynamically discovered rather than hardcoded so this test doesn't silently
// break if a future MITRE bundle update adds group attribution for whatever
// ID today's snapshot happens to lack one for. Fatal if the bundle assumption
// (coverage is inherently partial -- some technique has none) ever breaks.
func findTechniqueWithNoGroupAttribution(t *testing.T) string {
	t.Helper()
	attributed := map[string]bool{}
	for _, ids := range attackdata.GroupTechniqueIndex() {
		for _, id := range ids {
			attributed[strings.ToUpper(id)] = true
		}
	}
	for _, ref := range attackdata.All() {
		if !attributed[strings.ToUpper(ref.ID)] {
			return ref.ID
		}
	}
	t.Fatal("test fixture assumption broken: every bundled technique has group attribution")
	return ""
}

func TestCorrelateTechnique_ZeroRelationships_StillPopulatesCanonicalTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	techID := findTechniqueWithNoGroupAttribution(t)
	want := attackdata.Lookup(techID)
	if want == nil || want.Name == "" {
		t.Fatalf("test fixture assumption broken: %s has no bundled Name", techID)
	}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		tc, err := eng.CorrelateTechnique(context.Background(), techID)
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		// This is the regression test for self-review catch #1: with zero
		// actor/campaign/malware/tool relationships, TechniqueNeighborhood
		// returns a completely empty Neighborhood -- Technique.Name must
		// still be correct, proving it comes from resolveCanonicalTechnique,
		// never from Neighborhood.Nodes[0].Label.
		if tc.Technique.Name != want.Name {
			t.Errorf("Technique.Name = %q, want %q (must come from attackdata, not relationship data)", tc.Technique.Name, want.Name)
		}
		if len(tc.Actors) != 0 || len(tc.Campaigns) != 0 || len(tc.Malware) != 0 || len(tc.Tools) != 0 {
			t.Errorf("expected zero relationships for this fixture technique, got Actors=%v Campaigns=%v Malware=%v Tools=%v", tc.Actors, tc.Campaigns, tc.Malware, tc.Tools)
		}
	})
}

func TestCorrelateTechnique_KnownActor_PopulatesActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	// "Wizard Spider" is a real bundled ATT&CK group -- same fixture
	// internal/threatgraph's own tests and internal/connector/otx_test.go rely on.
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" not found in GroupTechniqueIndex()")
	}
	techID := wantTechs[0]

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		tc, err := eng.CorrelateTechnique(context.Background(), techID)
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		found := false
		for _, a := range tc.Actors {
			if a.Label == "Wizard Spider" {
				found = true
			}
		}
		if !found {
			t.Errorf("Actors = %+v, want to include Wizard Spider", tc.Actors)
		}
	})
}

func TestCorrelateTechnique_WithScenario_PopulatesScenariosAndRunRecommendation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/sc.yaml", []byte(
			"id: corr-fixture-sc\nname: Correlation Fixture Scenario\nsteps:\n  - name: step one\n    technique_id: T1059.001\n"),
			0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		scEngine := scenario.NewEngine(dir)
		if err := scEngine.Load(); err != nil {
			t.Fatalf("scEngine.Load: %v", err)
		}

		eng := NewEngine(pool, scEngine)
		tc, err := eng.CorrelateTechnique(context.Background(), "T1059.001")
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		if len(tc.Scenarios) != 1 || tc.Scenarios[0].ID != "corr-fixture-sc" {
			t.Fatalf("Scenarios = %+v, want [corr-fixture-sc]", tc.Scenarios)
		}
		if tc.Validation != nil {
			t.Fatalf("Validation = %+v, want nil (never run)", tc.Validation)
		}
		if tc.Recommendation.Action != "run" {
			t.Errorf("Recommendation.Action = %q, want run", tc.Recommendation.Action)
		}
	})
}

func TestCorrelateTechnique_NoScenario_RecommendationIsNoScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		tc, err := eng.CorrelateTechnique(context.Background(), "T1546.008") // real ID, unlikely to be in any test's empty scenario dir
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		if tc.Recommendation.Action != "no_scenario" {
			t.Errorf("Recommendation.Action = %q, want no_scenario", tc.Recommendation.Action)
		}
	})
}

func TestCorrelateTechnique_PreventionVerdict_SetsValidationAndRecommendation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('corr-run-1', 'corr-scn-1', 'Corr Test Run', 'corr-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1003"},"result":"fail","executedAt":"2026-01-01T00:00:00Z"}]`)

		dir := t.TempDir()
		if err := os.WriteFile(dir+"/sc.yaml", []byte(
			"id: corr-fixture-sc2\nname: Corr Fixture 2\nsteps:\n  - name: step one\n    technique_id: T1003\n"),
			0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		scEngine := scenario.NewEngine(dir)
		if err := scEngine.Load(); err != nil {
			t.Fatalf("scEngine.Load: %v", err)
		}

		eng := NewEngine(pool, scEngine)
		tc, err := eng.CorrelateTechnique(context.Background(), "T1003")
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		if tc.Validation == nil || tc.Validation.Source != "prevention" || tc.Validation.Verdict != "fail" {
			t.Fatalf("Validation = %+v, want {fail, prevention, ...}", tc.Validation)
		}
		if tc.Recommendation.Action != "revalidate" {
			t.Errorf("Recommendation.Action = %q, want revalidate", tc.Recommendation.Action)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/correlation/... -run TestCorrelateTechnique -v`
Expected: FAIL with "undefined: NewEngine" / "undefined: Engine"

- [ ] **Step 3: Implement `engine.go`**

```go
package correlation

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatgraph"
	"github.com/audspect/bas/internal/threatpriority"
)

type Engine struct {
	pool           *pgxpool.Pool
	scenarioEngine *scenario.Engine
}

// NewEngine wires the engine to a Postgres pool (threatgraph/threatpriority
// queries) and the scenario Engine (scenariosForTechnique). Mirrors
// threatpriority.NewEngine's construction pattern.
func NewEngine(pool *pgxpool.Pool, scenarioEngine *scenario.Engine) *Engine {
	return &Engine{pool: pool, scenarioEngine: scenarioEngine}
}

// CorrelateTechnique is the standalone entry point: loads its own
// single-call verdict maps, then delegates to correlateTechnique.
func (e *Engine) CorrelateTechnique(ctx context.Context, techniqueID string) (TechniqueCorrelation, error) {
	prevention, err := threatpriority.LoadPreventionVerdicts(ctx, e.pool)
	if err != nil {
		return TechniqueCorrelation{}, err
	}
	validation, err := threatpriority.LoadValidationVerdicts(ctx, e.pool)
	if err != nil {
		return TechniqueCorrelation{}, err
	}
	return e.correlateTechnique(ctx, techniqueID, prevention, validation)
}

// correlateTechnique is the shared body CorrelateActor/CorrelateIOC call
// per-technique, taking already-built verdict maps so they're loaded once
// per Correlate* call, never once per technique -- the same "shared indexes
// built once" discipline threatpriority.Engine already established.
//
// Step 0 (Canonical Resolution) runs before any relationship lookup: see
// resolveCanonicalTechnique's doc comment for why -- TechniqueNeighborhood
// returns a completely empty Neighborhood for a technique with zero
// relationships, so deriving the name from it (the original design draft)
// would leave TechniqueName blank for most techniques.
func (e *Engine) correlateTechnique(ctx context.Context, techniqueID string, prevention, validation map[string]threatpriority.VerdictEntry) (TechniqueCorrelation, error) {
	tc := TechniqueCorrelation{Technique: resolveCanonicalTechnique(techniqueID)}

	nb, err := threatgraph.TechniqueNeighborhood(ctx, e.pool, tc.Technique.ID)
	if err != nil {
		return TechniqueCorrelation{}, err
	}
	for _, node := range nb.Nodes {
		switch node.Type {
		case threatgraph.NodeTypeActor:
			tc.Actors = append(tc.Actors, node)
		case threatgraph.NodeTypeCampaign:
			tc.Campaigns = append(tc.Campaigns, node)
		case threatgraph.NodeTypeMalware:
			tc.Malware = append(tc.Malware, node)
		case threatgraph.NodeTypeTool:
			tc.Tools = append(tc.Tools, node)
			// NodeTypeTechnique is the neighborhood's own self-node -- skipped,
			// Technique is already set above from Canonical Resolution.
		}
	}

	tc.Scenarios = scenariosForTechnique(e.scenarioEngine, tc.Technique.ID)
	tc.Validation = lookupValidation(tc.Technique.ID, prevention, validation)
	tc.Recommendation = computeRecommendation(tc.Validation, len(tc.Scenarios) > 0)
	return tc, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/correlation/... -v`
Expected: PASS, all tests in the package so far.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/correlation/engine.go orchestrator/internal/correlation/engine_test.go
git commit -m "feat(correlation): Engine and CorrelateTechnique (Correlation Output)"
```

---

### Task 7: `internal/correlation` — `CorrelateActor`

**Files:**
- Modify: `orchestrator/internal/correlation/engine.go`
- Modify: `orchestrator/internal/correlation/engine_test.go`

**Interfaces:**
- Consumes: `reporting.ResolveActorTechniques(name string, aliases []string) (techIDs []string, canonicalGroup string, ok bool)` (existing, `internal/reporting`); `threatgraph.ActorNeighborhood(ctx, pool, name) (threatgraph.Neighborhood, error)` (existing); `e.correlateTechnique` (Task 6).
- Produces: `func (e *Engine) CorrelateActor(ctx context.Context, actorName string) (ActorCorrelation, error)`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/correlation/engine_test.go`:

```go
func TestCorrelateActor_TwoTechniques_EachIndependentlyCorrelated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) < 2 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" needs at least 2 techniques")
	}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			VALUES ('Wizard Spider', '{}', '{}', '{}', 'test')`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('corr-actor-run', 'corr-actor-scn', 'Corr Actor Run', 'corr-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"`+wantTechs[0]+`"},"result":"pass","executedAt":"2026-01-01T00:00:00Z"}]`)
		mustExec(t, pool, `INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			VALUES ('corr-actor-campaign', 'Corr Actor Campaign', '', $1, '{}', 'test')`, []string{"Wizard Spider"})

		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ac, err := eng.CorrelateActor(context.Background(), "Wizard Spider")
		if err != nil {
			t.Fatalf("CorrelateActor: %v", err)
		}
		if len(ac.Techniques) != len(wantTechs) {
			t.Fatalf("Techniques = %d, want %d (full ResolveActorTechniques roster)", len(ac.Techniques), len(wantTechs))
		}
		var sawValidated, sawUnvalidated bool
		for _, tc := range ac.Techniques {
			if tc.Technique.ID == strings.ToUpper(wantTechs[0]) {
				if tc.Validation == nil || tc.Validation.Verdict != "pass" {
					t.Errorf("technique %s: Validation = %+v, want {pass, prevention}", wantTechs[0], tc.Validation)
				}
				sawValidated = true
			} else if tc.Validation == nil {
				sawUnvalidated = true
			}
		}
		if !sawValidated || !sawUnvalidated {
			t.Errorf("expected a mix of validated/unvalidated techniques, got sawValidated=%v sawUnvalidated=%v", sawValidated, sawUnvalidated)
		}
		foundCampaign := false
		for _, c := range ac.Campaigns {
			if c.Label == "Corr Actor Campaign" {
				foundCampaign = true
			}
		}
		if !foundCampaign {
			t.Errorf("Campaigns = %+v, want to include Corr Actor Campaign", ac.Campaigns)
		}
	})
}

func TestCorrelateActor_DiscardsActorNeighborhoodTechniqueNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	// Disambiguation regression test: ActorNeighborhood internally resolves
	// its own (unaliased) technique nodes via GroupTechniqueIndex()[name] --
	// CorrelateActor's technique roster must come exclusively from
	// ResolveActorTechniques, so ac.Techniques' length must equal the
	// alias-aware roster length even though ActorNeighborhood also returns
	// technique-type nodes internally.
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			VALUES ('Wizard Spider', '{}', '{}', '{}', 'test')`)

		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ac, err := eng.CorrelateActor(context.Background(), "Wizard Spider")
		if err != nil {
			t.Fatalf("CorrelateActor: %v", err)
		}
		if len(ac.Techniques) != len(wantTechs) {
			t.Fatalf("Techniques = %d, want exactly %d (ResolveActorTechniques' roster, not ActorNeighborhood's)", len(ac.Techniques), len(wantTechs))
		}
	})
}

func TestCorrelateActor_UnknownActor_ReturnsEmptyNotError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ac, err := eng.CorrelateActor(context.Background(), "NoSuchActor")
		if err != nil {
			t.Fatalf("CorrelateActor: %v", err)
		}
		if len(ac.Techniques) != 0 || len(ac.Campaigns) != 0 {
			t.Errorf("got %+v, want empty (no profile row, no known aliases)", ac)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/correlation/... -run TestCorrelateActor -v`
Expected: FAIL with "undefined: CorrelateActor"

- [ ] **Step 3: Implement `CorrelateActor` in `engine.go`**

Add the import `"github.com/audspect/bas/internal/reporting"` and `"github.com/jackc/pgx/v5"` (for `pgx.ErrNoRows`), then append:

```go
// CorrelateActor resolves the actor's technique roster via the alias-aware
// reporting.ResolveActorTechniques (not threatgraph.ActorNeighborhood's own
// internal, unaliased GroupTechniqueIndex()[name] lookup -- see the
// Disambiguation note below), correlates each technique with shared verdict
// maps built once, and surfaces actor-level campaign/malware/tool from
// ActorNeighborhood (not per-technique -- intelligence_malware/tools aren't
// specific to one technique in the existing schema).
func (e *Engine) CorrelateActor(ctx context.Context, actorName string) (ActorCorrelation, error) {
	aliases, err := e.loadActorAliases(ctx, actorName)
	if err != nil {
		return ActorCorrelation{}, err
	}
	techIDs, _, _ := reporting.ResolveActorTechniques(actorName, aliases)

	prevention, err := threatpriority.LoadPreventionVerdicts(ctx, e.pool)
	if err != nil {
		return ActorCorrelation{}, err
	}
	validation, err := threatpriority.LoadValidationVerdicts(ctx, e.pool)
	if err != nil {
		return ActorCorrelation{}, err
	}

	ac := ActorCorrelation{ActorName: actorName}
	for _, id := range techIDs {
		tc, err := e.correlateTechnique(ctx, id, prevention, validation)
		if err != nil {
			return ActorCorrelation{}, err
		}
		ac.Techniques = append(ac.Techniques, tc)
	}

	nb, err := threatgraph.ActorNeighborhood(ctx, e.pool, actorName)
	if err != nil {
		return ActorCorrelation{}, err
	}
	// Disambiguation: ActorNeighborhood also resolves and returns its own
	// technique nodes internally (assemble.go:194, the unaliased
	// GroupTechniqueIndex()[name] path this package does not standardize
	// on) -- only campaign/malware/tool nodes are kept here; technique
	// (and actor/sector/region) nodes are discarded, since the technique
	// roster above already came exclusively from ResolveActorTechniques.
	for _, node := range nb.Nodes {
		switch node.Type {
		case threatgraph.NodeTypeCampaign:
			ac.Campaigns = append(ac.Campaigns, node)
		case threatgraph.NodeTypeMalware:
			ac.Malware = append(ac.Malware, node)
		case threatgraph.NodeTypeTool:
			ac.Tools = append(ac.Tools, node)
		}
	}
	return ac, nil
}

// loadActorAliases is a small, independent query -- matches this session's
// established tolerance for this scale of duplication between independent
// read paths (internal/db.GetRunIOCsEnriched vs. GetRunIOCs is the
// precedent) rather than exporting threatpriority's own unexported
// loadProfile just for this one column.
func (e *Engine) loadActorAliases(ctx context.Context, name string) ([]string, error) {
	var aliases []string
	err := e.pool.QueryRow(ctx, `SELECT aliases FROM threat_actor_profiles WHERE name = $1`, name).Scan(&aliases)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return aliases, err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/correlation/... -v`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/correlation/engine.go orchestrator/internal/correlation/engine_test.go
git commit -m "feat(correlation): CorrelateActor with alias-aware technique roster"
```

---

### Task 8: `internal/correlation` — `CorrelateIOC`

**Files:**
- Modify: `orchestrator/internal/correlation/engine.go`
- Modify: `orchestrator/internal/correlation/engine_test.go`

**Interfaces:**
- Consumes: `threatgraph.IOCNeighborhood(ctx, pool, iocID) (threatgraph.Neighborhood, error)` (existing); `e.correlateTechnique` (Task 6).
- Produces: `func (e *Engine) CorrelateIOC(ctx context.Context, iocID string) (IOCCorrelation, error)`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/correlation/engine_test.go`:

```go
func TestCorrelateIOC_SeededSighting_CorrelatesItsTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var iocID string
		if err := pool.QueryRow(context.Background(), `
			INSERT INTO iocs (type, value, source) VALUES ('command_line', 'whoami /all', 'detection_alert')
			RETURNING id`).Scan(&iocID); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}
		mustExec(t, pool, `INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id, technique_id)
			VALUES ($1, 'corr-ioc-scn', 'corr-ioc-run', 'corr-ioc-agent', 'T1059')`, iocID)

		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ic, err := eng.CorrelateIOC(context.Background(), iocID)
		if err != nil {
			t.Fatalf("CorrelateIOC: %v", err)
		}
		if ic.Type != "command_line" || ic.Value != "whoami /all" {
			t.Errorf("Type/Value = %q/%q, want command_line/whoami /all", ic.Type, ic.Value)
		}
		if len(ic.Techniques) != 1 || ic.Techniques[0].Technique.ID != "T1059" {
			t.Fatalf("Techniques = %+v, want exactly [T1059]", ic.Techniques)
		}
	})
}

func TestCorrelateIOC_NoSightings_ReturnsIOCIdentityNoTechniques(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var iocID string
		if err := pool.QueryRow(context.Background(), `
			INSERT INTO iocs (type, value, source) VALUES ('process', 'powershell.exe', 'detection_alert')
			RETURNING id`).Scan(&iocID); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}

		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ic, err := eng.CorrelateIOC(context.Background(), iocID)
		if err != nil {
			t.Fatalf("CorrelateIOC: %v", err)
		}
		if ic.Type != "process" || len(ic.Techniques) != 0 {
			t.Errorf("got %+v, want Type=process, zero Techniques", ic)
		}
	})
}

func TestCorrelateIOC_UnknownID_ReturnsEmptyNotError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ic, err := eng.CorrelateIOC(context.Background(), "does-not-exist")
		if err != nil {
			t.Fatalf("CorrelateIOC: %v", err)
		}
		if ic.Type != "" || len(ic.Techniques) != 0 {
			t.Errorf("got %+v, want empty", ic)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/correlation/... -run TestCorrelateIOC -v`
Expected: FAIL with "undefined: CorrelateIOC"

- [ ] **Step 3: Implement `CorrelateIOC` in `engine.go`**

Add `"strings"` to the imports, then append:

```go
// CorrelateIOC reads the IOC's own type/value directly (a small,
// independent query, same duplication tolerance as loadActorAliases --
// avoids parsing threatgraph.IOCNeighborhood's combined "type: value"
// Label back apart), then walks IOCNeighborhood for its technique(s) (via
// ioc_sightings.technique_id, already real) and correlates each with shared
// verdict maps built once.
func (e *Engine) CorrelateIOC(ctx context.Context, iocID string) (IOCCorrelation, error) {
	ic := IOCCorrelation{IOCID: iocID}
	err := e.pool.QueryRow(ctx, `SELECT type, value FROM iocs WHERE id = $1`, iocID).Scan(&ic.Type, &ic.Value)
	if err != nil && err != pgx.ErrNoRows {
		return IOCCorrelation{}, err
	}

	nb, err := threatgraph.IOCNeighborhood(ctx, e.pool, iocID)
	if err != nil {
		return IOCCorrelation{}, err
	}
	var techIDs []string
	for _, node := range nb.Nodes {
		if node.Type == threatgraph.NodeTypeTechnique {
			techIDs = append(techIDs, strings.TrimPrefix(node.ID, "technique:"))
		}
	}
	if len(techIDs) == 0 {
		return ic, nil
	}

	prevention, err := threatpriority.LoadPreventionVerdicts(ctx, e.pool)
	if err != nil {
		return IOCCorrelation{}, err
	}
	validation, err := threatpriority.LoadValidationVerdicts(ctx, e.pool)
	if err != nil {
		return IOCCorrelation{}, err
	}
	for _, id := range techIDs {
		tc, err := e.correlateTechnique(ctx, id, prevention, validation)
		if err != nil {
			return IOCCorrelation{}, err
		}
		ic.Techniques = append(ic.Techniques, tc)
	}
	return ic, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/correlation/... -v`
Expected: PASS, all tests in the package.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/correlation/engine.go orchestrator/internal/correlation/engine_test.go
git commit -m "feat(correlation): CorrelateIOC"
```

---

### Task 9: API layer — 3 endpoints, RBAC, routing

**Files:**
- Create: `orchestrator/internal/api/correlation_handlers.go`
- Test: `orchestrator/internal/api/correlation_handlers_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (add `correlationEngine` field + `WithCorrelation`)
- Modify: `orchestrator/internal/api/routes.go` (register 3 routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add 3 rows)

**Interfaces:**
- Consumes: `correlation.Engine.CorrelateTechnique/CorrelateActor/CorrelateIOC` (Tasks 6-8); `correlation.TechniqueCorrelation/ActorCorrelation/IOCCorrelation/CanonicalTechnique` (Task 3).
- Produces: `GET /api/correlation/technique/{id}`, `GET /api/correlation/actor/{name}`, `GET /api/correlation/ioc/{id}`; `Handler.WithCorrelation(*correlation.Engine) *Handler`. Task 10 (`cmd/server/main.go`) calls `WithCorrelation`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/correlation_handlers_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/correlation"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func correlationHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	eng := scenario.NewEngine(t.TempDir())
	return New(pool, ws.NewHub(), eng, "").WithCorrelation(correlation.NewEngine(pool, eng))
}

func TestCorrelateTechniqueHandler_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	want := attackdata.Lookup("T1059.001")
	if want == nil {
		t.Fatal("test fixture assumption broken: T1059.001 not bundled")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := correlationHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CorrelateTechnique(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/api/correlation/technique/T1059.001", nil), "id", "T1059.001"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out correlation.TechniqueCorrelation
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Technique.Name != want.Name {
			t.Errorf("Technique.Name = %q, want %q", out.Technique.Name, want.Name)
		}
	})
}

func TestCorrelateActorHandler_UnknownActor_Returns200Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := correlationHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CorrelateActor(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/api/correlation/actor/NoSuchActor", nil), "name", "NoSuchActor"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (unknown actor is an empty correlation, not an error)", rec.Code)
		}
		var out correlation.ActorCorrelation
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out.Techniques) != 0 {
			t.Errorf("Techniques = %+v, want empty", out.Techniques)
		}
	})
}

func TestCorrelateIOCHandler_UnknownID_Returns200Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := correlationHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CorrelateIOC(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/api/correlation/ioc/does-not-exist", nil), "id", "does-not-exist"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestCorrelate -v`
Expected: FAIL with "undefined: h.CorrelateTechnique" / "undefined: Handler.WithCorrelation"

- [ ] **Step 3: Add the `correlationEngine` field and `WithCorrelation`**

In `orchestrator/internal/api/handlers.go`, add the field next to `threatPriorityEngine` (near line 104):

```go
	correlationEngine     *correlation.Engine // nil when not loaded — Intelligence Correlation Engine
```

Add the import `"github.com/audspect/bas/internal/correlation"` to the file's import block.

Add the setter next to `WithThreatPriority` (near line 165):

```go
// WithCorrelation attaches the intelligence correlation engine.
func (h *Handler) WithCorrelation(e *correlation.Engine) *Handler {
	h.correlationEngine = e
	return h
}
```

- [ ] **Step 4: Create the handlers**

Create `orchestrator/internal/api/correlation_handlers.go`:

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/correlation"
)

// CorrelateTechnique returns the full correlated view of one ATT&CK
// technique -- actors/campaigns/malware/tools that use it, scenarios that
// cover it, its current validation status, and a recommendation.
// GET /api/correlation/technique/{id}
func (h *Handler) CorrelateTechnique(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.correlationEngine == nil {
		respond(w, correlation.TechniqueCorrelation{Technique: correlation.CanonicalTechnique{ID: id, Name: id}})
		return
	}
	tc, err := h.correlationEngine.CorrelateTechnique(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, tc)
}

// CorrelateActor returns one actor's full, individually-correlated
// technique roster plus actor-level campaign/malware/tool relationships.
// GET /api/correlation/actor/{name}
func (h *Handler) CorrelateActor(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if h.correlationEngine == nil {
		respond(w, correlation.ActorCorrelation{ActorName: name})
		return
	}
	ac, err := h.correlationEngine.CorrelateActor(r.Context(), name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ac)
}

// CorrelateIOC returns an IOC's own identity plus every technique it's been
// sighted alongside, each individually correlated.
// GET /api/correlation/ioc/{id}
func (h *Handler) CorrelateIOC(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.correlationEngine == nil {
		respond(w, correlation.IOCCorrelation{IOCID: id})
		return
	}
	ic, err := h.correlationEngine.CorrelateIOC(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ic)
}
```

- [ ] **Step 5: Register the routes**

In `orchestrator/internal/api/routes.go`, add after line 221 (`r.Get("/api/knowledge-graph/{type}/{id}", h.KnowledgeGraphNeighborhood)`):

```go
		// Intelligence Correlation Engine -- Phase 1 (backend). One queryable
		// layer over Threat Intel + IOC Pipeline + Scenario Engine + Detection
		// Validation. See docs/superpowers/specs/2026-08-05-intelligence-correlation-engine-design.md.
		r.Get("/api/correlation/technique/{id}", h.CorrelateTechnique)
		r.Get("/api/correlation/actor/{name}", h.CorrelateActor)
		r.Get("/api/correlation/ioc/{id}", h.CorrelateIOC)
```

- [ ] **Step 6: Add RBAC matrix rows**

In `orchestrator/internal/api/rbac_matrix_test.go`, add after line 97 (`{http.MethodGet, "/api/knowledge-graph/{type}/{id}", tierAny, ""},`):

```go
	{http.MethodGet, "/api/correlation/technique/{id}", tierAny, ""},
	{http.MethodGet, "/api/correlation/actor/{name}", tierAny, ""},
	{http.MethodGet, "/api/correlation/ioc/{id}", tierAny, ""},
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestCorrelate|TestRBACMatrix_NoDrift' -v`
Expected: PASS. `TestRBACMatrix_NoDrift` confirms the 3 new routes.go registrations exactly match the 3 new rbac_matrix_test.go rows (catches typos in either).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/correlation_handlers.go orchestrator/internal/api/correlation_handlers_test.go orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): wire 3 Intelligence Correlation Engine endpoints"
```

---

### Task 10: Wire the engine into `cmd/server/main.go`

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `correlation.NewEngine(pool *pgxpool.Pool, scenarioEngine *scenario.Engine) *correlation.Engine` (Task 6); `Handler.WithCorrelation` (Task 9).
- Produces: nothing further downstream — this is the final wiring task.

- [ ] **Step 1: Construct the engine**

In `orchestrator/cmd/server/main.go`, add after line 290 (`priorityEngine := threatpriority.NewEngine(pool, engine, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)`):

```go
	correlationEngine := correlation.NewEngine(pool, engine)
```

Add the import `"github.com/audspect/bas/internal/correlation"` to `main.go`'s import block.

- [ ] **Step 2: Attach it to the handler chain**

In the `New(...)` handler-chain call (near line 450, alongside `.WithThreatPriority(priorityEngine).`), add:

```go
		WithThreatPriority(priorityEngine).
		WithCorrelation(correlationEngine).
```

- [ ] **Step 3: Verify the full build**

Run: `cd orchestrator && go build ./...`
Expected: builds cleanly, no unused-import or undefined-symbol errors.

- [ ] **Step 4: Run the full test suite**

Run: `cd orchestrator && go test ./... -short`
Expected: PASS (the `-short` flag skips every container-backed test across the whole module — this just confirms nothing non-DB-backed broke). Then, if Docker is available on this machine (check with `docker info`), run the full suite including container-backed tests:

Run: `cd orchestrator && go test ./...`
Expected: PASS, including every new `-short`-skipped test written in Tasks 1-9.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/cmd/server/main.go
git commit -m "feat(server): wire Intelligence Correlation Engine into the handler chain"
```

---

## Self-Review

**Spec coverage:**
- 3-layer architecture (§0 of the spec) → Task 3 (Canonical Resolution), Tasks 4+6-8 (Relationship Discovery reuse), Task 6 (Correlation Output assembly). ✓
- `VerdictEntry` export+widen, and the corrected `validationPct` finding → Tasks 1-2. ✓
- `internal/correlation` package, all 3 struct families, `resolveCanonicalTechnique`, `scenariosForTechnique`, `computeRecommendation` → Tasks 3-8. ✓
- Self-review catch #1 (empty-Neighborhood blank name) → explicit regression test in Task 6 Step 1 (`TestCorrelateTechnique_ZeroRelationships_StillPopulatesCanonicalTechnique`). ✓
- Self-review catch #2 (ActorNeighborhood's unaliased technique nodes) → explicit regression test in Task 7 Step 1 (`TestCorrelateActor_DiscardsActorNeighborhoodTechniqueNodes`). ✓
- Sub-technique canonicalization edge case (T1003.099 → parent's data, queried ID kept) → explicit test in Task 3 Step 1. ✓
- 3 API endpoints, `tierAny`, `WithCorrelation` mirroring `WithThreatPriority` → Task 9. ✓
- `cmd/server/main.go` wiring → Task 10. ✓
- Non-goals (aggregation, UI, per-agent granularity, ID-deprecation-forwarding, OTX/MISP adversary-name matching) → deliberately have no task; nothing in this plan touches them. ✓

**Placeholder scan:** no TBD/TODO; every step has real code, every test has real assertions.

**Type consistency:** `VerdictEntry` (Task 1) → `map[string]VerdictEntry` used identically in Tasks 2, 5, 6, 7, 8. `CanonicalTechnique`/`TechniqueCorrelation`/`ActorCorrelation`/`IOCCorrelation` (Task 3) used identically in every later task's signatures. `resolveCanonicalTechnique`, `scenariosForTechnique`, `lookupValidation`, `computeRecommendation` (Tasks 3-5) called with matching signatures in Task 6. `correlateTechnique` (unexported, Task 6) called identically by `CorrelateActor` (Task 7) and `CorrelateIOC` (Task 8) with the same `(ctx, techniqueID, prevention, validation)` shape.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-06-intelligence-correlation-engine-phase1.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
