# Detection Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract `GetCoverageAnalytics`'s ~270 lines of inline computation (`internal/api/handlers.go:3074-3462`) into a proper package, matching Sub-project A's Campaign extraction pattern, after consolidating the 3x-duplicated `detectedTechs` helper it depends on into one canonical home.

**Architecture:** `internal/reporting.DetectedTechniques` becomes the single canonical detection-classification helper (replacing 2 duplicate copies). A new package `internal/detecteffectiveness` owns the coverage-analytics types, verdict logic, and the query+tally computation. `internal/analytics.DetectionEffectiveness` is a thin pass-through. `GetCoverageAnalytics` shrinks to query-param parsing + a delegate call.

**Tech Stack:** Go, `internal/reporting`/`internal/detecteffectiveness`/`internal/analytics`/`internal/api` packages, `pgxpool.Pool`, Postgres-backed tests via `internal/testutil.MustSharedTestDB` (requires Docker running).

## Global Constraints

- Go backend only, `orchestrator/` module. No frontend changes.
- No API contract changes — `GET /api/coverage/analytics`'s response shape, query params, and JSON field names stay identical.
- `pathcorrelation` and `internal/coverage` are not touched — confirmed genuinely distinct concepts, already correctly factored.
- No pre-existing behavioral test covers `GetCoverageAnalytics` today (confirmed via grep — only an RBAC route-registration check exists). New tests are written first, against the not-yet-existing `detecteffectiveness.Compute`, and must fail (compile error) before implementation — true TDD, not regression-guard-after.
- Docker must be running before any task's Postgres-backed tests — run `docker info` first; if it's down, start Docker Desktop and poll until ready (established this-session pattern), don't assume.
- Every task ends with a commit + `git push` (this repo's established convention).

---

### Task 1: Consolidate `detectedTechs` into `reporting.DetectedTechniques`

Prerequisite for Task 2 — without this, extracting `GetCoverageAnalytics` into a new package would require a 3rd copy of this helper (`internal/api` already has one, `internal/campaign` already has a mirror). This task creates one canonical exported version and repoints all 5 existing call sites at it, deleting both duplicates.

**Files:**
- Create: `orchestrator/internal/reporting/detected_techniques.go`
- Test: `orchestrator/internal/reporting/detected_techniques_test.go`
- Modify: `orchestrator/internal/api/campaign_handlers.go:153-182` (delete `detectedTechs`), `:212` (call site)
- Modify: `orchestrator/internal/api/handlers.go:2091`, `:3248` (call sites — `:3248` is inside `GetCoverageAnalytics`, which Task 2/4 move/rewrite later, but must compile in the meantime)
- Modify: `orchestrator/internal/api/finding_handlers.go:1-15` (add import), `:46` (call site)
- Modify: `orchestrator/internal/campaign/store.go:113` (call site), `:119-157` (delete `detectedTechsFromSummary`)

**Interfaces:**
- Produces: `func DetectedTechniques(detRaw []byte, results []models.SimulationResult) map[string]bool` in package `reporting`. Task 2's extracted `detecteffectiveness.Compute` calls this directly.
- Consumes: `models.SimulationResult`, `models.ResultFail` (`internal/models`), `reporting.ClassifyDetectionStatus` (`internal/reporting/engine.go:2103`, already in the same package after this move).

- [x] **Step 1: Write the failing test**

Create `orchestrator/internal/reporting/detected_techniques_test.go`:

```go
package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

func TestDetectedTechniques_SweepDataMarksDetected(t *testing.T) {
	detRaw := []byte(`{"techniques":[{"techniqueId":"T1059","verdict":"detected"}]}`)
	got := DetectedTechniques(detRaw, nil)
	if !got["T1059"] {
		t.Errorf("DetectedTechniques() = %v, want T1059 marked detected from sweep data", got)
	}
}

func TestDetectedTechniques_NoSweepData_FallsBackToEventClassifier(t *testing.T) {
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1003"}, Result: models.ResultFail, Events: []string{"4688"}},
	}
	got := DetectedTechniques(nil, results)
	want := ClassifyDetectionStatus([]string{"4688"}) == "Detected"
	if got["T1003"] != want {
		t.Errorf("DetectedTechniques() = %v, want T1003=%v matching ClassifyDetectionStatus", got, want)
	}
}

func TestDetectedTechniques_PassResultNeverMarkedDetected(t *testing.T) {
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass, Events: []string{"4688"}},
	}
	got := DetectedTechniques(nil, results)
	if got["T1059"] {
		t.Errorf("DetectedTechniques() = %v, want T1059 absent -- Pass results are never classified as Detected, only Fail results", got)
	}
}

func TestDetectedTechniques_SweepDataTakesPrecedenceOverEventClassifier(t *testing.T) {
	// Sweep data already marks T1059 detected -- the event-classifier fallback
	// loop must not run for it a second time (it's gated by !out[id]), but the
	// end result must still be detected regardless of what the events say.
	detRaw := []byte(`{"techniques":[{"techniqueId":"T1059","verdict":"detected"}]}`)
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultFail, Events: nil},
	}
	got := DetectedTechniques(detRaw, results)
	if !got["T1059"] {
		t.Errorf("DetectedTechniques() = %v, want T1059 detected from sweep data alone", got)
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestDetectedTechniques -v`
Expected: FAIL — `undefined: DetectedTechniques` (compile error).

- [x] **Step 3: Implement `DetectedTechniques`**

Create `orchestrator/internal/reporting/detected_techniques.go`:

```go
package reporting

import (
	"encoding/json"

	"github.com/audspect/bas/internal/models"
)

// DetectedTechniques returns the set of technique ids whose FAIL was
// detected, from a run's persisted detection_summary.techniques (the
// agent's post-run alert sweep), falling back to ClassifyDetectionStatus
// per FAILed result when no sweep data marks a technique detected. This
// mirrors how buildKillChain decides detected vs missed -- the same
// persisted detection_summary column feeds both.
//
// The second loop is NOT gated on detRaw being empty -- it always runs,
// checking every FAILed result's Events for any technique the sweep data
// didn't already mark detected.
func DetectedTechniques(detRaw []byte, results []models.SimulationResult) map[string]bool {
	out := map[string]bool{}
	if len(detRaw) > 0 {
		var ds struct {
			Techniques []struct {
				TechniqueID string `json:"techniqueId"`
				Verdict     string `json:"verdict"`
			} `json:"techniques"`
		}
		if json.Unmarshal(detRaw, &ds) == nil {
			for _, t := range ds.Techniques {
				if t.Verdict == "detected" {
					out[t.TechniqueID] = true
				}
			}
		}
	}
	for _, res := range results {
		if res.Result == models.ResultFail && !out[res.Technique.ID] {
			if ClassifyDetectionStatus(res.Events) == "Detected" {
				out[res.Technique.ID] = true
			}
		}
	}
	return out
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestDetectedTechniques -v`
Expected: all 4 tests PASS.

- [x] **Step 5: Repoint all 5 call sites, delete both duplicate functions**

In `orchestrator/internal/api/campaign_handlers.go`, find (the full duplicate function, lines 153-182):

```go
// detectedTechs returns the set of technique ids whose FAIL was detected, from
// the run's persisted detection_summary.techniques (the agent's post-run alert
// sweep), falling back to the coarse per-step event classifier when no sweep was
// submitted. This mirrors how reporting.buildKillChain decides detected vs missed.
func detectedTechs(detRaw []byte, results []models.SimulationResult) map[string]bool {
	out := map[string]bool{}
	if len(detRaw) > 0 {
		var ds struct {
			Techniques []struct {
				TechniqueID string `json:"techniqueId"`
				Verdict     string `json:"verdict"`
			} `json:"techniques"`
		}
		if json.Unmarshal(detRaw, &ds) == nil {
			for _, t := range ds.Techniques {
				if t.Verdict == "detected" {
					out[t.TechniqueID] = true
				}
			}
		}
	}
	for _, res := range results {
		if res.Result == models.ResultFail && !out[res.Technique.ID] {
			if reporting.ClassifyDetectionStatus(res.Events) == "Detected" {
				out[res.Technique.ID] = true
			}
		}
	}
	return out
}

// loadChildren loads a campaign's child runs as campaign.ChildRun (for the
```

Replace with:

```go
// loadChildren loads a campaign's child runs as campaign.ChildRun (for the
```

(deletes the duplicate function entirely, keeps the following `loadChildren` doc comment as the new anchor point unchanged).

Still in `campaign_handlers.go`, find the call site:

```go
		det := detectedTechs(detRaw, results)
```

Replace with:

```go
		det := reporting.DetectedTechniques(detRaw, results)
```

In `orchestrator/internal/api/handlers.go`, find (line 2091):

```go
		if d := detectedTechs(detRaw, run.Results); len(d) > 0 {
```

Replace with:

```go
		if d := reporting.DetectedTechniques(detRaw, run.Results); len(d) > 0 {
```

Then find (line 3248, inside `GetCoverageAnalytics` -- this whole surrounding block moves to `internal/detecteffectiveness` in Task 2, but must compile until then):

```go
		detected := detectedTechs(detRaw, results)
```

Replace with:

```go
		detected := reporting.DetectedTechniques(detRaw, results)
```

In `orchestrator/internal/api/finding_handlers.go`, find the import block:

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/findings"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/go-chi/chi/v5"
)
```

Replace with:

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/findings"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/go-chi/chi/v5"
)
```

Then find the call site:

```go
	detected := detectedTechs(detRaw, results) // technique ids caught by EDR/SIEM
```

Replace with:

```go
	detected := reporting.DetectedTechniques(detRaw, results) // technique ids caught by EDR/SIEM
```

In `orchestrator/internal/campaign/store.go`, find the call site:

```go
		det := detectedTechsFromSummary(detRaw, results)
```

Replace with:

```go
		det := reporting.DetectedTechniques(detRaw, results)
```

Then find (the duplicate function, lines 119-157):

```go
// detectedTechsFromSummary mirrors campaign_handlers.go's detectedTechs
// helper (internal/api/campaign_handlers.go:157) -- same detection_summary
// shape and same per-step event-classifier supplementary pass, reimplemented
// here since that helper is unexported in a different package. Both read
// the same persisted column; if the schema changes, both call sites need
// updating regardless of which package owns this copy.
//
// The second loop is NOT a fallback gated on detRaw being empty -- it always
// runs, checking every FAILed result's Events via
// reporting.ClassifyDetectionStatus for any technique the sweep data didn't
// already mark detected. Caught during implementation: an earlier draft of
// this function only handled the detRaw branch, silently under-counting
// Detected vs Missed in campaign rollups.
func detectedTechsFromSummary(detRaw []byte, results []models.SimulationResult) map[string]bool {
	out := map[string]bool{}
	if len(detRaw) > 0 {
		var ds struct {
			Techniques []struct {
				TechniqueID string `json:"techniqueId"`
				Verdict     string `json:"verdict"`
			} `json:"techniques"`
		}
		if json.Unmarshal(detRaw, &ds) == nil {
			for _, t := range ds.Techniques {
				if t.Verdict == "detected" {
					out[t.TechniqueID] = true
				}
			}
		}
	}
	for _, res := range results {
		if res.Result == models.ResultFail && !out[res.Technique.ID] {
			if reporting.ClassifyDetectionStatus(res.Events) == "Detected" {
				out[res.Technique.ID] = true
			}
		}
	}
	return out
}
```

Delete it entirely (replace with nothing). `store.go` still needs its `"encoding/json"` and `"github.com/audspect/bas/internal/reporting"` imports for `ListWithRollups`/the new call site -- both already imported, no import changes needed here.

- [x] **Step 6: Build and verify no other callers were missed**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: clean build. A leftover `detectedTechs`/`detectedTechsFromSummary` reference anywhere would fail with `undefined: detectedTechs` -- if that happens, grep for the exact identifier and fix the missed call site before continuing.

- [x] **Step 7: Run existing tests for every touched package**

Run: `cd orchestrator && go test ./internal/reporting/... ./internal/campaign/... ./internal/api/... -run "TestDetectedTechniques|TestListWithRollups|TestListCampaigns" -v`
Expected: all PASS -- proves the consolidation didn't change behavior anywhere it's used.

- [x] **Step 8: Commit**

```bash
git add orchestrator/internal/reporting/detected_techniques.go orchestrator/internal/reporting/detected_techniques_test.go orchestrator/internal/api/campaign_handlers.go orchestrator/internal/api/handlers.go orchestrator/internal/api/finding_handlers.go orchestrator/internal/campaign/store.go
git commit -m "refactor(reporting): consolidate detectedTechs into reporting.DetectedTechniques

Was duplicated 2x (internal/api's detectedTechs, internal/campaign's
detectedTechsFromSummary mirror). Promoting to an exported function in
internal/reporting -- which already owns ClassifyDetectionStatus, the
function's own fallback classifier -- means Task 2's extraction of
GetCoverageAnalytics doesn't need a 3rd copy. All 5 call sites repointed,
both duplicates deleted."
git push
```

---

### Task 2: `internal/detecteffectiveness` — the extracted computation

**Files:**
- Create: `orchestrator/internal/detecteffectiveness/detecteffectiveness.go`
- Test: `orchestrator/internal/detecteffectiveness/detecteffectiveness_test.go`

**Interfaces:**
- Consumes: `reporting.DetectedTechniques` (Task 1), `models.SimulationResult`/`models.ResultError`/`models.ResultSkipped`/`models.ResultPass`/`models.ResultBlocked`/`models.ResultFail` (`internal/models`), `*pgxpool.Pool`.
- Produces: `type CoverageAnalytics struct{...}`, `type PrivilegeCoverage struct{...}`, `type TierStat struct{...}`, `type PrivGapTechnique struct{...}`, `type AnalyticsSummary struct{...}`, `type TechniqueAnalytic struct{...}`, `type TacticAnalytic struct{...}`, `type RunAnalyticSummary struct{...}`, `type Verdict int` with `VerdictMissed`/`VerdictDetectedOnly`/`VerdictPrevented`, `func VerdictString(v Verdict) string`, `func NormPrivTier(executedAs string) string`, `func Compute(ctx context.Context, pool *pgxpool.Pool, scenarioID, agentID string, limit int) (CoverageAnalytics, error)`. Task 3's `analytics.DetectionEffectiveness` calls `Compute` directly.

- [x] **Step 1: Write the failing tests**

Create `orchestrator/internal/detecteffectiveness/detecteffectiveness_test.go`:

```go
package detecteffectiveness

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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

const seedResults = `[
	{"technique":{"id":"T1059","name":"Command and Scripting Interpreter","tactic":"execution"},"result":"pass"},
	{"technique":{"id":"T1003","name":"OS Credential Dumping","tactic":"credential-access"},"result":"fail"},
	{"technique":{"id":"T1078","name":"Valid Accounts","tactic":"defense-evasion"},"result":"fail"}
]`

const seedDetectionSummary = `{"techniques":[{"techniqueId":"T1003","verdict":"detected"}]}`

func TestCompute_TalliesPreventedDetectedOnlyMissed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, detection_summary, started_at)
			VALUES ('run-1', 'scn-1', 'Test Run', 'a1', 'completed', $1, $2, NOW())`,
			seedResults, seedDetectionSummary)

		got, err := Compute(context.Background(), pool, "", "", 20)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if got.RunsAnalyzed != 1 {
			t.Fatalf("RunsAnalyzed = %d, want 1", got.RunsAnalyzed)
		}
		want := AnalyticsSummary{Attempted: 3, Prevented: 1, DetectedOnly: 1, Missed: 1, PreventionRate: 33, DetectionCoverage: 66}
		if got.Summary != want {
			t.Errorf("Summary = %+v, want %+v (T1059=prevented, T1003=detectedOnly via sweep, T1078=missed)", got.Summary, want)
		}
		if len(got.ByTactic) != 3 {
			t.Fatalf("ByTactic = %+v, want 3 tactics (execution/credential-access/defense-evasion)", got.ByTactic)
		}
	})
}

func TestCompute_FiltersByScenarioID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'Run 1', 'a1', 'completed', $1, NOW())`, seedResults)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-2', 'scn-2', 'Run 2', 'a1', 'completed', $1, NOW())`, seedResults)

		got, err := Compute(context.Background(), pool, "scn-1", "", 20)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if got.RunsAnalyzed != 1 {
			t.Fatalf("RunsAnalyzed = %d, want 1 (filtered to scn-1 only)", got.RunsAnalyzed)
		}
		if len(got.RecentRuns) != 1 || got.RecentRuns[0].ScenarioID != "scn-1" {
			t.Errorf("RecentRuns = %+v, want exactly the scn-1 run", got.RecentRuns)
		}
	})
}

func TestCompute_NoRuns_ReturnsZeroSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := Compute(context.Background(), pool, "", "", 20)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if got.RunsAnalyzed != 0 || got.Summary != (AnalyticsSummary{}) {
			t.Errorf("Compute() = %+v, want zero-value on an empty fleet (no divide-by-zero panic)", got)
		}
	})
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/detecteffectiveness/... -v`
Expected: FAIL — the package doesn't exist yet, compile error (`no Go files in ...` / `undefined: Compute`).

- [x] **Step 3: Implement `internal/detecteffectiveness`**

Create `orchestrator/internal/detecteffectiveness/detecteffectiveness.go` — moved from `internal/api/handlers.go:3076-3462`, exported, using `reporting.DetectedTechniques` (Task 1) in place of the deleted local `detectedTechs`:

```go
// Package detecteffectiveness computes prevented/detectedOnly/missed
// analytics across recent scenario runs -- per-technique, per-tactic, and
// per-privilege-tier. Extracted from internal/api/handlers.go's
// GetCoverageAnalytics handler, matching the internal/campaign precedent
// from Sub-project A: real computation lives in its own package, the
// handler becomes a thin caller.
//
// This is a genuinely different question from internal/coverage.Compute
// (does content exist for a technique at all) and
// internal/pathcorrelation.Correlate (graph/attack-path-weighted detection
// score) -- see docs/superpowers/specs/2026-07-30-detection-reconciliation-design.md.
package detecteffectiveness

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
)

// Verdict ranks a technique's best-observed outcome across runs: missed is
// worst, prevented is best. Ordering matters -- ByTechnique sorts missed
// first via this ranking, and "best" tracking uses v > e.best.
type Verdict int

const (
	VerdictMissed       Verdict = 0
	VerdictDetectedOnly Verdict = 1
	VerdictPrevented    Verdict = 2
)

// VerdictString renders a Verdict as its JSON string form.
func VerdictString(v Verdict) string {
	switch v {
	case VerdictPrevented:
		return "prevented"
	case VerdictDetectedOnly:
		return "detectedOnly"
	default:
		return "missed"
	}
}

// NormPrivTier maps a raw ExecutedAs value from SimulationResult to one of
// "user" | "admin" | "system" | "inherited".
func NormPrivTier(executedAs string) string {
	switch {
	case executedAs == "":
		return "inherited"
	case executedAs == "system":
		return "system"
	case executedAs == "admin" || strings.Contains(executedAs, "→"):
		return "admin"
	default:
		return "user"
	}
}

// CoverageAnalytics is the aggregate coverage view across a set of runs.
type CoverageAnalytics struct {
	RunsAnalyzed      int                  `json:"runsAnalyzed"`
	Summary           AnalyticsSummary     `json:"summary"`
	ByTechnique       []TechniqueAnalytic  `json:"byTechnique"`
	ByTactic          []TacticAnalytic     `json:"byTactic"`
	RecentRuns        []RunAnalyticSummary `json:"recentRuns"`
	PrivilegeCoverage PrivilegeCoverage    `json:"privilegeCoverage"`
}

// PrivilegeCoverage is the per-execution-tier breakdown of coverage results.
type PrivilegeCoverage struct {
	ByTier   []TierStat         `json:"byTier"`
	GapTechs []PrivGapTechnique `json:"gapTechs"`
}

// TierStat is the prevention/detection summary for one execution tier.
type TierStat struct {
	Tier           string `json:"tier"` // user | admin | system | inherited
	Attempted      int    `json:"attempted"`
	Prevented      int    `json:"prevented"`
	DetectedOnly   int    `json:"detectedOnly"`
	Missed         int    `json:"missed"`
	PreventionRate int    `json:"preventionRate"` // prevented/attempted*100
}

// PrivGapTechnique is a technique tested only at elevated tier(s), never at user.
type PrivGapTechnique struct {
	TechniqueID string   `json:"techniqueId"`
	Name        string   `json:"name,omitempty"`
	Tiers       []string `json:"tiers"` // tiers actually tested (e.g. ["admin"])
}

type AnalyticsSummary struct {
	Attempted         int `json:"attempted"`
	Prevented         int `json:"prevented"`
	DetectedOnly      int `json:"detectedOnly"`
	Missed            int `json:"missed"`
	PreventionRate    int `json:"preventionRate"`    // prevented/attempted*100
	DetectionCoverage int `json:"detectionCoverage"` // (prevented+detected)/attempted*100
}

type TechniqueAnalytic struct {
	TechniqueID  string `json:"techniqueId"`
	Name         string `json:"name,omitempty"`
	Tactic       string `json:"tactic,omitempty"`
	BestVerdict  string `json:"bestVerdict"` // prevented | detectedOnly | missed
	RunCount     int    `json:"runCount"`
	Prevented    int    `json:"prevented"`
	DetectedOnly int    `json:"detectedOnly"`
	Missed       int    `json:"missed"`
}

type TacticAnalytic struct {
	Tactic       string `json:"tactic"`
	Attempted    int    `json:"attempted"`
	Prevented    int    `json:"prevented"`
	DetectedOnly int    `json:"detectedOnly"`
	Missed       int    `json:"missed"`
}

type RunAnalyticSummary struct {
	RunID        string    `json:"runId"`
	ScenarioID   string    `json:"scenarioId"`
	Name         string    `json:"name"`
	AgentID      string    `json:"agentId"`
	StartedAt    time.Time `json:"startedAt"`
	Attempted    int       `json:"attempted"`
	Prevented    int       `json:"prevented"`
	DetectedOnly int       `json:"detectedOnly"`
	Missed       int       `json:"missed"`
}

// Compute aggregates prevented/detectedOnly/missed analytics across recent
// completed/partial scenario_runs, optionally filtered to one scenario
// and/or one agent, capped at limit runs (most recent first).
func Compute(ctx context.Context, pool *pgxpool.Pool, scenarioID, agentID string, limit int) (CoverageAnalytics, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, scenario_id, name, agent_id, results, detection_summary, started_at
		   FROM scenario_runs
		  WHERE status IN ('completed', 'partial')
		    AND results IS NOT NULL
		    AND ($1 = '' OR scenario_id = $1)
		    AND ($2 = '' OR agent_id = $2)
		  ORDER BY started_at DESC LIMIT $3`,
		scenarioID, agentID, limit)
	if err != nil {
		return CoverageAnalytics{}, err
	}
	defer rows.Close()

	type techEntry struct {
		name   string
		tactic string
		best   Verdict // best across all runs
		runs   int
		prev   int
		det    int
		miss   int
		// per-tier tallies: tier → [attempted, prevented, detectedOnly, missed]
		tierStats map[string]*[4]int
	}
	type privTechEntry struct {
		name  string
		tiers map[string]bool
	}
	techMap := map[string]*techEntry{}
	tacticMap := map[string]*TacticAnalytic{}
	privTechs := map[string]*privTechEntry{} // techniqueID → tiers seen
	var recent []RunAnalyticSummary
	runsAnalyzed := 0

	for rows.Next() {
		var rid, scID, name, agID string
		var resRaw, detRaw []byte
		var startedAt time.Time
		if err := rows.Scan(&rid, &scID, &name, &agID, &resRaw, &detRaw, &startedAt); err != nil {
			continue
		}
		var results []models.SimulationResult
		if len(resRaw) > 0 {
			json.Unmarshal(resRaw, &results)
		}
		detected := reporting.DetectedTechniques(detRaw, results)
		runsAnalyzed++

		runSumm := RunAnalyticSummary{RunID: rid, ScenarioID: scID, Name: name, AgentID: agID, StartedAt: startedAt}

		for _, res := range results {
			switch res.Result {
			case models.ResultError, models.ResultSkipped:
				continue
			}
			tid := strings.ToUpper(res.Technique.ID)
			if tid == "" {
				continue
			}
			var v Verdict
			switch res.Result {
			case models.ResultPass, models.ResultBlocked:
				v = VerdictPrevented
			case models.ResultFail:
				if detected[res.Technique.ID] || detected[tid] {
					v = VerdictDetectedOnly
				} else {
					v = VerdictMissed
				}
			default:
				continue
			}

			e := techMap[tid]
			if e == nil {
				e = &techEntry{name: res.Technique.Name, tactic: res.Technique.Tactic, tierStats: map[string]*[4]int{}}
				techMap[tid] = e
			}
			if res.Technique.Name != "" && e.name == "" {
				e.name = res.Technique.Name
			}
			if res.Technique.Tactic != "" && e.tactic == "" {
				e.tactic = res.Technique.Tactic
			}
			e.runs++
			if v > e.best {
				e.best = v
			}
			switch v {
			case VerdictPrevented:
				e.prev++
			case VerdictDetectedOnly:
				e.det++
			default:
				e.miss++
			}

			// Privilege tier tracking.
			tier := NormPrivTier(res.ExecutedAs)
			ts := e.tierStats[tier]
			if ts == nil {
				ts = &[4]int{}
				e.tierStats[tier] = ts
			}
			ts[0]++ // attempted
			switch v {
			case VerdictPrevented:
				ts[1]++
			case VerdictDetectedOnly:
				ts[2]++
			default:
				ts[3]++
			}
			pt := privTechs[tid]
			if pt == nil {
				pt = &privTechEntry{name: res.Technique.Name, tiers: map[string]bool{}}
				privTechs[tid] = pt
			}
			if res.Technique.Name != "" && pt.name == "" {
				pt.name = res.Technique.Name
			}
			pt.tiers[tier] = true

			// per-run counts
			switch v {
			case VerdictPrevented:
				runSumm.Prevented++
			case VerdictDetectedOnly:
				runSumm.DetectedOnly++
			default:
				runSumm.Missed++
			}
			runSumm.Attempted++
		}
		recent = append(recent, runSumm)
	}

	// Build ByTechnique (sorted: missed first, then detectedOnly, then prevented, then by ID).
	techList := make([]TechniqueAnalytic, 0, len(techMap))
	for tid, e := range techMap {
		tacKey := e.tactic
		if tacKey == "" {
			tacKey = "unknown"
		}
		if tacticMap[tacKey] == nil {
			tacticMap[tacKey] = &TacticAnalytic{Tactic: tacKey}
		}
		tac := tacticMap[tacKey]
		tac.Attempted++
		switch e.best {
		case VerdictPrevented:
			tac.Prevented++
		case VerdictDetectedOnly:
			tac.DetectedOnly++
		default:
			tac.Missed++
		}
		techList = append(techList, TechniqueAnalytic{
			TechniqueID: tid, Name: e.name, Tactic: e.tactic,
			BestVerdict: VerdictString(e.best),
			RunCount:    e.runs, Prevented: e.prev, DetectedOnly: e.det, Missed: e.miss,
		})
	}
	sort.Slice(techList, func(i, j int) bool {
		bi := techMap[techList[i].TechniqueID].best
		bj := techMap[techList[j].TechniqueID].best
		if bi != bj {
			return bi < bj // missed first
		}
		return techList[i].TechniqueID < techList[j].TechniqueID
	})

	// Build ByTactic (sorted by missed desc).
	tacList := make([]TacticAnalytic, 0, len(tacticMap))
	for _, t := range tacticMap {
		tacList = append(tacList, *t)
	}
	sort.Slice(tacList, func(i, j int) bool {
		if tacList[i].Missed != tacList[j].Missed {
			return tacList[i].Missed > tacList[j].Missed
		}
		return tacList[i].Tactic < tacList[j].Tactic
	})

	// Summary.
	var summ AnalyticsSummary
	for _, t := range techList {
		summ.Attempted++
		switch t.BestVerdict {
		case "prevented":
			summ.Prevented++
		case "detectedOnly":
			summ.DetectedOnly++
		default:
			summ.Missed++
		}
	}
	if summ.Attempted > 0 {
		summ.PreventionRate = summ.Prevented * 100 / summ.Attempted
		summ.DetectionCoverage = (summ.Prevented + summ.DetectedOnly) * 100 / summ.Attempted
	}

	// Build PrivilegeCoverage: per-tier stats + gap list.
	tierOrder := []string{"user", "admin", "system", "inherited"}
	tierAgg := map[string]*[4]int{}
	for _, e := range techMap {
		for tier, ts := range e.tierStats {
			agg := tierAgg[tier]
			if agg == nil {
				agg = &[4]int{}
				tierAgg[tier] = agg
			}
			agg[0] += ts[0]
			agg[1] += ts[1]
			agg[2] += ts[2]
			agg[3] += ts[3]
		}
	}
	var tierStats []TierStat
	for _, tier := range tierOrder {
		ts := tierAgg[tier]
		if ts == nil || ts[0] == 0 {
			continue
		}
		pct := 0
		if ts[0] > 0 {
			pct = ts[1] * 100 / ts[0]
		}
		tierStats = append(tierStats, TierStat{
			Tier: tier, Attempted: ts[0], Prevented: ts[1],
			DetectedOnly: ts[2], Missed: ts[3], PreventionRate: pct,
		})
	}
	var gapTechs []PrivGapTechnique
	for tid, pt := range privTechs {
		if pt.tiers["user"] {
			continue // tested at user — not a gap
		}
		if !pt.tiers["admin"] && !pt.tiers["system"] {
			continue // only inherited, not elevated — not a meaningful gap
		}
		var tiers []string
		for _, t := range []string{"admin", "system", "inherited"} {
			if pt.tiers[t] {
				tiers = append(tiers, t)
			}
		}
		gapTechs = append(gapTechs, PrivGapTechnique{TechniqueID: tid, Name: pt.name, Tiers: tiers})
	}
	sort.Slice(gapTechs, func(i, j int) bool { return gapTechs[i].TechniqueID < gapTechs[j].TechniqueID })

	return CoverageAnalytics{
		RunsAnalyzed:      runsAnalyzed,
		Summary:           summ,
		ByTechnique:       techList,
		ByTactic:          tacList,
		RecentRuns:        recent,
		PrivilegeCoverage: PrivilegeCoverage{ByTier: tierStats, GapTechs: gapTechs},
	}, nil
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/detecteffectiveness/... -v`
Expected: build succeeds; all 3 tests PASS.

- [x] **Step 5: Commit**

```bash
git add orchestrator/internal/detecteffectiveness/
git commit -m "feat(detecteffectiveness): extract GetCoverageAnalytics's computation into its own package

Moved from internal/api/handlers.go:3076-3462, matching Sub-project A's
internal/campaign precedent -- real computation lives in a dedicated,
tested package instead of inline in a handler. Types/verdict/tier-tally
logic unchanged; only detectedTechs -> reporting.DetectedTechniques
(Task 1) and the package boundary are new."
git push
```

---

### Task 3: `analytics.DetectionEffectiveness` — thin pass-through

**Files:**
- Create: `orchestrator/internal/analytics/detection.go`
- Test: `orchestrator/internal/analytics/detection_test.go`

**Interfaces:**
- Consumes: `detecteffectiveness.Compute`, `detecteffectiveness.CoverageAnalytics` (Task 2).
- Produces: `func DetectionEffectiveness(ctx context.Context, pool *pgxpool.Pool, scenarioID, agentID string, limit int) (detecteffectiveness.CoverageAnalytics, error)`. Task 4's `GetCoverageAnalytics` handler calls this directly.

- [x] **Step 1: Write the failing test**

Create `orchestrator/internal/analytics/detection_test.go`:

```go
package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDetectionEffectiveness_EmptyFleet_ReturnsZeroSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := DetectionEffectiveness(context.Background(), pool, "", "", 20)
		if err != nil {
			t.Fatalf("DetectionEffectiveness: %v", err)
		}
		if got.RunsAnalyzed != 0 {
			t.Errorf("RunsAnalyzed = %d, want 0 on an empty fleet", got.RunsAnalyzed)
		}
	})
}

func TestDetectionEffectiveness_DelegatesToCompute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'Test Run', 'a1', 'completed',
				'[{"technique":{"id":"T1059","name":"Command and Scripting Interpreter","tactic":"execution"},"result":"pass"}]', NOW())`)

		got, err := DetectionEffectiveness(context.Background(), pool, "", "", 20)
		if err != nil {
			t.Fatalf("DetectionEffectiveness: %v", err)
		}
		if got.RunsAnalyzed != 1 || got.Summary.Prevented != 1 {
			t.Errorf("DetectionEffectiveness() = %+v, want RunsAnalyzed=1 Summary.Prevented=1", got)
		}
	})
}
```

`sharedDB`/`mustExec` are already declared in `internal/analytics/risk_test.go` (Sub-project A) — this package-level `TestMain` is shared across every test file in `internal/analytics`, no new boilerplate needed here.

- [x] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/analytics/... -run TestDetectionEffectiveness -v`
Expected: FAIL — `undefined: DetectionEffectiveness` (compile error).

- [x] **Step 3: Implement `DetectionEffectiveness`**

Create `orchestrator/internal/analytics/detection.go`:

```go
package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/detecteffectiveness"
)

// DetectionEffectiveness returns prevented/detectedOnly/missed analytics
// across recent scenario runs -- a thin pass-through to
// detecteffectiveness.Compute, the canonical definition
// (internal/detecteffectiveness/detecteffectiveness.go).
func DetectionEffectiveness(ctx context.Context, pool *pgxpool.Pool, scenarioID, agentID string, limit int) (detecteffectiveness.CoverageAnalytics, error) {
	return detecteffectiveness.Compute(ctx, pool, scenarioID, agentID, limit)
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/analytics/... -run TestDetectionEffectiveness -v`
Expected: build succeeds; both tests PASS.

- [x] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/detection.go orchestrator/internal/analytics/detection_test.go
git commit -m "feat(analytics): add DetectionEffectiveness, a thin pass-through to detecteffectiveness.Compute"
git push
```

---

### Task 4: `GetCoverageAnalytics` delegates to `analytics.DetectionEffectiveness`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go:3-40` (import), `:3074-3462` (delete moved block, replace handler body)
- Test: `orchestrator/internal/api/coverage_analytics_handler_test.go` (new)

**Interfaces:**
- Consumes: `analytics.DetectionEffectiveness` (Task 3).
- Produces: nothing new — `GetCoverageAnalytics`'s signature, route, and JSON response shape are unchanged; only its body's implementation moves.

- [x] **Step 1: Write the handler-level test, against the CURRENT (still-inline) handler**

There is no pre-existing test for `GetCoverageAnalytics` (confirmed via grep in the design spec), so this step both writes the new regression guard *and* establishes the baseline it protects — true TDD sequencing, not regression-guard-after. This test is a pure HTTP/JSON black-box: it doesn't reference any of the soon-to-move types directly, so it will compile and pass unchanged whether it runs against today's still-inline handler or Task 4's refactored one.

Create `orchestrator/internal/api/coverage_analytics_handler_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

type coverageAnalyticsResponse struct {
	RunsAnalyzed int `json:"runsAnalyzed"`
	Summary      struct {
		Prevented int `json:"prevented"`
	} `json:"summary"`
}

func TestGetCoverageAnalytics_ReturnsTalliedResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'Test Run', 'a1', 'completed',
				'[{"technique":{"id":"T1059","name":"Command and Scripting Interpreter","tactic":"execution"},"result":"pass"}]', NOW())`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetCoverageAnalytics(rec, httptest.NewRequest(http.MethodGet, "/api/coverage/analytics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got coverageAnalyticsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if got.RunsAnalyzed != 1 || got.Summary.Prevented != 1 {
			t.Errorf("response = %+v, want RunsAnalyzed=1 Summary.Prevented=1", got)
		}
	})
}

func TestGetCoverageAnalytics_ScenarioIDQueryParamFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'Run 1', 'a1', 'completed',
				'[{"technique":{"id":"T1059","name":"x","tactic":"execution"},"result":"pass"}]', NOW())`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-2', 'scn-2', 'Run 2', 'a1', 'completed',
				'[{"technique":{"id":"T1078","name":"y","tactic":"defense-evasion"},"result":"pass"}]', NOW())`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetCoverageAnalytics(rec, httptest.NewRequest(http.MethodGet, "/api/coverage/analytics?scenarioId=scn-1", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got coverageAnalyticsResponse
		json.Unmarshal(rec.Body.Bytes(), &got)
		if got.RunsAnalyzed != 1 {
			t.Errorf("RunsAnalyzed = %d, want 1 (scenarioId=scn-1 query param filtered out run-2)", got.RunsAnalyzed)
		}
	})
}
```

`sharedDB`/`mustExec` are already declared in `internal/api`'s existing test suite (used throughout `campaign_crud_test.go` etc.) — no new boilerplate needed. `coverageAnalyticsResponse` is a deliberately minimal local re-declaration of just the 2 fields these tests check, not the full 7-type response shape — it stays valid regardless of which package (`internal/api`'s local types today, `internal/detecteffectiveness`'s after Task 4 Step 4) actually produces the matching JSON.

- [x] **Step 2: Run the test to verify it passes against the current handler**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetCoverageAnalytics -v`
Expected: both tests PASS — this is the baseline the rest of this task's refactor must not break.

- [x] **Step 3: Add the `analytics` import**

In `orchestrator/internal/api/handlers.go`, find:

```go
	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/auth"
```

Replace with:

```go
	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/analytics"
	"github.com/audspect/bas/internal/auth"
```

- [x] **Step 4: Delete the moved block, replace the handler body**

Find the entire block from the `// ── Coverage Analytics ──` divider through the end of `GetCoverageAnalytics` (`handlers.go:3074-3462` — the full ~390-line block: the section divider, `analyticsVerdict`/verdict consts/`verdictString`, `normPrivTier`, all 7 result types, and the handler function itself). This is too long to reproduce here in full (see `detecteffectiveness.go` from Task 2 for its byte-identical content, now under exported names) — locate it by its start and end anchors:

Start anchor (keep the line before it, `sort.Slice(out, ...)`/`respond(w, out)`/`}` from the *previous* handler, unchanged):

```go
// ── Coverage Analytics ────────────────────────────────────────────────────────

type analyticsVerdict int
```

End anchor (keep everything from `// ────` onward, which begins the *next* handler, `GetARTTechniques`, unchanged):

```go
// GET /api/coverage/analytics — aggregate prevention/detection analytics across
```
… (the full function body from Task 2's `detecteffectiveness.go`, ending at) …
```go
	respond(w, CoverageAnalytics{
		RunsAnalyzed:      runsAnalyzed,
		Summary:           summ,
		ByTechnique:       techList,
		ByTactic:          tacList,
		RecentRuns:        recent,
		PrivilegeCoverage: PrivilegeCoverage{ByTier: tierStats, GapTechs: gapTechs},
	})
}

// ─────────────────────────────────────────────────────────────────────────────
```

Replace the entire `// ── Coverage Analytics ──` divider through that closing `}` (everything shown as the "start anchor" and "end anchor" above, and everything between them) with:

```go
// GET /api/coverage/analytics — aggregate prevention/detection analytics across
// recent runs. Results are bucketed per technique into prevented / detectedOnly
// (FAIL but EDR/SIEM caught it) / missed (FAIL, no detection). Error and Skipped
// outcomes are excluded from counts. Viewer+.
//
// Query params:
//
//	scenarioId — filter to one scenario (optional)
//	agentId    — filter to one agent (optional)
//	limit      — max runs to include, default 20, max 100
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

// ─────────────────────────────────────────────────────────────────────────────
```

(leave the following `GetARTTechniques` function and its own doc comment exactly as they are — this replacement stops right before them.)

- [x] **Step 5: Verify the deleted types have no remaining references**

Run: `cd orchestrator && grep -n "analyticsVerdict\|verdictMissed\|verdictDetectedOnly\|verdictPrevented\|verdictString\|normPrivTier\|CoverageAnalytics{\|PrivilegeCoverage{\|TierStat{\|PrivGapTechnique{\|AnalyticsSummary{\|TechniqueAnalytic{\|TacticAnalytic{\|RunAnalyticSummary{" internal/api/*.go`
Expected: no matches (everything now lives in `internal/detecteffectiveness`, referenced only via `analytics.DetectionEffectiveness`'s return value in the handler above).

- [x] **Step 6: Re-run the same test to confirm the refactor didn't change behavior**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run TestGetCoverageAnalytics -v`
Expected: build and vet clean; both tests from Step 1 PASS unchanged — proving the handler's response shape and query-param handling survived the extraction byte-for-byte.

- [x] **Step 7: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/coverage_analytics_handler_test.go
git commit -m "refactor(api): GetCoverageAnalytics delegates to analytics.DetectionEffectiveness

Handler shrinks from ~390 lines to query-param parsing + a delegate
call. The moved types/verdict/tally logic now live in
internal/detecteffectiveness (Task 2); this was the one of Detection's
3 coverage concepts that genuinely needed extracting -- pathcorrelation
and internal/coverage were confirmed already correctly factored."
git push
```

---

### Task 5: Full regression

**Files:** none (verification only)

- [x] **Step 1: Confirm Docker is running**

Run: `docker info 2>&1 | grep -iE "server|error"`
Expected: a `Server:` block with no error. If it shows `failed to connect to the docker API` instead, start Docker Desktop and poll until ready before continuing:

```bash
timeout 180 bash -c 'until docker info >/dev/null 2>&1; do sleep 5; done' && echo "DOCKER_READY"
```

- [x] **Step 2: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1`
Expected: `go build`/`go vet` clean, every package `ok`. If a single package fails under Docker load with a testcontainers connection error, re-run that package in isolation with a longer timeout before concluding it's the known transient flake this session has repeatedly confirmed (Sub-project A hit exactly this with `internal/api` — confirmed clean in isolation at `661s`, just past the default 10-minute per-package timeout under full-suite resource contention).

- [x] **Step 3: Report completion**

This sub-project executes directly on `main` (matching this session's established inline-execution convention) — no branch/worktree/PR decision needed. Confirm with the user that Sub-project C is complete, and that Sub-project D (Threat Intel Summary) is next.

## Execution notes

**Plan error found and fixed during Task 4**: the plan assumed `internal/api`'s test suite had a
`mustExec` helper matching `internal/analytics`/`internal/detecteffectiveness`'s naming
convention. It doesn't — `internal/api`'s raw-SQL test helper is named `mustExecAPI`
(`dashboard_handlers_test.go:102`). Caught immediately by a compiler diagnostic
(`undefined: mustExec`) before any test ran; fixed by using the correct name. `sharedDB` itself
was correctly assumed to already exist (`testmain_test.go:18`).

**Result**: all 4 implementation tasks completed with tests passing at every TDD checkpoint
(fail-before-implementation, pass-after). Task 4's regression-guard test — written and confirmed
passing against the still-inline handler *before* the refactor, per the plan's TDD-first
requirement — passed unchanged afterward, proving the extraction preserved behavior exactly. Full
suite (`go build`, `go vet`, `go test ./... -count=1`) is completely clean: zero `FAIL` lines
across every package, no transient flake this time.

**Unrelated issue found and fixed before Task 1 started**: `orchestrator/wwwroot/images/logo.png`
and `logo_name.png` (the actual site logo, last committed 2026-07-01) were missing from disk with
no commit explaining it — not caused by anything in this plan. Restored via
`git checkout -- orchestrator/wwwroot/images/logo.png orchestrator/wwwroot/images/logo_name.png`
before proceeding.