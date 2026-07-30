# Unified Analytics Layer, Sub-project A: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/analytics`, a thin orchestration facade over 4 already-clean-or-near-clean domains (Risk, Compliance, Campaigns, Exposure), and refactor the two places that currently duplicate this logic (`dashboard.Compute()`, `campaign_handlers.go`'s `ListCampaigns`) to consume it instead of owning it — so each metric has exactly one definition, verified by keeping every existing test green.

**Architecture:** Each category's actual computation stays in its existing domain package (`internal/db`, `internal/campaign`, `internal/exposure`, `internal/predict`) — `internal/analytics` only orchestrates and, for Risk, is the new sole owner of logic that today lives duplicated nowhere else (so it moves there outright). One new small extraction (`campaign.ListWithRollups`) makes campaign fleet-rollup logic callable outside `internal/api` for the first time. No frontend changes; no new database objects.

**Tech Stack:** Go, Postgres (pgx), no new dependencies.

## Global Constraints

- `dashboard.Compute()`'s output must be byte-identical before and after its refactor for the same DB state — verified by keeping its 3 existing tests in `internal/dashboard/snapshot_test.go` passing unchanged, not by writing new tests that could hide a behavior drift.
- No new database tables, columns, or migrations.
- No changes to `GET /api/campaigns/{id}/summary` (`CampaignSummary` handler) or its richer per-agent `childRunOut` response — only the fleet-list endpoint (`GET /api/campaigns`, `ListCampaigns`) gets refactored.
- Exposure's `AssetSummary` already carries both `ExposureScore` and `CriticalityRisk` per asset (confirmed in `internal/exposure/types.go:124,131`, computed inside `exposure.Build` at `build.go:175-183`) — no separate "criticality" accessor gets built; `AssetExposureSummary` exposes the existing `[]exposure.AssetSummary` as-is.
- Detection, Threat Intel, and Endpoint Posture are explicitly out of scope — later sub-projects. `FleetExposure.Correlation()` (Task 5) only re-exposes a value already computed as a prerequisite for `exposure.Build`; it does not define Detection's canonical analytics API.

---

### Task 1: `analytics.FleetRisk` — extract the fleet risk-score query

**Files:**
- Create: `orchestrator/internal/analytics/risk.go`
- Test: `orchestrator/internal/analytics/risk_test.go`

**Interfaces:**
- Produces: `type RiskResult struct { FleetAvgScore int }`, `func FleetRisk(ctx context.Context, pool *pgxpool.Pool) (RiskResult, error)` — consumed by Task 6 (`dashboard.Compute()`'s refactor).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/analytics/risk_test.go`:

```go
package analytics

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

func TestFleetRisk_AveragesRecentCompletedRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-1', 'a1', 'completed', '{"riskScore": 42}'::jsonb, NOW())`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-2', 'a1', 'completed', '{"riskScore": 58}'::jsonb, NOW())`)
		// Old run, outside the 30-day window -- must not affect the average.
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-3', 'a1', 'completed', '{"riskScore": 0}'::jsonb, NOW() - INTERVAL '90 days')`)

		got, err := FleetRisk(context.Background(), pool)
		if err != nil {
			t.Fatalf("FleetRisk: %v", err)
		}
		if got.FleetAvgScore != 50 {
			t.Errorf("FleetAvgScore = %d, want 50 (avg of 42 and 58, excluding the 90-day-old run)", got.FleetAvgScore)
		}
	})
}

func TestFleetRisk_NoCompletedRuns_ReturnsZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := FleetRisk(context.Background(), pool)
		if err != nil {
			t.Fatalf("FleetRisk: %v", err)
		}
		if got.FleetAvgScore != 0 {
			t.Errorf("FleetAvgScore = %d, want 0 (no completed runs)", got.FleetAvgScore)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/analytics/... 2>&1`
Expected: FAIL — the package doesn't exist yet.

- [ ] **Step 3: Implement `FleetRisk`**

Create `orchestrator/internal/analytics/risk.go`:

```go
// Package analytics is the canonical facade every dashboard view calls for
// fleet-wide metrics -- Risk, Compliance, Campaigns, Exposure (this
// sub-project), Detection/Threat Intel/Endpoint Posture (later
// sub-projects). Each category's actual computation stays in its own
// existing domain package; this package orchestrates, it does not
// reimplement. See docs/superpowers/specs/2026-07-30-unified-analytics-layer-phase-a-design.md.
package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RiskResult is the fleet-wide risk score.
type RiskResult struct {
	FleetAvgScore int `json:"fleetAvgScore"`
}

// FleetRisk returns the fleet-wide average risk score across completed runs
// in the last 30 days -- the sole definition (moved verbatim from
// internal/dashboard's former private avgRiskScore; that function is
// deleted in Task 6, not duplicated).
func FleetRisk(ctx context.Context, pool *pgxpool.Pool) (RiskResult, error) {
	var avg int
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(ROUND(AVG((score->>'riskScore')::numeric)), 0)::int
		FROM scenario_runs
		WHERE completed_at IS NOT NULL
		  AND completed_at > NOW() - INTERVAL '30 days'
		  AND score IS NOT NULL`).Scan(&avg)
	return RiskResult{FleetAvgScore: avg}, err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/analytics/... -run TestFleetRisk -v`
Expected: build succeeds; both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/risk.go orchestrator/internal/analytics/risk_test.go
git commit -m "feat(analytics): add FleetRisk, the sole fleet risk-score definition"
git push
```

---

### Task 2: `analytics.Compliance` — thin pass-through

**Files:**
- Create: `orchestrator/internal/analytics/compliance.go`
- Test: `orchestrator/internal/analytics/compliance_test.go`

**Interfaces:**
- Consumes: `db.GetFleetComplianceScores(ctx, pool) ([]db.ComplianceSnapshot, error)` and `db.GetComplianceScores(ctx, pool, agentID string) ([]db.ComplianceSnapshot, error)` (existing, `internal/db/postgres.go:1192,1221`); `db.UpsertComplianceSnapshot(ctx, pool, s db.ComplianceSnapshot) error` (existing, used only by the test to seed data).
- Produces: `func Compliance(ctx context.Context, pool *pgxpool.Pool, agentID string) ([]db.ComplianceSnapshot, error)` — no other task consumes this directly (Sub-project B will), but it completes the category.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/analytics/compliance_test.go`:

```go
package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func TestCompliance_EmptyAgentID_ReturnsFleetScores(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.UpsertComplianceSnapshot(ctx, pool, db.ComplianceSnapshot{
			AgentID: "agent-1", FrameworkID: "ISO_27001_2022", RunCount: 3,
			CompliancePct: 75.0, CoveragePct: 80.0, TotalControls: 10,
		}); err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}

		got, err := Compliance(ctx, pool, "")
		if err != nil {
			t.Fatalf("Compliance: %v", err)
		}
		if len(got) != 1 || got[0].FrameworkID != "ISO_27001_2022" {
			t.Fatalf("Compliance(\"\") = %+v, want 1 row for ISO_27001_2022", got)
		}
	})
}

func TestCompliance_WithAgentID_ReturnsThatAgentsScores(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.UpsertComplianceSnapshot(ctx, pool, db.ComplianceSnapshot{
			AgentID: "agent-compliance-test", FrameworkID: "PCI_DSS_V4", RunCount: 2,
			CompliancePct: 60.0, CoveragePct: 70.0, TotalControls: 40,
		}); err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}

		got, err := Compliance(ctx, pool, "agent-compliance-test")
		if err != nil {
			t.Fatalf("Compliance: %v", err)
		}
		if len(got) != 1 || got[0].AgentID != "agent-compliance-test" {
			t.Fatalf("Compliance(agent-compliance-test) = %+v, want 1 row for that agent", got)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/analytics/... 2>&1`
Expected: FAIL — `undefined: Compliance`.

- [ ] **Step 3: Implement `Compliance`**

Create `orchestrator/internal/analytics/compliance.go`:

```go
package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// Compliance returns the latest persisted compliance_snapshots rows --
// fleet-wide (the lowest-compliance agent's row per framework, matching
// db.GetFleetComplianceScores' own ORDER BY compliance_pct ASC) when
// agentID is "", or that agent's own per-framework rows otherwise. Thin
// pass-through -- both underlying queries already exist and are already
// what GetComplianceDashboardScores (internal/api/handlers.go:4164) calls
// today; this gives that same logic a name outside internal/api.
func Compliance(ctx context.Context, pool *pgxpool.Pool, agentID string) ([]db.ComplianceSnapshot, error) {
	if agentID != "" {
		return db.GetComplianceScores(ctx, pool, agentID)
	}
	return db.GetFleetComplianceScores(ctx, pool)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/analytics/... -run TestCompliance -v`
Expected: build succeeds; both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/compliance.go orchestrator/internal/analytics/compliance_test.go
git commit -m "feat(analytics): add Compliance, a thin pass-through to the already-unified compliance snapshot reader"
git push
```

---

### Task 3: `campaign.ListWithRollups` — the one real extraction

**Files:**
- Create: `orchestrator/internal/campaign/store.go`
- Test: `orchestrator/internal/campaign/store_test.go`

**Interfaces:**
- Consumes: `campaign.Aggregate(runs []ChildRun, skips []Skip) Summary` and `campaign.DeriveStatus(runs []ChildRun, skips int, stopped bool) string` (existing, `internal/campaign/campaign.go:90,39`); `campaign.ChildRun`, `campaign.Skip` (existing, `campaign.go:10-25`).
- Produces: `type Rollup struct { ID, Name, ScenarioID, ScenarioName, Mode, CreatedBy string; StartedAt time.Time; Summary Summary }`, `func ListWithRollups(ctx context.Context, pool *pgxpool.Pool) ([]Rollup, error)` — consumed by Task 4 (`analytics.Campaigns`) and Task 7 (`ListCampaigns` handler refactor).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/campaign/store_test.go`:

```go
package campaign

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

func TestListWithRollups_ComputesLiveSummaryPerCampaign(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, created_by, targets, skips, tags, started_at)
			VALUES ('camp-1', 'Test Campaign', 'scn-1', 'Test Scenario', 'posture', 'tester', '["a1"]', '[]', '[]', NOW())`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, agent_id, campaign_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'a1', 'camp-1', 'completed', '[]', NOW())`)

		got, err := ListWithRollups(ctx, pool)
		if err != nil {
			t.Fatalf("ListWithRollups: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("ListWithRollups() = %+v, want 1 campaign", got)
		}
		r := got[0]
		if r.ID != "camp-1" || r.Name != "Test Campaign" {
			t.Errorf("Rollup = %+v, want ID=camp-1 Name=Test Campaign", r)
		}
		if r.Summary.Status != "completed" {
			t.Errorf("Summary.Status = %q, want completed (matches DeriveStatus for one completed child, no skips)", r.Summary.Status)
		}
		if r.Summary.Dispatched != 1 {
			t.Errorf("Summary.Dispatched = %d, want 1", r.Summary.Dispatched)
		}
	})
}

func TestListWithRollups_EmptyFleet_ReturnsEmptySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := ListWithRollups(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListWithRollups: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("ListWithRollups() = %+v, want empty", got)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/campaign/... 2>&1`
Expected: FAIL — `undefined: ListWithRollups`.

- [ ] **Step 3: Implement `ListWithRollups`**

Create `orchestrator/internal/campaign/store.go`:

```go
package campaign

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

// Rollup is one campaign with its live-computed Summary -- the analytics
// layer's canonical Campaigns result.
type Rollup struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ScenarioID   string    `json:"scenarioId"`
	ScenarioName string    `json:"scenarioName"`
	Mode         string    `json:"mode"`
	CreatedBy    string    `json:"createdBy"`
	StartedAt    time.Time `json:"startedAt"`
	Summary      Summary   `json:"summary"`
}

// ListWithRollups queries every campaign and its child runs, computing each
// one's live Summary via the existing Aggregate/DeriveStatus. A fresh,
// focused implementation for the fleet-list need -- deliberately not a
// refactor of internal/api/campaign_handlers.go's loadCampaign/loadChildren,
// which also builds the richer per-agent childRunOut breakdown the single-
// campaign detail endpoint needs and this list endpoint does not. See
// design spec Non-Goals.
func ListWithRollups(ctx context.Context, pool *pgxpool.Pool) ([]Rollup, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, name, scenario_id, scenario_name, mode, created_by, skips, started_at, stopped_at
		  FROM campaigns ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	type campRow struct {
		id, name, scenarioID, scenarioName, mode, createdBy string
		skipsRaw                                            []byte
		startedAt                                           time.Time
		stoppedAt                                           *time.Time
	}
	var camps []campRow
	for rows.Next() {
		var c campRow
		if err := rows.Scan(&c.id, &c.name, &c.scenarioID, &c.scenarioName, &c.mode,
			&c.createdBy, &c.skipsRaw, &c.startedAt, &c.stoppedAt); err != nil {
			rows.Close()
			return nil, err
		}
		camps = append(camps, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Rollup, 0, len(camps))
	for _, c := range camps {
		var skips []Skip
		_ = json.Unmarshal(c.skipsRaw, &skips)

		children, err := loadChildRunsForRollup(ctx, pool, c.id)
		if err != nil {
			return nil, err
		}

		s := Aggregate(children, skips)
		s.Status = DeriveStatus(children, len(skips), c.stoppedAt != nil)

		out = append(out, Rollup{
			ID: c.id, Name: c.name, ScenarioID: c.scenarioID, ScenarioName: c.scenarioName,
			Mode: c.mode, CreatedBy: c.createdBy, StartedAt: c.startedAt, Summary: s,
		})
	}
	return out, nil
}

// loadChildRunsForRollup loads just enough per-child-run data to compute a
// Summary (status, results, score, detected techniques) -- the ChildRun
// shape Aggregate/DeriveStatus need, nothing more (unlike
// campaign_handlers.go's loadChildren, which also builds the richer
// childRunOut for the detail view).
func loadChildRunsForRollup(ctx context.Context, pool *pgxpool.Pool, campaignID string) ([]ChildRun, error) {
	rows, err := pool.Query(ctx,
		`SELECT status, results, score, detection_summary
		   FROM scenario_runs WHERE campaign_id = $1 ORDER BY started_at`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ChildRun
	for rows.Next() {
		var status string
		var resultsRaw, scoreRaw, detRaw []byte
		if err := rows.Scan(&status, &resultsRaw, &scoreRaw, &detRaw); err != nil {
			return nil, err
		}
		var results []models.SimulationResult
		_ = json.Unmarshal(resultsRaw, &results)
		var score *models.Score
		if len(scoreRaw) > 0 {
			var sc models.Score
			if json.Unmarshal(scoreRaw, &sc) == nil {
				score = &sc
			}
		}
		det := detectedTechsFromSummary(detRaw, results)
		out = append(out, ChildRun{Status: status, Results: results, Score: score, DetectedTechs: det})
	}
	return out, rows.Err()
}

// detectedTechsFromSummary mirrors campaign_handlers.go's detectedTechs
// helper (internal/api/campaign_handlers.go:157) -- same detection_summary
// shape, reimplemented here since that helper is unexported in a different
// package. Both read the same persisted column; if the schema changes,
// both call sites need updating regardless of which package owns this copy.
func detectedTechsFromSummary(detRaw []byte, results []models.SimulationResult) map[string]bool {
	out := map[string]bool{}
	if len(detRaw) == 0 {
		return out
	}
	var ds struct {
		Techniques []struct {
			TechniqueID string `json:"techniqueId"`
			Verdict     string `json:"verdict"`
		} `json:"techniques"`
	}
	if json.Unmarshal(detRaw, &ds) != nil {
		return out
	}
	for _, t := range ds.Techniques {
		if t.Verdict == "detected" {
			out[t.TechniqueID] = true
		}
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/campaign/... -run TestListWithRollups -v`
Expected: build succeeds; both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/campaign/store.go orchestrator/internal/campaign/store_test.go
git commit -m "feat(campaign): add ListWithRollups, making fleet campaign rollups callable outside internal/api"
git push
```

---

### Task 4: `analytics.Campaigns` — thin pass-through

**Files:**
- Create: `orchestrator/internal/analytics/campaigns.go`
- Test: `orchestrator/internal/analytics/campaigns_test.go`

**Interfaces:**
- Consumes: `campaign.ListWithRollups(ctx, pool) ([]campaign.Rollup, error)` (Task 3).
- Produces: `func Campaigns(ctx context.Context, pool *pgxpool.Pool) ([]campaign.Rollup, error)`.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/analytics/campaigns_test.go`:

```go
package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCampaigns_EmptyFleet_ReturnsEmptySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := Campaigns(context.Background(), pool)
		if err != nil {
			t.Fatalf("Campaigns: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("Campaigns() = %+v, want empty", got)
		}
	})
}

func TestCampaigns_DelegatesToListWithRollups(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `
			INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, created_by, targets, skips, tags, started_at)
			VALUES ('camp-analytics-1', 'Analytics Test Campaign', 'scn-1', 'Test Scenario', 'posture', 'tester', '[]', '[]', '[]', NOW())`)

		got, err := Campaigns(ctx, pool)
		if err != nil {
			t.Fatalf("Campaigns: %v", err)
		}
		if len(got) != 1 || got[0].ID != "camp-analytics-1" {
			t.Fatalf("Campaigns() = %+v, want 1 rollup for camp-analytics-1", got)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/analytics/... 2>&1`
Expected: FAIL — `undefined: Campaigns`.

- [ ] **Step 3: Implement `Campaigns`**

Create `orchestrator/internal/analytics/campaigns.go`:

```go
package analytics

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/campaign"
)

// Campaigns returns every campaign with its live rollup -- a thin pass-
// through to campaign.ListWithRollups, the newly-extracted canonical
// definition (internal/campaign/store.go).
func Campaigns(ctx context.Context, pool *pgxpool.Pool) ([]campaign.Rollup, error) {
	return campaign.ListWithRollups(ctx, pool)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/analytics/... -run TestCampaigns -v`
Expected: build succeeds; both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/campaigns.go orchestrator/internal/analytics/campaigns_test.go
git commit -m "feat(analytics): add Campaigns, a thin pass-through to campaign.ListWithRollups"
git push
```

---

### Task 5: `analytics.BuildFleetExposure` + `analytics.FindingExposureWindows`

**Files:**
- Create: `orchestrator/internal/analytics/exposure.go`
- Test: `orchestrator/internal/analytics/exposure_test.go`

**Interfaces:**
- Consumes: `attackpath.BuildGraphAndAnalyze(cols []attackpath.Collection, tags []attackpath.AssetTag) (*attackpath.Graph, attackpath.Summary)` (existing, `internal/attackpath/assets.go:93`); `pathcorrelation.DefaultPaths(g, s) []pathcorrelation.AttackPath`, `pathcorrelation.Correlate(ctx, g, s, paths, mapper, runs, rules) (pathcorrelation.AttackPathCorrelation, error)`, `pathcorrelation.DefaultEdgeTechniqueMapper{}`, `pathcorrelation.NewSQLRunLookup(pool) *pathcorrelation.SQLRunLookup` (existing, `internal/pathcorrelation/{correlate,paths,mapper,runlookup}.go`); `exposure.Build(ctx, g, s, corr, rels, enricher, findingsLookup, agents) (*exposure.AssetGraph, error)`, `exposure.NewSQLCVEEnricher(pool)`, `exposure.NewSQLFindingsLookup(pool)`, `exposure.AgentRow{AgentID, Hostname, IP, OS}`, `(*exposure.AssetGraph).Summaries() []exposure.AssetSummary` (existing, `internal/exposure/build.go`); `predict.Build(ctx, pool) (predict.Prediction, error)` returning `.Exposure predict.ExposureWindows` (existing, `internal/predict/predict.go:47`).
- Produces: `type FleetExposure struct` (unexported fields), `func BuildFleetExposure(ctx, pool) (*FleetExposure, error)`, `func (fe *FleetExposure) Correlation() pathcorrelation.AttackPathCorrelation`, `func (fe *FleetExposure) AssetExposureSummary() ExposureSummary`, `type ExposureSummary struct { FleetAvgScore int; Assets []exposure.AssetSummary }`, `func FindingExposureWindows(ctx, pool) (predict.ExposureWindows, error)` — `BuildFleetExposure`/`Correlation`/`AssetExposureSummary` consumed by Task 6 (`dashboard.Compute()` refactor).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/analytics/exposure_test.go`:

```go
package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

func TestBuildFleetExposure_MatchesDirectCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		ctx := context.Background()

		fe, err := BuildFleetExposure(ctx, pool)
		if err != nil {
			t.Fatalf("BuildFleetExposure: %v", err)
		}

		gotCorr := fe.Correlation()
		gotExp := fe.AssetExposureSummary()
		if len(gotExp.Assets) != 1 {
			t.Fatalf("AssetExposureSummary().Assets = %+v, want 1 (one enrolled agent, no collections)", gotExp.Assets)
		}

		// Independently reproduce the same pipeline BuildFleetExposure wraps.
		g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
		paths := pathcorrelation.DefaultPaths(g, s)
		wantCorr, err := pathcorrelation.Correlate(ctx, g, s, paths,
			pathcorrelation.DefaultEdgeTechniqueMapper{}, pathcorrelation.NewSQLRunLookup(pool), nil)
		if err != nil {
			t.Fatalf("pathcorrelation.Correlate: %v", err)
		}
		if gotCorr.Score != wantCorr.Score {
			t.Errorf("Correlation().Score = %d, want %d (direct pathcorrelation.Correlate call)", gotCorr.Score, wantCorr.Score)
		}

		wantGraph, err := exposure.Build(ctx, g, s, wantCorr, nil,
			exposure.NewSQLCVEEnricher(pool), exposure.NewSQLFindingsLookup(pool),
			[]exposure.AgentRow{{AgentID: "a1", Hostname: "HOST-1"}})
		if err != nil {
			t.Fatalf("exposure.Build: %v", err)
		}
		wantSummaries := wantGraph.Summaries()
		if len(wantSummaries) != 1 {
			t.Fatalf("direct exposure.Build gave %d summaries, want 1", len(wantSummaries))
		}
		if gotExp.Assets[0].ExposureScore != wantSummaries[0].ExposureScore {
			t.Errorf("Assets[0].ExposureScore = %d, want %d (direct exposure.Build call)", gotExp.Assets[0].ExposureScore, wantSummaries[0].ExposureScore)
		}
		if gotExp.Assets[0].CriticalityRisk != wantSummaries[0].CriticalityRisk {
			t.Errorf("Assets[0].CriticalityRisk = %d, want %d (already computed inside exposure.Build, just surfaced)", gotExp.Assets[0].CriticalityRisk, wantSummaries[0].CriticalityRisk)
		}
		if gotExp.FleetAvgScore != wantSummaries[0].ExposureScore {
			t.Errorf("FleetAvgScore = %d, want %d (average of the single asset's score)", gotExp.FleetAvgScore, wantSummaries[0].ExposureScore)
		}
	})
}

func TestBuildFleetExposure_EmptyFleet_NoAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		fe, err := BuildFleetExposure(context.Background(), pool)
		if err != nil {
			t.Fatalf("BuildFleetExposure: %v", err)
		}
		exp := fe.AssetExposureSummary()
		if len(exp.Assets) != 0 || exp.FleetAvgScore != 0 {
			t.Errorf("AssetExposureSummary() = %+v, want empty/zero on an empty fleet", exp)
		}
	})
}

func TestFindingExposureWindows_MatchesDirectPredictBuildCall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `
			INSERT INTO findings (agent_id, technique_id, technique_name, control_class, severity, status, first_seen)
			VALUES ('a1', 'T1059', 'Command and Scripting Interpreter', 'prevention', 'High', 'open', NOW() - INTERVAL '10 days')`)

		got, err := FindingExposureWindows(ctx, pool)
		if err != nil {
			t.Fatalf("FindingExposureWindows: %v", err)
		}
		if !got.HasData || got.OpenCount != 1 {
			t.Fatalf("FindingExposureWindows() = %+v, want HasData=true OpenCount=1", got)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/analytics/... 2>&1`
Expected: FAIL — `undefined: BuildFleetExposure`, `undefined: FindingExposureWindows`.

- [ ] **Step 3: Implement `BuildFleetExposure` and `FindingExposureWindows`**

Create `orchestrator/internal/analytics/exposure.go`:

```go
package analytics

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/predict"
)

// FleetExposure holds the one expensive build (attack-path graph +
// detection correlation + asset exposure computation) so its accessors
// below stay cheap -- mirrors exposure.AssetGraph's own existing "Build()
// is the only expensive call" convention (internal/exposure/build.go:12-19).
type FleetExposure struct {
	corr pathcorrelation.AttackPathCorrelation
	ag   *exposure.AssetGraph
}

// BuildFleetExposure performs the one expensive pass -- the same
// attackpath.BuildGraphAndAnalyze + pathcorrelation.Correlate +
// exposure.Build sequence dashboard.Compute performed inline before this
// sub-project, moved here as the single definition. pathcorrelation.Correlate
// is computed internally because exposure.Build's existing signature
// already requires its output as an input -- this dependency predates this
// sub-project. Storing it avoids computing it twice; it does NOT make this
// sub-project the owner of Detection's canonical analytics category (see
// Correlation doc comment).
func BuildFleetExposure(ctx context.Context, pool *pgxpool.Pool) (*FleetExposure, error) {
	cols, err := loadCollections(ctx, pool)
	if err != nil {
		return nil, err
	}
	tags, err := loadAssetTags(ctx, pool)
	if err != nil {
		return nil, err
	}
	g, s := attackpath.BuildGraphAndAnalyze(cols, tags)

	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(ctx, g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{}, pathcorrelation.NewSQLRunLookup(pool), nil)
	if err != nil {
		return nil, err
	}

	agents, err := loadAgents(ctx, pool)
	if err != nil {
		return nil, err
	}
	ag, err := exposure.Build(ctx, g, s, corr, nil,
		exposure.NewSQLCVEEnricher(pool), exposure.NewSQLFindingsLookup(pool), agents)
	if err != nil {
		return nil, err
	}

	return &FleetExposure{corr: corr, ag: ag}, nil
}

// Correlation returns the pathcorrelation.AttackPathCorrelation value this
// FleetExposure already computed as a prerequisite for exposure.Build --
// exposed so dashboard.Compute (Task 6) doesn't need to call Correlate a
// second time just to read corr.Score for its own DetectionCoverage field.
// This is NOT this sub-project defining Detection's canonical analytics
// API -- Sub-project C still decides what "Detection" means across
// pathcorrelation.Correlate/coverage.Compute/GetCoverageAnalytics' 3
// distinct concepts.
func (fe *FleetExposure) Correlation() pathcorrelation.AttackPathCorrelation {
	return fe.corr
}

// ExposureSummary is the fleet-wide asset exposure view.
type ExposureSummary struct {
	FleetAvgScore int                     `json:"fleetAvgScore"`
	Assets        []exposure.AssetSummary `json:"assets"`
}

// AssetExposureSummary is the cheap accessor: fleet average (same
// total/len(summaries) arithmetic dashboard.Compute performed inline
// before this sub-project) plus the full per-asset list --
// exposure.AssetGraph.Summaries()'s own []AssetSummary, unchanged, already
// served live by Operational's GetExposureAssets today via the same
// exposure.Build call. Each AssetSummary already carries both
// ExposureScore and CriticalityRisk (CriticalityRisk is computed inside
// exposure.Build itself, internal/exposure/build.go:175-183) -- there is
// no separate "asset criticality" accessor here, it was never actually a
// distinct un-unified concept.
func (fe *FleetExposure) AssetExposureSummary() ExposureSummary {
	summaries := fe.ag.Summaries()
	avg := 0
	if len(summaries) > 0 {
		total := 0
		for _, a := range summaries {
			total += a.ExposureScore
		}
		avg = total / len(summaries)
	}
	return ExposureSummary{FleetAvgScore: avg, Assets: summaries}
}

// FindingExposureWindows is unrelated to the graph/asset-based exposure
// above -- a 3rd, distinct "exposure" concept (open-finding staleness).
// Thin pass-through to predict.Build, using only its Exposure half; no
// change needed inside internal/predict, Build is already exported.
func FindingExposureWindows(ctx context.Context, pool *pgxpool.Pool) (predict.ExposureWindows, error) {
	p, err := predict.Build(ctx, pool)
	if err != nil {
		return predict.ExposureWindows{}, err
	}
	return p.Exposure, nil
}

// loadCollections and loadAssetTags and loadAgents are moved verbatim from
// internal/dashboard/snapshot.go (deleted there in Task 6, not duplicated).

func loadCollections(ctx context.Context, pool *pgxpool.Pool) ([]attackpath.Collection, error) {
	rows, err := pool.Query(ctx, `SELECT payload FROM attackpath_collections`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []attackpath.Collection
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		var c attackpath.Collection
		if json.Unmarshal(raw, &c) == nil {
			cols = append(cols, c)
		}
	}
	return cols, rows.Err()
}

func loadAssetTags(ctx context.Context, pool *pgxpool.Pool) ([]attackpath.AssetTag, error) {
	rows, err := pool.Query(ctx, `
		SELECT host_key, label, crown_jewel, segment, high_value,
		       criticality_tier, internet_facing, identity_exposed, production, compliance_scope
		FROM attackpath_asset_tags`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []attackpath.AssetTag
	for rows.Next() {
		var t attackpath.AssetTag
		if rows.Scan(&t.HostKey, &t.Label, &t.CrownJewel, &t.Segment, &t.HighValue,
			&t.CriticalityTier, &t.InternetFacing, &t.IdentityExposed, &t.Production, &t.ComplianceScope) == nil {
			tags = append(tags, t)
		}
	}
	return tags, rows.Err()
}

func loadAgents(ctx context.Context, pool *pgxpool.Pool) ([]exposure.AgentRow, error) {
	rows, err := pool.Query(ctx, `SELECT agent_id, hostname, ip_address, os_version FROM agents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposure.AgentRow
	for rows.Next() {
		var a exposure.AgentRow
		if rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS) == nil {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/analytics/... -run 'TestBuildFleetExposure|TestFindingExposureWindows' -v`
Expected: build succeeds; all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/exposure.go orchestrator/internal/analytics/exposure_test.go
git commit -m "feat(analytics): add BuildFleetExposure and FindingExposureWindows"
git push
```

---

### Task 6: Refactor `dashboard.Compute()` to consume `internal/analytics`

**Files:**
- Modify: `orchestrator/internal/dashboard/snapshot.go` (replace `Compute()`'s body; delete now-dead `avgRiskScore`, `loadCollections`, `loadAssetTags`, `loadAgents`)
- Test: no new test file — the existing `orchestrator/internal/dashboard/snapshot_test.go` is the regression guard (Global Constraints: must keep passing unchanged)

**Interfaces:**
- Consumes: `analytics.FleetRisk(ctx, pool) (analytics.RiskResult, error)` (Task 1), `analytics.BuildFleetExposure(ctx, pool) (*analytics.FleetExposure, error)`, `(*analytics.FleetExposure).Correlation()`, `(*analytics.FleetExposure).AssetExposureSummary()` (Task 5).
- Produces: `dashboard.Compute`'s external signature and `Snapshot` type are unchanged — no other package's call sites need updating.

- [ ] **Step 1: Confirm the regression-guard tests currently pass**

Run: `cd orchestrator && go test ./internal/dashboard/... -v 2>&1 | tail -20`
Expected: all 3 existing tests (`TestCompute_EmptyFleet_ReturnsZeroScores`, `TestCompute_AvgRiskScoreFromRecentRuns`, `TestCompute_ExposureAndDetectionMatchDirectCalls`) PASS — this is the baseline the refactor must not break.

- [ ] **Step 2: Replace `Compute()` and delete the now-dead private loaders**

In `orchestrator/internal/dashboard/snapshot.go`, replace the entire file's `import` block and everything from `func Compute` through the end of the file (currently lines 9-147: the `import` block, `Compute`, `avgRiskScore`, `loadCollections`, `loadAssetTags`, `loadAgents`) with:

```go
import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/analytics"
)

// Snapshot is the fleet-wide posture at the moment Compute was called.
type Snapshot struct {
	AvgRiskScore      int `json:"avgRiskScore"`
	ExposureScore     int `json:"exposureScore"`
	DetectionCoverage int `json:"detectionCoverage"`
	AssetCount        int `json:"assetCount"`
}

// Compute builds today's fleet-wide snapshot. Nil-safe: an empty fleet (no
// runs, no assets) returns a zero-value Snapshot, never an error -- same
// convention as exposure.Build/pathcorrelation.Correlate. Delegates to
// internal/analytics for every value -- this function no longer owns any
// computation itself, matching the "dashboards are pure presentation"
// architecture (docs/superpowers/specs/2026-07-30-unified-analytics-layer-phase-a-design.md).
func Compute(ctx context.Context, pool *pgxpool.Pool) (Snapshot, error) {
	risk, err := analytics.FleetRisk(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}

	fe, err := analytics.BuildFleetExposure(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	expSummary := fe.AssetExposureSummary()
	corr := fe.Correlation()

	return Snapshot{
		AvgRiskScore:      risk.FleetAvgScore,
		ExposureScore:     expSummary.FleetAvgScore,
		DetectionCoverage: corr.Score,
		AssetCount:        len(expSummary.Assets),
	}, nil
}
```

Keep the file's package doc comment (lines 1-7, "Package dashboard is the Phase 6 executive-dashboard aggregator...") — update it to reflect that it now delegates rather than computes:

```go
// Package dashboard is the Phase 6 executive-dashboard aggregator: a thin
// consumer over internal/analytics (Risk, Exposure) reduced to a fleet-wide
// snapshot for a time-series view. It owns no computation and no DB tables
// itself -- internal/api's scheduler persists what Compute returns.
package dashboard
```

- [ ] **Step 3: Run the regression-guard tests to verify byte-identical output**

Run: `cd orchestrator && go build ./... && go test ./internal/dashboard/... -v 2>&1 | tail -20`
Expected: build succeeds; all 3 existing tests still PASS with no changes to their assertions — proves the refactor preserved behavior exactly.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/dashboard/snapshot.go
git commit -m "refactor(dashboard): Compute() delegates to internal/analytics instead of owning the logic"
git push
```

---

### Task 7: Refactor `ListCampaigns` handler to consume `campaign.ListWithRollups`

**Files:**
- Modify: `orchestrator/internal/api/campaign_handlers.go:259-287` (`ListCampaigns` handler)
- Test: no new test file — `orchestrator/internal/api/campaign_crud_test.go`'s existing `TestListCampaigns_Empty`/`TestListCampaigns_ReturnsRollup` are the regression guard

**Interfaces:**
- Consumes: `campaign.ListWithRollups(ctx, pool) ([]campaign.Rollup, error)` (Task 3).
- Produces: `ListCampaigns`'s HTTP response shape is unchanged (still a JSON array of objects with `id`/`name`/`scenarioId`/`scenarioName`/`mode`/`createdBy`/`startedAt`/`summary`) — no frontend change needed.

- [ ] **Step 1: Confirm the regression-guard tests currently pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestListCampaigns -v 2>&1 | tail -20`
Expected: both existing tests PASS — this is the baseline the refactor must not break.

- [ ] **Step 2: Replace `ListCampaigns`'s body**

In `orchestrator/internal/api/campaign_handlers.go`, replace the `ListCampaigns` function (currently lines 260-287):

```go
// ListCampaigns returns every campaign with its live rollup. GET /api/campaigns
func (h *Handler) ListCampaigns(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `SELECT id FROM campaigns ORDER BY started_at DESC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	out := []map[string]any{}
	for _, id := range ids {
		c, err := h.loadCampaign(r.Context(), id)
		if err != nil {
			continue
		}
		s, _, _ := h.summaryFor(r.Context(), c)
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
			"mode": c.Mode, "createdBy": c.CreatedBy, "startedAt": c.StartedAt, "summary": s,
		})
	}
	respond(w, out)
}
```

with:

```go
// ListCampaigns returns every campaign with its live rollup. GET /api/campaigns
func (h *Handler) ListCampaigns(w http.ResponseWriter, r *http.Request) {
	rollups, err := campaign.ListWithRollups(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rollups))
	for _, c := range rollups {
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "scenarioId": c.ScenarioID, "scenarioName": c.ScenarioName,
			"mode": c.Mode, "createdBy": c.CreatedBy, "startedAt": c.StartedAt, "summary": c.Summary,
		})
	}
	respond(w, out)
}
```

Confirm `internal/api/campaign_handlers.go`'s existing imports already include `"github.com/audspect/bas/internal/campaign"` (it does — `campaign.ChildRun`/`campaign.Skip`/`campaign.Aggregate`/`campaign.DeriveStatus` are already used throughout this file) — no new import needed.

- [ ] **Step 3: Run the regression-guard tests to verify identical response shape**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestListCampaigns -v 2>&1 | tail -20`
Expected: build succeeds; both existing tests still PASS unchanged — proves the JSON response shape didn't change.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/campaign_handlers.go
git commit -m "refactor(api): ListCampaigns delegates to campaign.ListWithRollups"
git push
```

---

### Task 8: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1 > /tmp/analytics-phase-a-full-suite.log 2>&1; echo "EXIT_CODE:$?"`

Expected: `EXIT_CODE:0`, every package `ok`. If a single package fails under Docker load with a testcontainers connection error, re-run that package in isolation before concluding it's the known transient flake this session has repeatedly confirmed (this session's established distinction: one package failing under full-suite load is usually transient; many/all packages failing identically means check `docker info` first — a genuine outage, not a flake).

- [ ] **Step 2: Report completion**

This sub-project executes directly on `main` (matching this session's established inline-execution convention) — no branch/worktree/PR decision needed. Confirm with the user that Sub-project A is complete, and that Sub-project B (the unified dashboard shell + view selector, consuming this analytics layer) is next.
