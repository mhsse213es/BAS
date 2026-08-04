# Drift & Stability Analytics (Phase 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Derive stability/drift metrics (drift count, streaks, stability %, relapse timing) for every remediated control from the existing `technique_verification_runs` history — no new storage, computation only.

**Architecture:** A DB-free pure-function package (`internal/driftanalytics`) computes `DriftStats` from an ordered binary PASS/FAIL sequence. `internal/api` builds those sequences from `technique_verification_runs`, pooling across every `request_id` for a given `(agent_id, check_id)` pair (not scoped to one Sub-project 8 revalidation chain), and exposes 3 new read-only endpoints.

**Tech Stack:** Go, PostgreSQL (pgx), chi router — matches every prior sub-project in this initiative.

## Global Constraints

- No new database tables or columns — `technique_verification_runs` is the sole data source.
- `internal/driftanalytics` must have zero database/network dependencies — every function in it is pure and unit-testable without a container.
- `DriftStats`/`VerificationOutcome` carry no JSON struct tags, matching the established precedent set by `jobs.Job`/`jobs.JobTarget` (Sub-project 6) and `remediation.TechniqueVerificationRun` — capitalized Go field names flow straight through as the wire format.
- Drift is strictly a PASS→FAIL transition — a bare FAIL streak with no preceding PASS is never counted as drift.
- `models.ResultBlocked` normalizes to `"pass"` (matches the `case ResultPass, ResultBlocked:` convention used everywhere else in this codebase); `models.ResultError`/`models.ResultSkipped` rows are excluded from the sequence entirely.
- No new permissions — all 3 new endpoints reuse `auth.CanExecuteRemediation`, matching every other read endpoint in this initiative.
- Direct commits to `main`, no branches/PRs, per this repo's established convention.
- Every task follows TDD: write failing test → verify it fails → implement → verify it passes → commit.

---

### Task 1: `internal/driftanalytics` — types and `ComputeDriftStats`

**Files:**
- Create: `orchestrator/internal/driftanalytics/driftanalytics.go`
- Create: `orchestrator/internal/driftanalytics/driftanalytics_test.go`

**Interfaces:**
- Produces: `VerificationOutcome{Result string, At time.Time}`, `DriftStats{TotalRuns, PassCount, FailCount int; StabilityPercent float64; DriftCount, LongestPassStreak, LongestFailStreak int; CurrentStreakResult string; CurrentStreakLength int; CurrentStreakStartedAt *time.Time; AverageDaysUntilDrift float64; DriftEvents []time.Time; FirstVerifiedAt, LastVerifiedAt *time.Time}`, `ComputeDriftStats(runs []VerificationOutcome) DriftStats` — all consumed directly by Tasks 3-5.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/driftanalytics/driftanalytics_test.go`:
```go
package driftanalytics

import (
	"testing"
	"time"
)

func day(n int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n)
}

func TestComputeDriftStats_EmptySequence(t *testing.T) {
	s := ComputeDriftStats(nil)
	if s.TotalRuns != 0 || s.CurrentStreakResult != "" || s.FirstVerifiedAt != nil || s.LastVerifiedAt != nil {
		t.Errorf("got %+v, want all-zero stats for an empty sequence", s)
	}
}

func TestComputeDriftStats_SingleRun(t *testing.T) {
	s := ComputeDriftStats([]VerificationOutcome{{Result: "pass", At: day(0)}})
	if s.TotalRuns != 1 || s.PassCount != 1 || s.DriftCount != 0 || s.LongestPassStreak != 1 || s.CurrentStreakResult != "pass" || s.CurrentStreakLength != 1 {
		t.Errorf("got %+v, want a single-pass no-drift result", s)
	}
}

func TestComputeDriftStats_AllFail_NeverDrifted(t *testing.T) {
	runs := []VerificationOutcome{
		{Result: "fail", At: day(0)}, {Result: "fail", At: day(1)},
		{Result: "fail", At: day(2)}, {Result: "fail", At: day(3)},
	}
	s := ComputeDriftStats(runs)
	if s.DriftCount != 0 {
		t.Errorf("DriftCount = %d, want 0 (never fixed, so nothing to drift from)", s.DriftCount)
	}
	if s.LongestFailStreak != 4 || s.LongestPassStreak != 0 {
		t.Errorf("LongestFailStreak=%d LongestPassStreak=%d, want 4/0", s.LongestFailStreak, s.LongestPassStreak)
	}
}

func TestComputeDriftStats_AllPass_NeverDrifted(t *testing.T) {
	runs := []VerificationOutcome{
		{Result: "pass", At: day(0)}, {Result: "pass", At: day(1)},
		{Result: "pass", At: day(2)}, {Result: "pass", At: day(3)},
	}
	s := ComputeDriftStats(runs)
	if s.DriftCount != 0 || s.LongestPassStreak != 4 || s.StabilityPercent != 100 {
		t.Errorf("got %+v, want DriftCount=0 LongestPassStreak=4 StabilityPercent=100", s)
	}
}

func TestComputeDriftStats_CanonicalExample_OneDrift(t *testing.T) {
	// FAIL, PASS, PASS, PASS, FAIL -- the spec's own worked example.
	runs := []VerificationOutcome{
		{Result: "fail", At: day(0)},
		{Result: "pass", At: day(1)},
		{Result: "pass", At: day(2)},
		{Result: "pass", At: day(3)},
		{Result: "fail", At: day(4)},
	}
	s := ComputeDriftStats(runs)
	if s.DriftCount != 1 {
		t.Errorf("DriftCount = %d, want 1", s.DriftCount)
	}
	if s.LongestPassStreak != 3 || s.LongestFailStreak != 1 {
		t.Errorf("LongestPassStreak=%d LongestFailStreak=%d, want 3/1", s.LongestPassStreak, s.LongestFailStreak)
	}
	if s.CurrentStreakResult != "fail" || s.CurrentStreakLength != 1 {
		t.Errorf("CurrentStreakResult=%q CurrentStreakLength=%d, want fail/1", s.CurrentStreakResult, s.CurrentStreakLength)
	}
	if s.StabilityPercent != 60 {
		t.Errorf("StabilityPercent = %v, want 60", s.StabilityPercent)
	}
	if s.AverageDaysUntilDrift != 3 {
		t.Errorf("AverageDaysUntilDrift = %v, want 3 (day4 - day1)", s.AverageDaysUntilDrift)
	}
	if len(s.DriftEvents) != 1 || !s.DriftEvents[0].Equal(day(4)) {
		t.Errorf("DriftEvents = %v, want [day(4)]", s.DriftEvents)
	}
	if s.CurrentStreakStartedAt == nil || !s.CurrentStreakStartedAt.Equal(day(4)) {
		t.Errorf("CurrentStreakStartedAt = %v, want day(4)", s.CurrentStreakStartedAt)
	}
}

func TestComputeDriftStats_MultipleDrifts_AveragesCorrectly(t *testing.T) {
	// PASS(day0) -> FAIL(day5): drift 1, duration 5 days
	// PASS(day6) -> FAIL(day16): drift 2, duration 10 days
	// PASS(day17): current streak
	runs := []VerificationOutcome{
		{Result: "pass", At: day(0)},
		{Result: "fail", At: day(5)},
		{Result: "pass", At: day(6)},
		{Result: "fail", At: day(16)},
		{Result: "pass", At: day(17)},
	}
	s := ComputeDriftStats(runs)
	if s.DriftCount != 2 {
		t.Fatalf("DriftCount = %d, want 2", s.DriftCount)
	}
	if s.AverageDaysUntilDrift != 7.5 {
		t.Errorf("AverageDaysUntilDrift = %v, want 7.5 ((5+10)/2)", s.AverageDaysUntilDrift)
	}
	if len(s.DriftEvents) != 2 || !s.DriftEvents[0].Equal(day(5)) || !s.DriftEvents[1].Equal(day(16)) {
		t.Errorf("DriftEvents = %v, want [day(5), day(16)]", s.DriftEvents)
	}
	if s.CurrentStreakResult != "pass" || s.CurrentStreakLength != 1 {
		t.Errorf("CurrentStreakResult=%q CurrentStreakLength=%d, want pass/1", s.CurrentStreakResult, s.CurrentStreakLength)
	}
}

func TestComputeDriftStats_FirstAndLastVerifiedAt(t *testing.T) {
	runs := []VerificationOutcome{{Result: "pass", At: day(0)}, {Result: "fail", At: day(10)}}
	s := ComputeDriftStats(runs)
	if s.FirstVerifiedAt == nil || !s.FirstVerifiedAt.Equal(day(0)) {
		t.Errorf("FirstVerifiedAt = %v, want day(0)", s.FirstVerifiedAt)
	}
	if s.LastVerifiedAt == nil || !s.LastVerifiedAt.Equal(day(10)) {
		t.Errorf("LastVerifiedAt = %v, want day(10)", s.LastVerifiedAt)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/driftanalytics/... -v`
Expected: FAIL to compile — the package doesn't exist yet.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/driftanalytics/driftanalytics.go`:
```go
// Package driftanalytics derives stability/drift metrics from a control's
// technique-verification history. Every function here is pure -- no
// database or network access -- so the algorithm is fully unit-testable
// without a container. Callers (internal/api) build the ordered,
// normalized sequence from technique_verification_runs and pass it in.
package driftanalytics

import "time"

// VerificationOutcome is one already-normalized, binary result in a
// control's ordered history. Result is always "pass" or "fail" --
// models.ResultBlocked normalizes to "pass" (the control prevented the
// technique from running, a security win) and
// models.ResultError/ResultSkipped rows are dropped entirely before
// building this slice.
type VerificationOutcome struct {
	Result string
	At     time.Time
}

// DriftStats is the full set of derived stability metrics for one
// (agent_id, check_id) pair's pooled history, across every remediation
// request ever made for it.
type DriftStats struct {
	TotalRuns              int
	PassCount              int
	FailCount              int
	StabilityPercent       float64 // PassCount / TotalRuns * 100; 0 if TotalRuns == 0
	DriftCount             int     // count of PASS -> FAIL transitions
	LongestPassStreak      int
	LongestFailStreak      int
	CurrentStreakResult    string // "pass" or "fail"; "" if TotalRuns == 0
	CurrentStreakLength    int
	CurrentStreakStartedAt *time.Time  // when the current (still-open) streak began
	AverageDaysUntilDrift  float64     // mean duration (days) of every PASS-streak that ended in a drift; 0 if DriftCount == 0
	DriftEvents            []time.Time // the timestamp of the FAIL that caused each drift, one per DriftCount, in order
	FirstVerifiedAt        *time.Time
	LastVerifiedAt         *time.Time
}

// ComputeDriftStats derives DriftStats from an ordered (oldest-first)
// binary sequence via a single linear walk. Drift is strictly a
// PASS->FAIL transition -- a bare FAIL streak with no preceding PASS is
// never counted (there's nothing to drift from).
func ComputeDriftStats(runs []VerificationOutcome) DriftStats {
	var s DriftStats
	s.TotalRuns = len(runs)
	if s.TotalRuns == 0 {
		return s
	}
	s.FirstVerifiedAt = &runs[0].At
	s.LastVerifiedAt = &runs[len(runs)-1].At

	streakResult := runs[0].Result
	streakStart := runs[0].At
	streakLen := 0
	var driftDurationsDays []float64

	flushStreak := func() {
		if streakResult == "pass" && streakLen > s.LongestPassStreak {
			s.LongestPassStreak = streakLen
		}
		if streakResult == "fail" && streakLen > s.LongestFailStreak {
			s.LongestFailStreak = streakLen
		}
	}

	for i, r := range runs {
		if r.Result == "pass" {
			s.PassCount++
		} else {
			s.FailCount++
		}

		if i > 0 && runs[i-1].Result != r.Result {
			if runs[i-1].Result == "pass" && r.Result == "fail" {
				s.DriftCount++
				driftDurationsDays = append(driftDurationsDays, r.At.Sub(streakStart).Hours()/24)
				s.DriftEvents = append(s.DriftEvents, r.At)
			}
			flushStreak()
			streakResult = r.Result
			streakStart = r.At
			streakLen = 0
		}
		streakLen++
	}
	flushStreak() // close out the final (current) streak

	s.CurrentStreakResult = streakResult
	s.CurrentStreakLength = streakLen
	s.CurrentStreakStartedAt = &streakStart
	s.StabilityPercent = float64(s.PassCount) / float64(s.TotalRuns) * 100
	if len(driftDurationsDays) > 0 {
		var sum float64
		for _, d := range driftDurationsDays {
			sum += d
		}
		s.AverageDaysUntilDrift = sum / float64(len(driftDurationsDays))
	}
	return s
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/driftanalytics/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/driftanalytics/driftanalytics.go orchestrator/internal/driftanalytics/driftanalytics_test.go
git commit -m "feat(driftanalytics): add pure drift/stability computation from verification history"
```

---

### Task 2: Source queries — building `VerificationOutcome` sequences from `technique_verification_runs`

**Files:**
- Create: `orchestrator/internal/api/drift_query.go`
- Create: `orchestrator/internal/api/drift_query_test.go`

**Interfaces:**
- Consumes: `driftanalytics.VerificationOutcome` (Task 1).
- Produces: `h.verificationOutcomesForPair(ctx, agentID, checkID string) ([]driftanalytics.VerificationOutcome, error)`, `h.verificationOutcomesByCheckForAgent(ctx, agentID string) (map[string][]driftanalytics.VerificationOutcome, error)`, `driftPairKey{AgentID, CheckID string}`, `h.verificationOutcomesByPairFleetWide(ctx) (map[driftPairKey][]driftanalytics.VerificationOutcome, error)` — all consumed by Tasks 3-5.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/drift_query_test.go`:
```go
package api

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// seedVerificationRun inserts a remediation_requests row (satisfying the
// FK) and one technique_verification_runs row for it. Each call uses a
// fresh remediationRequestID -- tests pooling across multiple separate
// remediation attempts for the same (agentID, checkID) pair, which is
// exactly what Phase 6's scope decision requires.
func seedVerificationRun(t *testing.T, pool *pgxpool.Pool, remediationRequestID, agentID, checkID, status, completedAt string) {
	t.Helper()
	mustExecAPI(t, pool, `
		INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
		VALUES ($1, 'enable_windows_firewall', $2, $3, 1, 'completed', 'user-1', 'test')`,
		remediationRequestID, agentID, checkID)
	mustExecAPI(t, pool, `
		INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by, completed_at)
		VALUES (gen_random_uuid()::text, $1, $2, $3, 'T1082', $4, 'user-1', $5::timestamptz)`,
		remediationRequestID, agentID, checkID, status, completedAt)
}

func TestVerificationOutcomesForPair_PoolsAcrossRequestIDs_ExcludesErrorSkipped_NormalizesBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dq-a1', 'DQ-A1', 'windows')`)
		// Two SEPARATE remediation requests for the same (agent, check) pair.
		seedVerificationRun(t, pool, "dq-rr-1", "dq-a1", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-2", "dq-a1", "windows-firewall-enabled", "blocked", "2026-01-02T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-3", "dq-a1", "windows-firewall-enabled", "error", "2026-01-03T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-4", "dq-a1", "windows-firewall-enabled", "skipped", "2026-01-04T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-5", "dq-a1", "windows-firewall-enabled", "fail", "2026-01-05T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		outcomes, err := h.verificationOutcomesForPair(context.Background(), "dq-a1", "windows-firewall-enabled")
		if err != nil {
			t.Fatalf("verificationOutcomesForPair: %v", err)
		}
		if len(outcomes) != 3 {
			t.Fatalf("got %d outcomes, want 3 (error/skipped excluded)", len(outcomes))
		}
		if outcomes[0].Result != "pass" || outcomes[1].Result != "pass" || outcomes[2].Result != "fail" {
			t.Errorf("got results %q/%q/%q, want pass/pass/fail (blocked normalized to pass)", outcomes[0].Result, outcomes[1].Result, outcomes[2].Result)
		}
	})
}

func TestVerificationOutcomesByCheckForAgent_GroupsByCheckID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dq-a2', 'DQ-A2', 'windows')`)
		seedVerificationRun(t, pool, "dq-rr-6", "dq-a2", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-7", "dq-a2", "windows-defender-enabled", "fail", "2026-01-01T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		grouped, err := h.verificationOutcomesByCheckForAgent(context.Background(), "dq-a2")
		if err != nil {
			t.Fatalf("verificationOutcomesByCheckForAgent: %v", err)
		}
		if len(grouped) != 2 {
			t.Fatalf("got %d checks, want 2", len(grouped))
		}
		if len(grouped["windows-firewall-enabled"]) != 1 || len(grouped["windows-defender-enabled"]) != 1 {
			t.Errorf("grouped = %+v, want 1 outcome per check", grouped)
		}
	})
}

func TestVerificationOutcomesByPairFleetWide_GroupsByAgentAndCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dq-a3', 'DQ-A3', 'windows')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dq-a4', 'DQ-A4', 'windows')`)
		seedVerificationRun(t, pool, "dq-rr-8", "dq-a3", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "dq-rr-9", "dq-a4", "windows-firewall-enabled", "fail", "2026-01-01T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		grouped, err := h.verificationOutcomesByPairFleetWide(context.Background())
		if err != nil {
			t.Fatalf("verificationOutcomesByPairFleetWide: %v", err)
		}
		if len(grouped[driftPairKey{AgentID: "dq-a3", CheckID: "windows-firewall-enabled"}]) != 1 {
			t.Error("missing dq-a3 pair")
		}
		if len(grouped[driftPairKey{AgentID: "dq-a4", CheckID: "windows-firewall-enabled"}]) != 1 {
			t.Error("missing dq-a4 pair")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestVerificationOutcomes" -v`
Expected: FAIL to compile — none of the query functions or `driftPairKey` exist yet.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/api/drift_query.go`:
```go
package api

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/driftanalytics"
)

// normalizeVerificationStatus maps a technique_verification_runs.status
// value to driftanalytics' binary "pass"/"fail". Only ever called with
// "pass"/"blocked"/"fail" -- callers filter error/skipped out in SQL
// before this function is reached. blocked normalizes to pass, matching
// the "pass, blocked" success bucket used everywhere else in this
// codebase (the control prevented the technique from running).
func normalizeVerificationStatus(status string) string {
	if status == "fail" {
		return "fail"
	}
	return "pass"
}

// verificationOutcomesForPair returns one control's full pooled history
// across every remediation request ever made for it (agentID, checkID),
// ordered oldest-first.
func (h *Handler) verificationOutcomesForPair(ctx context.Context, agentID, checkID string) ([]driftanalytics.VerificationOutcome, error) {
	rows, err := h.db.Query(ctx,
		`SELECT status, completed_at FROM technique_verification_runs
		 WHERE agent_id=$1 AND check_id=$2 AND completed_at IS NOT NULL AND status IN ('pass','blocked','fail')
		 ORDER BY completed_at ASC`, agentID, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var outcomes []driftanalytics.VerificationOutcome
	for rows.Next() {
		var status string
		var at time.Time
		if err := rows.Scan(&status, &at); err != nil {
			return nil, err
		}
		outcomes = append(outcomes, driftanalytics.VerificationOutcome{Result: normalizeVerificationStatus(status), At: at})
	}
	return outcomes, rows.Err()
}

// verificationOutcomesByCheckForAgent groups one agent's full history by
// check_id in a single query, avoiding one round-trip per check.
func (h *Handler) verificationOutcomesByCheckForAgent(ctx context.Context, agentID string) (map[string][]driftanalytics.VerificationOutcome, error) {
	rows, err := h.db.Query(ctx,
		`SELECT check_id, status, completed_at FROM technique_verification_runs
		 WHERE agent_id=$1 AND completed_at IS NOT NULL AND status IN ('pass','blocked','fail')
		 ORDER BY check_id, completed_at ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grouped := map[string][]driftanalytics.VerificationOutcome{}
	for rows.Next() {
		var checkID, status string
		var at time.Time
		if err := rows.Scan(&checkID, &status, &at); err != nil {
			return nil, err
		}
		grouped[checkID] = append(grouped[checkID], driftanalytics.VerificationOutcome{Result: normalizeVerificationStatus(status), At: at})
	}
	return grouped, rows.Err()
}

// driftPairKey identifies one control on one endpoint.
type driftPairKey struct {
	AgentID string
	CheckID string
}

// verificationOutcomesByPairFleetWide groups every control's full history
// by (agent_id, check_id) across the whole fleet in a single query.
func (h *Handler) verificationOutcomesByPairFleetWide(ctx context.Context) (map[driftPairKey][]driftanalytics.VerificationOutcome, error) {
	rows, err := h.db.Query(ctx,
		`SELECT agent_id, check_id, status, completed_at FROM technique_verification_runs
		 WHERE completed_at IS NOT NULL AND status IN ('pass','blocked','fail')
		 ORDER BY agent_id, check_id, completed_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grouped := map[driftPairKey][]driftanalytics.VerificationOutcome{}
	for rows.Next() {
		var agentID, checkID, status string
		var at time.Time
		if err := rows.Scan(&agentID, &checkID, &status, &at); err != nil {
			return nil, err
		}
		key := driftPairKey{AgentID: agentID, CheckID: checkID}
		grouped[key] = append(grouped[key], driftanalytics.VerificationOutcome{Result: normalizeVerificationStatus(status), At: at})
	}
	return grouped, rows.Err()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestVerificationOutcomes" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/drift_query.go orchestrator/internal/api/drift_query_test.go
git commit -m "feat(api): add technique_verification_runs source queries for drift analytics"
```

---

### Task 3: `GET /api/agents/{agentId}/checks/{checkId}/drift`

**Files:**
- Create: `orchestrator/internal/api/drift_handlers.go`
- Create: `orchestrator/internal/api/drift_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `h.verificationOutcomesForPair` (Task 2), `driftanalytics.ComputeDriftStats` (Task 1).
- Produces: `h.GetControlDrift(w, r)`.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/drift_handlers_test.go`:
```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/driftanalytics"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetControlDrift_ComputesFromPooledHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('dh-a1', 'DH-A1', 'windows')`)
		seedVerificationRun(t, pool, "dh-rr-1", "dh-a1", "windows-firewall-enabled", "fail", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "dh-rr-2", "dh-a1", "windows-firewall-enabled", "pass", "2026-01-02T00:00:00Z")
		seedVerificationRun(t, pool, "dh-rr-3", "dh-a1", "windows-firewall-enabled", "pass", "2026-01-03T00:00:00Z")
		seedVerificationRun(t, pool, "dh-rr-4", "dh-a1", "windows-firewall-enabled", "pass", "2026-01-04T00:00:00Z")
		seedVerificationRun(t, pool, "dh-rr-5", "dh-a1", "windows-firewall-enabled", "fail", "2026-01-05T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParams(httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"agentId": "dh-a1", "checkId": "windows-firewall-enabled"})
		w := httptest.NewRecorder()
		h.GetControlDrift(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			DriftStats driftanalytics.DriftStats `json:"driftStats"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.DriftStats.DriftCount != 1 {
			t.Errorf("DriftCount = %d, want 1", resp.DriftStats.DriftCount)
		}
	})
}

func TestGetControlDrift_NoHistory_ReturnsZeroValueStats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParams(httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"agentId": "dh-does-not-exist", "checkId": "windows-firewall-enabled"})
		w := httptest.NewRecorder()
		h.GetControlDrift(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			DriftStats driftanalytics.DriftStats `json:"driftStats"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.DriftStats.TotalRuns != 0 {
			t.Errorf("TotalRuns = %d, want 0", resp.DriftStats.TotalRuns)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetControlDrift" -v`
Expected: FAIL to compile — `GetControlDrift` doesn't exist yet.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/api/drift_handlers.go`:
```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/driftanalytics"
)

// GET /api/agents/{agentId}/checks/{checkId}/drift
// The core per-control view: drift/stability metrics for one control on
// one endpoint, pooled across every remediation request ever made for it.
// No history yet is a normal, common state (e.g. a control that's never
// opted into continuous validation) -- returns 200 with zero-value stats,
// not 404, since there's no authoritative list of valid pairs to 404
// against.
func (h *Handler) GetControlDrift(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	checkID := chi.URLParam(r, "checkId")
	outcomes, err := h.verificationOutcomesForPair(r.Context(), agentID, checkID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats := driftanalytics.ComputeDriftStats(outcomes)
	respond(w, map[string]any{"driftStats": stats})
}
```

- [ ] **Step 4: Add the route**

In `orchestrator/internal/api/routes.go`, immediately after the existing line:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/remediation-requests/{requestId}/revalidations", h.GetRemediationRevalidations)
```
add:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/checks/{checkId}/drift", h.GetControlDrift)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing line:
```go
{http.MethodGet, "/api/remediation-requests/{requestId}/revalidations", tierPermission, auth.CanExecuteRemediation},
```
add:
```go
{http.MethodGet, "/api/agents/{agentId}/checks/{checkId}/drift", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetControlDrift|TestRBACMatrix" -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/drift_handlers.go orchestrator/internal/api/drift_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add GET /api/agents/{agentId}/checks/{checkId}/drift"
```

---

### Task 4: `GET /api/agents/{agentId}/drift-summary`

**Files:**
- Modify: `orchestrator/internal/api/drift_handlers.go`
- Modify: `orchestrator/internal/api/drift_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `h.verificationOutcomesByCheckForAgent` (Task 2), `driftanalytics.ComputeDriftStats` (Task 1).
- Produces: `h.GetAgentDriftSummary(w, r)`, `checkDriftEntry{CheckID string, Stats driftanalytics.DriftStats}` (consumed nowhere else, but named for Task 6's memory-update consistency check).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/drift_handlers_test.go`:
```go
func TestGetAgentDriftSummary_SortsByStabilityAscending(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('ds-a1', 'DS-A1', 'windows')`)
		// windows-firewall-enabled: 100% stable (1 pass)
		seedVerificationRun(t, pool, "ds-rr-1", "ds-a1", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		// windows-defender-enabled: 50% stable (1 pass, 1 fail)
		seedVerificationRun(t, pool, "ds-rr-2", "ds-a1", "windows-defender-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "ds-rr-3", "ds-a1", "windows-defender-enabled", "fail", "2026-01-02T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "ds-a1")
		w := httptest.NewRecorder()
		h.GetAgentDriftSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			OverallStabilityPercent float64            `json:"overallStabilityPercent"`
			Checks                  []checkDriftEntry `json:"checks"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Checks) != 2 {
			t.Fatalf("got %d checks, want 2", len(resp.Checks))
		}
		if resp.Checks[0].CheckID != "windows-defender-enabled" {
			t.Errorf("Checks[0].CheckID = %q, want windows-defender-enabled (least stable first)", resp.Checks[0].CheckID)
		}
		if resp.OverallStabilityPercent != 75 { // (100 + 50) / 2
			t.Errorf("OverallStabilityPercent = %v, want 75", resp.OverallStabilityPercent)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetAgentDriftSummary" -v`
Expected: FAIL to compile — `GetAgentDriftSummary`/`checkDriftEntry` don't exist yet.

- [ ] **Step 3: Implement**

Add to `orchestrator/internal/api/drift_handlers.go` (add `"sort"` to the import block):
```go
// checkDriftEntry is one control's drift stats within a per-agent summary.
type checkDriftEntry struct {
	CheckID string
	Stats   driftanalytics.DriftStats
}

// GET /api/agents/{agentId}/drift-summary
// Every control this agent has any verification history for, sorted
// least-stable first, plus an endpoint-level overall stability score
// (mean StabilityPercent across its controls).
func (h *Handler) GetAgentDriftSummary(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	grouped, err := h.verificationOutcomesByCheckForAgent(r.Context(), agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entries := make([]checkDriftEntry, 0, len(grouped))
	var stabilitySum float64
	for checkID, outcomes := range grouped {
		stats := driftanalytics.ComputeDriftStats(outcomes)
		entries = append(entries, checkDriftEntry{CheckID: checkID, Stats: stats})
		stabilitySum += stats.StabilityPercent
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Stats.StabilityPercent < entries[j].Stats.StabilityPercent })

	overall := 0.0
	if len(entries) > 0 {
		overall = stabilitySum / float64(len(entries))
	}
	respond(w, map[string]any{"overallStabilityPercent": overall, "checks": entries})
}
```

- [ ] **Step 4: Add the route**

In `orchestrator/internal/api/routes.go`, immediately after the line added in Task 3:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/checks/{checkId}/drift", h.GetControlDrift)
```
add:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/drift-summary", h.GetAgentDriftSummary)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the line added in Task 3:
```go
{http.MethodGet, "/api/agents/{agentId}/checks/{checkId}/drift", tierPermission, auth.CanExecuteRemediation},
```
add:
```go
{http.MethodGet, "/api/agents/{agentId}/drift-summary", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetAgentDriftSummary|TestRBACMatrix" -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/drift_handlers.go orchestrator/internal/api/drift_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add GET /api/agents/{agentId}/drift-summary"
```

---

### Task 5: `GET /api/drift-reports/summary`

**Files:**
- Modify: `orchestrator/internal/api/drift_handlers.go`
- Modify: `orchestrator/internal/api/drift_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `h.verificationOutcomesByPairFleetWide` (Task 2), `driftanalytics.ComputeDriftStats` (Task 1).
- Produces: `h.GetFleetDriftReport(w, r)`.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/drift_handlers_test.go`:
```go
func TestGetFleetDriftReport_BucketsControlsCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('fr-a1', 'FR-A1', 'windows')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('fr-a2', 'FR-A2', 'windows')`)

		// fr-a1/windows-firewall-enabled: drifts (PASS, FAIL) -- currently failing, drifted "now"
		seedVerificationRun(t, pool, "fr-rr-1", "fr-a1", "windows-firewall-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "fr-rr-2", "fr-a1", "windows-firewall-enabled", "fail", "2026-01-02T00:00:00Z")

		// fr-a2/windows-defender-enabled: never drifts (PASS, PASS)
		seedVerificationRun(t, pool, "fr-rr-3", "fr-a2", "windows-defender-enabled", "pass", "2026-01-01T00:00:00Z")
		seedVerificationRun(t, pool, "fr-rr-4", "fr-a2", "windows-defender-enabled", "pass", "2026-01-02T00:00:00Z")

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		h.GetFleetDriftReport(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			TopDrifting  []controlDriftEntry  `json:"topDrifting"`
			NeverDrifted []controlDriftEntry  `json:"neverDrifted"`
			MonthlyTrend []monthlyDriftBucket `json:"monthlyTrend"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.TopDrifting) != 1 || resp.TopDrifting[0].CheckID != "windows-firewall-enabled" {
			t.Errorf("TopDrifting = %+v, want 1 entry for windows-firewall-enabled", resp.TopDrifting)
		}
		if len(resp.NeverDrifted) != 1 || resp.NeverDrifted[0].CheckID != "windows-defender-enabled" {
			t.Errorf("NeverDrifted = %+v, want 1 entry for windows-defender-enabled", resp.NeverDrifted)
		}
		if len(resp.MonthlyTrend) != 1 || resp.MonthlyTrend[0].Month != "2026-01" || resp.MonthlyTrend[0].DriftCount != 1 {
			t.Errorf("MonthlyTrend = %+v, want 1 bucket for 2026-01 with count 1", resp.MonthlyTrend)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetFleetDriftReport" -v`
Expected: FAIL to compile — `GetFleetDriftReport`/`controlDriftEntry`/`monthlyDriftBucket` don't exist yet.

- [ ] **Step 3: Implement**

Add to `orchestrator/internal/api/drift_handlers.go` (add `"time"` to the import block):
```go
// controlDriftEntry is one control's drift stats within the fleet-wide report.
type controlDriftEntry struct {
	AgentID string
	CheckID string
	Stats   driftanalytics.DriftStats
}

// monthlyDriftBucket is the drift-event count for one calendar month.
type monthlyDriftBucket struct {
	Month      string // "2006-01" format
	DriftCount int
}

// GET /api/drift-reports/summary
// Fleet-wide: top-drifting controls, controls that never drifted, controls
// currently drifting within the last 7 days, and a monthly drift-event
// trend. Naming matches Sub-project 5's existing
// GET /api/remediation-reports/summary precedent.
func (h *Handler) GetFleetDriftReport(w http.ResponseWriter, r *http.Request) {
	grouped, err := h.verificationOutcomesByPairFleetWide(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	all := make([]controlDriftEntry, 0, len(grouped))
	monthCounts := map[string]int{}
	for key, outcomes := range grouped {
		stats := driftanalytics.ComputeDriftStats(outcomes)
		all = append(all, controlDriftEntry{AgentID: key.AgentID, CheckID: key.CheckID, Stats: stats})
		for _, ev := range stats.DriftEvents {
			monthCounts[ev.Format("2006-01")]++
		}
	}

	topDrifting := make([]controlDriftEntry, 0)
	neverDrifted := make([]controlDriftEntry, 0)
	driftingWithin7Days := make([]controlDriftEntry, 0)
	now := time.Now().UTC()
	for _, e := range all {
		if e.Stats.DriftCount > 0 {
			topDrifting = append(topDrifting, e)
		}
		if e.Stats.DriftCount == 0 && e.Stats.TotalRuns > 1 {
			neverDrifted = append(neverDrifted, e)
		}
		if e.Stats.CurrentStreakResult == "fail" && e.Stats.CurrentStreakStartedAt != nil && now.Sub(*e.Stats.CurrentStreakStartedAt) <= 7*24*time.Hour {
			driftingWithin7Days = append(driftingWithin7Days, e)
		}
	}
	sort.Slice(topDrifting, func(i, j int) bool { return topDrifting[i].Stats.DriftCount > topDrifting[j].Stats.DriftCount })

	months := make([]monthlyDriftBucket, 0, len(monthCounts))
	for m, c := range monthCounts {
		months = append(months, monthlyDriftBucket{Month: m, DriftCount: c})
	}
	sort.Slice(months, func(i, j int) bool { return months[i].Month < months[j].Month })

	respond(w, map[string]any{
		"topDrifting":         topDrifting,
		"neverDrifted":        neverDrifted,
		"driftingWithin7Days": driftingWithin7Days,
		"monthlyTrend":        months,
	})
}
```

- [ ] **Step 4: Add the route**

In `orchestrator/internal/api/routes.go`, immediately after the line added in Task 4:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/drift-summary", h.GetAgentDriftSummary)
```
add:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/drift-reports/summary", h.GetFleetDriftReport)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the line added in Task 4:
```go
{http.MethodGet, "/api/agents/{agentId}/drift-summary", tierPermission, auth.CanExecuteRemediation},
```
add:
```go
{http.MethodGet, "/api/drift-reports/summary", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetFleetDriftReport|TestRBACMatrix" -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/drift_handlers.go orchestrator/internal/api/drift_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add GET /api/drift-reports/summary"
```

---

### Task 6: Full suite verification

**Files:** none (verification-only task).

- [ ] **Step 1: Run the full orchestrator test suite**

Run: `cd orchestrator && go build ./... && go test ./...`
Expected: builds clean, all tests PASS. If `internal/connector` (or any package unrelated to this plan's changes) fails with a Docker-provider error under full-suite concurrency, re-run that package alone (`go test ./internal/connector/...`) before concluding it's a real regression — this happened once during Sub-project 8 and was confirmed to be testcontainers resource contention, not a code issue.

- [ ] **Step 2: If any test fails, apply superpowers:systematic-debugging**

Do not patch symptoms — find root cause per that skill's process before making any fix.

- [ ] **Step 3: Update project memory**

This step is a reminder for the session, not a code change: once the full suite is green, update `project_endpoint_health_remediation.md` with a new "Sub-project 9 — Drift & Stability Analytics (Phase 6)" section (mirroring the existing Sub-project 6/7/8 entries' level of detail) and refresh `MEMORY.md`'s index line.
