# Continuous BAS Revalidation (Phase 5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An opt-in `continuousValidation` flag on any remediation that, once its fix verification PASSes, automatically re-runs the same ATT&CK technique verification at T+24h/T+7d/T+30d — proving the control is *still* effective, not just effective once.

**Architecture:** Reuse Sub-project 6's generic Job Engine (`internal/jobs`) with a new `Job.Type = "bas_revalidation"`, dispatched via Sub-project 7's existing `ScheduledAt` primitive. A new type-switching dispatch/status pair in `internal/api` lets `internal/jobs.Dispatcher` drive both `batch_remediation` and `bas_revalidation` jobs without any change to `internal/jobs` itself. `dispatchBasRevalidationTarget` is Sub-project 5's `VerifyTechnique` dispatch body, extracted and reused — writes the same `run_id`-onto-`technique_verification_runs` shape, so the existing `continueRemediationFromResult` continuation hook picks up results automatically. No new tables.

**Tech Stack:** Go, PostgreSQL (pgx), chi router — matches every prior sub-project in this initiative.

## Global Constraints

- Purely additive migrations only (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) — no destructive schema changes.
- No new permissions — every changed/new endpoint reuses `auth.CanExecuteRemediation` or the tier-gate already in place on its parent action.
- `continuousValidation` defaults to `false` everywhere — fully opt-in, zero behavior change for existing callers that don't send the field.
- Direct commits to `main`, no branches/PRs, per this repo's established convention.
- Every task follows TDD: write failing test → verify it fails → implement → verify it passes → commit.

---

### Task 1: `continuous_validation` column migration

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (after the `remediation_requests` index block, ~line 1227)

**Interfaces:**
- Produces: `remediation_requests.continuous_validation boolean NOT NULL DEFAULT false`, readable/writable via plain SQL by every later task.

- [ ] **Step 1: Add the migration**

In `orchestrator/internal/db/postgres.go`, immediately after the existing line:
```go
`CREATE INDEX IF NOT EXISTS idx_remediation_requests_verify_run_id ON remediation_requests (verify_run_id) WHERE verify_run_id != ''`,
```
add:
```go
`ALTER TABLE remediation_requests ADD COLUMN IF NOT EXISTS continuous_validation boolean NOT NULL DEFAULT false`,
```

- [ ] **Step 2: Verify the migration runs cleanly**

Run: `cd orchestrator && go build ./...`
Expected: builds with no errors (migration list is just Go string literals — this step catches syntax typos, not DB behavior; DB behavior is verified by Task 2's test, the first to actually write to the column).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/db/postgres.go
git commit -m "feat(db): add remediation_requests.continuous_validation column"
```

---

### Task 2: Thread `continuousValidation` through `ExecuteRemediation` (single-endpoint path)

**Files:**
- Modify: `orchestrator/internal/api/remediation_handlers.go`
- Test: `orchestrator/internal/api/remediation_handlers_test.go` (existing file — add a test)

**Interfaces:**
- Consumes: Task 1's `remediation_requests.continuous_validation` column.
- Produces: `POST /api/agents/{agentId}/remediations` accepts `{"continuousValidation": true}`, written to the new column — read by Task 8's trigger logic.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/remediation_handlers_test.go`:
```go
func TestExecuteRemediation_ContinuousValidation_PersistsFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('cv-h1', 'CV-H1', 'windows')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithRemediationCatalog(cat)

		body, _ := json.Marshal(map[string]any{
			"remediationId":        "enable_windows_firewall",
			"reason":               "test",
			"continuousValidation": true,
		})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "agentId", "cv-h1")
		w := httptest.NewRecorder()
		h.ExecuteRemediation(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var flag bool
		if err := pool.QueryRow(context.Background(), `SELECT continuous_validation FROM remediation_requests WHERE agent_id='cv-h1'`).Scan(&flag); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !flag {
			t.Error("continuous_validation = false, want true")
		}
	})
}
```

Check the top of `remediation_handlers_test.go` for existing imports (`bytes`, `context`, `encoding/json`, `net/http`, `net/http/httptest`, `testing`, `pgxpool`, `remediation`, `scenario`, `ws`) and add any missing ones — this file already has tests exercising `ExecuteRemediation`, so most should already be present.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestExecuteRemediation_ContinuousValidation_PersistsFlag -v`
Expected: FAIL — `continuous_validation` is always `false` because `ExecuteRemediation` doesn't read or write the field yet (compile passes since the column exists from Task 1; the assertion fails).

- [ ] **Step 3: Implement**

In `orchestrator/internal/api/remediation_handlers.go`, in `ExecuteRemediation`:

Change:
```go
	var req struct {
		RemediationID string `json:"remediationId"`
		Reason        string `json:"reason"`
	}
```
to:
```go
	var req struct {
		RemediationID        string `json:"remediationId"`
		Reason               string `json:"reason"`
		ContinuousValidation bool   `json:"continuousValidation"`
	}
```

Change the INSERT:
```go
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, approved_by, reason, rollback_available)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		requestID, entry.ID, agentID, entry.CheckID, int(entry.Tier), remediation.StatusRequested, actorID, approvedBy, req.Reason, entry.SupportsRollback,
	); err != nil {
```
to:
```go
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, approved_by, reason, rollback_available, continuous_validation)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		requestID, entry.ID, agentID, entry.CheckID, int(entry.Tier), remediation.StatusRequested, actorID, approvedBy, req.Reason, entry.SupportsRollback, req.ContinuousValidation,
	); err != nil {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run TestExecuteRemediation_ContinuousValidation_PersistsFlag -v`
Expected: PASS

- [ ] **Step 5: Run the full existing `ExecuteRemediation` test suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/ -run TestExecuteRemediation -v`
Expected: all PASS (existing tests never send `continuousValidation`, so it defaults to `false` via Go's zero value — no behavior change for them).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/remediation_handlers.go orchestrator/internal/api/remediation_handlers_test.go
git commit -m "feat(api): accept continuousValidation on ExecuteRemediation"
```

---

### Task 3: Thread `continuousValidation` through batch remediation (`CreateBatchRemediationJob` + `dispatchBatchRemediationTarget`)

**Files:**
- Modify: `orchestrator/internal/api/job_dispatch.go` (`batchRemediationPayload` struct, both INSERT branches in `dispatchBatchRemediationTarget`)
- Modify: `orchestrator/internal/api/job_handlers.go` (`CreateBatchRemediationJob`)
- Test: `orchestrator/internal/api/job_dispatch_test.go` (existing file — add a test)
- Test: `orchestrator/internal/api/job_handlers_test.go` (existing file — add a test)

**Interfaces:**
- Consumes: Task 1's column.
- Produces: `batchRemediationPayload.ContinuousValidation bool` — a shape Task 4 also reuses.

- [ ] **Step 1: Write the failing test for `dispatchBatchRemediationTarget`**

Add to `orchestrator/internal/api/job_dispatch_test.go`:
```go
func TestDispatchBatchRemediationTarget_ContinuousValidation_PersistsFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jb-cv1', 'JB-CV1', 'windows')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		hub := ws.NewHub()
		startFakeAgent(t, hub, "jb-cv1")

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, hub, eng, "").WithRemediationCatalog(cat)

		payload, _ := json.Marshal(batchRemediationPayload{RemediationID: "enable_windows_firewall", Reason: "test", ContinuousValidation: true})
		job := jobs.Job{ID: "job-cv1", Type: "batch_remediation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-cv1", JobID: "job-cv1", AgentID: "jb-cv1"}

		refID, err := h.dispatchBatchRemediationTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchBatchRemediationTarget: %v", err)
		}
		var flag bool
		if err := pool.QueryRow(context.Background(), `SELECT continuous_validation FROM remediation_requests WHERE id=$1`, refID).Scan(&flag); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !flag {
			t.Error("continuous_validation = false, want true")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestDispatchBatchRemediationTarget_ContinuousValidation_PersistsFlag -v`
Expected: FAIL to compile — `batchRemediationPayload` has no `ContinuousValidation` field yet.

- [ ] **Step 3: Implement in `job_dispatch.go`**

Change:
```go
type batchRemediationPayload struct {
	RemediationID string `json:"remediationId"`
	Reason        string `json:"reason"`
}
```
to:
```go
type batchRemediationPayload struct {
	RemediationID        string `json:"remediationId"`
	Reason               string `json:"reason"`
	ContinuousValidation bool   `json:"continuousValidation"`
}
```

Change the "already compliant" INSERT branch:
```go
		if _, err := h.db.Exec(ctx,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, completed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())`,
			requestID, entry.ID, target.AgentID, entry.CheckID, int(entry.Tier), remediation.StatusCompleted, job.CreatedBy, payload.Reason, entry.SupportsRollback,
		); err != nil {
```
to:
```go
		if _, err := h.db.Exec(ctx,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, continuous_validation, completed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())`,
			requestID, entry.ID, target.AgentID, entry.CheckID, int(entry.Tier), remediation.StatusCompleted, job.CreatedBy, payload.Reason, entry.SupportsRollback, payload.ContinuousValidation,
		); err != nil {
```

Change the normal dispatch INSERT branch:
```go
	if _, err := h.db.Exec(ctx,
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		requestID, entry.ID, target.AgentID, entry.CheckID, int(entry.Tier), remediation.StatusRequested, job.CreatedBy, payload.Reason, entry.SupportsRollback,
	); err != nil {
```
to:
```go
	if _, err := h.db.Exec(ctx,
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, rollback_available, continuous_validation)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		requestID, entry.ID, target.AgentID, entry.CheckID, int(entry.Tier), remediation.StatusRequested, job.CreatedBy, payload.Reason, entry.SupportsRollback, payload.ContinuousValidation,
	); err != nil {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run TestDispatchBatchRemediationTarget -v`
Expected: all PASS, including the new test and the 3 pre-existing `dispatchBatchRemediationTarget` tests (unaffected — they marshal `map[string]string`, which JSON-unmarshals into `batchRemediationPayload` fine, leaving `ContinuousValidation` at its Go zero value `false`).

- [ ] **Step 5: Write the failing test for `CreateBatchRemediationJob`**

Add to `orchestrator/internal/api/job_handlers_test.go`:
```go
func TestCreateBatchRemediationJob_ContinuousValidation_ThreadsIntoPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jh-cv1', 'JH-CV1', 'windows')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId":        "enable_windows_firewall",
			"reason":               "test",
			"agentIds":             []string{"jh-cv1"},
			"continuousValidation": true,
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			JobID string `json:"jobId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)

		var raw []byte
		if err := pool.QueryRow(context.Background(), `SELECT payload FROM jobs WHERE id=$1`, resp.JobID).Scan(&raw); err != nil {
			t.Fatalf("query job: %v", err)
		}
		var payload batchRemediationPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if !payload.ContinuousValidation {
			t.Error("payload.ContinuousValidation = false, want true")
		}
	})
}
```

Check `job_handlers_test.go`'s existing imports for `bytes`, `context`, `encoding/json`, `net/http`, `net/http/httptest`, `auth`, `jobs`, `remediation`, `scenario`, `ws`, `pgxpool` and add any missing.

- [ ] **Step 6: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestCreateBatchRemediationJob_ContinuousValidation_ThreadsIntoPayload -v`
Expected: FAIL — the handler's request struct has no `continuousValidation` field yet and the payload is marshaled from an inline `map[string]string`, which can't carry a bool.

- [ ] **Step 7: Implement in `job_handlers.go`**

In `CreateBatchRemediationJob`, change:
```go
	var req struct {
		RemediationID string   `json:"remediationId"`
		Reason        string   `json:"reason"`
		AgentIDs      []string `json:"agentIds"`
		ScheduledAt   string   `json:"scheduledAt"`
	}
```
to:
```go
	var req struct {
		RemediationID        string   `json:"remediationId"`
		Reason               string   `json:"reason"`
		AgentIDs             []string `json:"agentIds"`
		ScheduledAt          string   `json:"scheduledAt"`
		ContinuousValidation bool     `json:"continuousValidation"`
	}
```

Change:
```go
	payload, err := json.Marshal(map[string]string{"remediationId": entry.ID, "reason": req.Reason})
```
to:
```go
	payload, err := json.Marshal(batchRemediationPayload{RemediationID: entry.ID, Reason: req.Reason, ContinuousValidation: req.ContinuousValidation})
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run TestCreateBatchRemediationJob -v`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/api/job_dispatch.go orchestrator/internal/api/job_dispatch_test.go orchestrator/internal/api/job_handlers.go orchestrator/internal/api/job_handlers_test.go
git commit -m "feat(api): thread continuousValidation through batch remediation jobs"
```

---

### Task 4: Thread `continuousValidation` through `CreateJobSchedule` (recurring path)

**Files:**
- Modify: `orchestrator/internal/api/schedule_handlers.go`
- Test: `orchestrator/internal/api/schedule_handlers_test.go` (existing file — add a test)

**Interfaces:**
- Consumes: Task 3's `batchRemediationPayload` (unchanged shape, reused here).
- Produces: every job `spawnDueSchedules` spawns from a continuous-validation-enabled schedule carries the flag.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/schedule_handlers_test.go`:
```go
func TestCreateJobSchedule_ContinuousValidation_ThreadsIntoPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('sh-cv1', 'SH-CV1', 'windows')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId":        "enable_windows_firewall",
			"reason":               "test",
			"agentIds":             []string{"sh-cv1"},
			"dayOfWeek":            1,
			"timeOfDay":            "09:00",
			"continuousValidation": true,
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateJobSchedule(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ScheduleID string `json:"scheduleId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)

		var raw []byte
		if err := pool.QueryRow(context.Background(), `SELECT payload FROM job_schedules WHERE id=$1`, resp.ScheduleID).Scan(&raw); err != nil {
			t.Fatalf("query schedule: %v", err)
		}
		var payload batchRemediationPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if !payload.ContinuousValidation {
			t.Error("payload.ContinuousValidation = false, want true")
		}
	})
}
```

Check existing imports in `schedule_handlers_test.go` and add any missing (`bytes`, `context`, `encoding/json`, `net/http`, `net/http/httptest`, `auth`, `jobs`, `remediation`, `scenario`, `ws`, `pgxpool`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run TestCreateJobSchedule_ContinuousValidation_ThreadsIntoPayload -v`
Expected: FAIL — no `continuousValidation` field on the request struct, payload still marshaled from a `map[string]string`.

- [ ] **Step 3: Implement in `schedule_handlers.go`**

Change:
```go
	var req struct {
		RemediationID string   `json:"remediationId"`
		Reason        string   `json:"reason"`
		AgentIDs      []string `json:"agentIds"`
		DayOfWeek     int      `json:"dayOfWeek"`
		TimeOfDay     string   `json:"timeOfDay"`
		Timezone      string   `json:"timezone"`
	}
```
to:
```go
	var req struct {
		RemediationID        string   `json:"remediationId"`
		Reason               string   `json:"reason"`
		AgentIDs             []string `json:"agentIds"`
		DayOfWeek            int      `json:"dayOfWeek"`
		TimeOfDay            string   `json:"timeOfDay"`
		Timezone             string   `json:"timezone"`
		ContinuousValidation bool     `json:"continuousValidation"`
	}
```

Change:
```go
	payload, err := json.Marshal(map[string]string{"remediationId": entry.ID, "reason": req.Reason})
```
to:
```go
	payload, err := json.Marshal(batchRemediationPayload{RemediationID: entry.ID, Reason: req.Reason, ContinuousValidation: req.ContinuousValidation})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run TestCreateJobSchedule -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/schedule_handlers.go orchestrator/internal/api/schedule_handlers_test.go
git commit -m "feat(api): thread continuousValidation through recurring job schedules"
```

---

### Task 5: `dispatchBasRevalidationTarget` + `basRevalidationTargetStatus`

**Files:**
- Create: `orchestrator/internal/api/bas_revalidation_dispatch.go`
- Create: `orchestrator/internal/api/bas_revalidation_dispatch_test.go`

**Interfaces:**
- Consumes: `jobs.Job`, `jobs.JobTarget` (Sub-project 6), `h.dispatchTechniqueVerification` (Sub-project 5, unchanged), `technique_verification_runs` table (Sub-project 5).
- Produces: `basRevalidationPayload` struct (consumed by Task 8's trigger logic); `dispatchBasRevalidationTarget(ctx, job, target) (refID string, err error)`; `basRevalidationTargetStatus(ctx, jobType, refID) (state, errText string, terminal bool)` (both consumed by Task 6's type-switch).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/bas_revalidation_dispatch_test.go`:
```go
package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestDispatchBasRevalidationTarget_Dispatches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('bv-t1', 'BV-T1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-bv-t1', 'enable_windows_firewall', 'bv-t1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		hub := ws.NewHub()
		startFakeAgent(t, hub, "bv-t1")

		h := New(pool, hub, eng, "")

		payload, _ := json.Marshal(basRevalidationPayload{
			RequestID: "rr-bv-t1", AgentID: "bv-t1", CheckID: "windows-firewall-enabled", TechniqueID: "T1082",
		})
		job := jobs.Job{ID: "job-bv1", Type: "bas_revalidation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-bv1", JobID: "job-bv1", AgentID: "bv-t1"}

		refID, err := h.dispatchBasRevalidationTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchBasRevalidationTarget: %v", err)
		}
		if refID == "" {
			t.Fatal("refID is empty")
		}
		var status, runID, requestID string
		if err := pool.QueryRow(context.Background(),
			`SELECT status, run_id, request_id FROM technique_verification_runs WHERE id=$1`, refID,
		).Scan(&status, &runID, &requestID); err != nil {
			t.Fatalf("query technique_verification_runs: %v", err)
		}
		if status != "dispatched" || runID == "" {
			t.Errorf("status=%q runID=%q, want status=dispatched and a non-empty runID", status, runID)
		}
		if requestID != "rr-bv-t1" {
			t.Errorf("request_id = %q, want rr-bv-t1", requestID)
		}
	})
}

func TestDispatchBasRevalidationTarget_AgentNotConnected_Errors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('bv-t2', 'BV-T2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-bv-t2', 'enable_windows_firewall', 'bv-t2', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")

		h := New(pool, ws.NewHub(), eng, "") // no fake agent connected

		payload, _ := json.Marshal(basRevalidationPayload{
			RequestID: "rr-bv-t2", AgentID: "bv-t2", CheckID: "windows-firewall-enabled", TechniqueID: "T1082",
		})
		job := jobs.Job{ID: "job-bv2", Type: "bas_revalidation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-bv2", JobID: "job-bv2", AgentID: "bv-t2"}

		if _, err := h.dispatchBasRevalidationTarget(context.Background(), job, target); err == nil {
			t.Fatal("expected an error, agent not connected")
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM technique_verification_runs WHERE request_id='rr-bv-t2'`).Scan(&status)
		if status != "error" {
			t.Errorf("status = %q, want error", status)
		}
	})
}

func TestBasRevalidationTargetStatus_MapsCheckResultToTargetState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('bv-t3', 'BV-T3')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-bv-t3', 'enable_windows_firewall', 'bv-t3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)

		cases := []struct {
			status       string
			wantState    string
			wantTerminal bool
		}{
			{"pass", jobs.TargetStateCompleted, true},
			{"fail", jobs.TargetStateFailed, true},
			{"error", jobs.TargetStateFailed, true},
			{"blocked", jobs.TargetStateFailed, true},
			{"skipped", jobs.TargetStateFailed, true},
			{"requested", jobs.TargetStateDispatched, false},
			{"dispatched", jobs.TargetStateDispatched, false},
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		for i, c := range cases {
			id := "tvr-bv-t3-" + string(rune('a'+i))
			mustExecAPI(t, pool, `
				INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by)
				VALUES ($1, 'rr-bv-t3', 'bv-t3', 'windows-firewall-enabled', 'T1082', $2, 'user-1')`, id, c.status)

			state, _, terminal := h.basRevalidationTargetStatus(context.Background(), "bas_revalidation", id)
			if state != c.wantState || terminal != c.wantTerminal {
				t.Errorf("status=%q: state=%q terminal=%v, want state=%q terminal=%v", c.status, state, terminal, c.wantState, c.wantTerminal)
			}
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestDispatchBasRevalidationTarget|TestBasRevalidationTargetStatus" -v`
Expected: FAIL to compile — `basRevalidationPayload`, `dispatchBasRevalidationTarget`, `basRevalidationTargetStatus` don't exist yet.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/api/bas_revalidation_dispatch.go`:
```go
package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/models"
)

// basRevalidationPayload is the Job.Payload shape for Type="bas_revalidation".
// Self-contained -- no re-lookup of remediation_requests needed at dispatch
// time, since a bas_revalidation Job is created with everything it needs
// (see handleRemediationVerifyResult's trigger logic).
type basRevalidationPayload struct {
	RequestID   string `json:"requestId"`
	AgentID     string `json:"agentId"`
	CheckID     string `json:"checkId"`
	TechniqueID string `json:"techniqueId"`
}

// dispatchBasRevalidationTarget is Sub-project 5's VerifyTechnique dispatch
// body, extracted and reused: it inserts a technique_verification_runs row
// and calls the unchanged dispatchTechniqueVerification. Because it writes
// run_id onto that row exactly as VerifyTechnique already does,
// continueRemediationFromResult's existing technique_verification_runs
// branch picks up the eventual scenario result with no new code -- this
// function deliberately does NOT call VerifyTechnique's per-request_id
// uniqueness guard (that guard lives in VerifyTechnique's own handler body,
// not the schema), so multiple rows correctly accumulate per request over
// the three revalidation cycles.
func (h *Handler) dispatchBasRevalidationTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	var payload basRevalidationPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return "", err
	}

	techVerifyID := newID()
	if _, err := h.db.Exec(ctx,
		`INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by)
		 VALUES ($1,$2,$3,$4,$5,'requested',$6)`,
		techVerifyID, payload.RequestID, target.AgentID, payload.CheckID, payload.TechniqueID, job.CreatedBy,
	); err != nil {
		return "", err
	}

	runID, sent, err := h.dispatchTechniqueVerification(ctx, target.AgentID, payload.TechniqueID)
	if err != nil {
		h.db.Exec(ctx, `UPDATE technique_verification_runs SET status='error', reason=$1 WHERE id=$2`, err.Error(), techVerifyID)
		return "", err
	}
	if !sent {
		h.db.Exec(ctx, `UPDATE technique_verification_runs SET status='error', reason='agent not connected' WHERE id=$1`, techVerifyID)
		return "", errors.New("agent not connected")
	}
	h.db.Exec(ctx,
		`UPDATE technique_verification_runs SET status='dispatched', run_id=$1, dispatched_at=NOW() WHERE id=$2`,
		runID, techVerifyID)
	return techVerifyID, nil
}

// basRevalidationTargetStatus polls the technique_verification_runs row
// (refID = its own id, the value dispatchBasRevalidationTarget returned as
// refID -- not run_id). Only models.ResultPass counts as job-target
// success; fail/error/blocked/skipped are all terminal-but-failed, reusing
// Sub-project 5's existing 5-value taxonomy without adding a 6th.
func (h *Handler) basRevalidationTargetStatus(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	var status, reason string
	if err := h.db.QueryRow(ctx, `SELECT status, reason FROM technique_verification_runs WHERE id=$1`, refID).Scan(&status, &reason); err != nil {
		return jobs.TargetStateFailed, "technique verification run not found: " + err.Error(), true
	}
	switch status {
	case string(models.ResultPass):
		return jobs.TargetStateCompleted, "", true
	case string(models.ResultFail), string(models.ResultError), string(models.ResultBlocked), string(models.ResultSkipped):
		return jobs.TargetStateFailed, reason, true
	default: // "requested", "dispatched"
		return jobs.TargetStateDispatched, "", false
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestDispatchBasRevalidationTarget|TestBasRevalidationTargetStatus" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/bas_revalidation_dispatch.go orchestrator/internal/api/bas_revalidation_dispatch_test.go
git commit -m "feat(jobs): add bas_revalidation dispatch and status functions"
```

---

### Task 6: Type-switching `dispatchJobTarget`/`statusForJobTarget`, wired into `WithJobsDispatcher`

**Files:**
- Modify: `orchestrator/internal/api/job_dispatch.go`
- Test: `orchestrator/internal/api/job_dispatch_test.go`

**Interfaces:**
- Consumes: `h.dispatchBatchRemediationTarget`/`h.batchRemediationTargetStatus` (Sub-project 6, unchanged), `h.dispatchBasRevalidationTarget`/`h.basRevalidationTargetStatus` (Task 5).
- Produces: `h.dispatchJobTarget`, `h.statusForJobTarget` — the two functions `WithJobsDispatcher` now registers with `jobs.Dispatcher`.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/job_dispatch_test.go`:
```go
func TestDispatchJobTarget_RoutesByJobType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jt-r1', 'JT-R1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-jt-r1', 'enable_windows_firewall', 'jt-r1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		hub := ws.NewHub()
		startFakeAgent(t, hub, "jt-r1")

		h := New(pool, hub, eng, "")

		payload, _ := json.Marshal(basRevalidationPayload{
			RequestID: "rr-jt-r1", AgentID: "jt-r1", CheckID: "windows-firewall-enabled", TechniqueID: "T1082",
		})
		job := jobs.Job{ID: "job-jt1", Type: "bas_revalidation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-jt1", JobID: "job-jt1", AgentID: "jt-r1"}

		refID, err := h.dispatchJobTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchJobTarget: %v", err)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM technique_verification_runs WHERE id=$1`, refID).Scan(&status)
		if status != "dispatched" {
			t.Errorf("status = %q, want dispatched (should have routed to dispatchBasRevalidationTarget)", status)
		}

		state, _, terminal := h.statusForJobTarget(context.Background(), "bas_revalidation", refID)
		if terminal {
			t.Error("terminal = true, want false (status is still 'dispatched')")
		}
		if state != jobs.TargetStateDispatched {
			t.Errorf("state = %q, want dispatched", state)
		}
	})
}

func TestDispatchJobTarget_UnknownType_Errors(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		job := jobs.Job{ID: "job-unk", Type: "does_not_exist", Payload: []byte(`{}`), CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-unk", JobID: "job-unk", AgentID: "agent-unk"}
		if _, err := h.dispatchJobTarget(context.Background(), job, target); err == nil {
			t.Fatal("expected an error for an unknown job type")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestDispatchJobTarget" -v`
Expected: FAIL to compile — `dispatchJobTarget`/`statusForJobTarget` don't exist yet.

- [ ] **Step 3: Implement**

In `orchestrator/internal/api/job_dispatch.go`, add `"fmt"` to the import block, then add:
```go
// dispatchJobTarget routes to the correct dispatch function for job.Type.
// internal/jobs.Dispatcher knows nothing about what any job type actually
// does -- this switch is the one place that knowledge lives.
func (h *Handler) dispatchJobTarget(ctx context.Context, job jobs.Job, target jobs.JobTarget) (refID string, err error) {
	switch job.Type {
	case "batch_remediation":
		return h.dispatchBatchRemediationTarget(ctx, job, target)
	case "bas_revalidation":
		return h.dispatchBasRevalidationTarget(ctx, job, target)
	default:
		return "", fmt.Errorf("unknown job type %q", job.Type)
	}
}

// statusForJobTarget mirrors dispatchJobTarget's routing for status polling.
func (h *Handler) statusForJobTarget(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool) {
	switch jobType {
	case "batch_remediation":
		return h.batchRemediationTargetStatus(ctx, jobType, refID)
	case "bas_revalidation":
		return h.basRevalidationTargetStatus(ctx, jobType, refID)
	default:
		return jobs.TargetStateFailed, "unknown job type", true
	}
}
```

Change `WithJobsDispatcher`:
```go
func (h *Handler) WithJobsDispatcher(store *jobs.Store, dispatcher *jobs.Dispatcher) *Handler {
	h.jobsStore = store
	dispatcher.SetDispatch(h.dispatchBatchRemediationTarget)
	dispatcher.SetStatus(h.batchRemediationTargetStatus)
	return h
}
```
to:
```go
func (h *Handler) WithJobsDispatcher(store *jobs.Store, dispatcher *jobs.Dispatcher) *Handler {
	h.jobsStore = store
	dispatcher.SetDispatch(h.dispatchJobTarget)
	dispatcher.SetStatus(h.statusForJobTarget)
	return h
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestDispatchJobTarget" -v`
Expected: PASS

- [ ] **Step 5: Run the full package test suite to confirm no regression on existing batch_remediation flow**

Run: `cd orchestrator && go test ./internal/api/ -run "TestDispatchBatchRemediationTarget|TestBatchRemediationTargetStatus|TestCreateBatchRemediationJob" -v`
Expected: all PASS — `WithJobsDispatcher` now registers the switches instead of the batch-remediation functions directly, but every `batch_remediation` job still routes to the exact same code.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/job_dispatch.go orchestrator/internal/api/job_dispatch_test.go
git commit -m "feat(api): add type-switching job dispatch to support multiple job types"
```

---

### Task 7: Trigger logic — create the 3-Job revalidation chain on fix-verification PASS

**Files:**
- Modify: `orchestrator/internal/api/remediation_continuation.go` (`handleRemediationVerifyResult`)
- Test: `orchestrator/internal/api/remediation_continuation_test.go` (existing file — add tests)

**Interfaces:**
- Consumes: `h.EligibleForBASVerification` (Sub-project 5, unchanged), `h.findStepByCheckID` (Sub-project 5, unchanged), `h.jobsStore.CreateBatchScheduled` (Sub-project 7, unchanged), `basRevalidationPayload` (Task 5).
- Produces: 3 `bas_revalidation` `jobs` rows per eligible, opted-in, PASSed remediation.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/remediation_continuation_test.go`:
```go
func TestHandleRemediationVerifyResult_ContinuousValidationEnabled_CreatesThreeRevalidationJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('cv-tr1', 'CV-TR1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason, continuous_validation)
			VALUES ('rr-cv-tr1', 'enable_windows_firewall', 'cv-tr1', 'windows-firewall-enabled', 1, 'verifying', 'run-cv-tr1', 'user-1', 'test', true)`)

		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.handleRemediationVerifyResult(req, "rr-cv-tr1", true)

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'='rr-cv-tr1'`,
		).Scan(&count); err != nil {
			t.Fatalf("query jobs: %v", err)
		}
		if count != 3 {
			t.Errorf("bas_revalidation job count = %d, want 3", count)
		}

		rows, err := pool.Query(context.Background(),
			`SELECT scheduled_at FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'='rr-cv-tr1' ORDER BY scheduled_at`)
		if err != nil {
			t.Fatalf("query scheduled_at: %v", err)
		}
		defer rows.Close()
		var scheduledAts []time.Time
		for rows.Next() {
			var at time.Time
			rows.Scan(&at)
			scheduledAts = append(scheduledAts, at)
		}
		if len(scheduledAts) != 3 {
			t.Fatalf("got %d scheduled_at values, want 3", len(scheduledAts))
		}
		gap1 := scheduledAts[1].Sub(scheduledAts[0])
		gap2 := scheduledAts[2].Sub(scheduledAts[1])
		if gap1 < 6*24*time.Hour || gap2 < 22*24*time.Hour {
			t.Errorf("gaps between scheduled_at values = %v, %v, want roughly 6d and 23d (24h -> 7d -> 30d)", gap1, gap2)
		}
	})
}

func TestHandleRemediationVerifyResult_ContinuousValidationDisabled_NoRevalidationJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('cv-tr2', 'CV-TR2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason, continuous_validation)
			VALUES ('rr-cv-tr2', 'enable_windows_firewall', 'cv-tr2', 'windows-firewall-enabled', 1, 'verifying', 'run-cv-tr2', 'user-1', 'test', false)`)

		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.handleRemediationVerifyResult(req, "rr-cv-tr2", true)

		var count int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'='rr-cv-tr2'`).Scan(&count)
		if count != 0 {
			t.Errorf("bas_revalidation job count = %d, want 0 (continuous_validation is false)", count)
		}
	})
}

func TestHandleRemediationVerifyResult_ContinuousValidationEnabled_IneligibleCheck_NoRevalidationJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('cv-tr3', 'CV-TR3', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, verify_run_id, requested_by, reason, continuous_validation)
			VALUES ('rr-cv-tr3', 'enable_bitlocker', 'cv-tr3', 'windows-bitlocker-enabled', 4, 'verifying', 'run-cv-tr3', 'user-1', 'test', true)`)

		// engine has no scenario registered at all -- findStepByCheckID finds
		// nothing, EligibleForBASVerification returns false.
		eng := scenario.NewEngine(t.TempDir())
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.handleRemediationVerifyResult(req, "rr-cv-tr3", true)

		var count int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'='rr-cv-tr3'`).Scan(&count)
		if count != 0 {
			t.Errorf("bas_revalidation job count = %d, want 0 (check has no mapped technique_id)", count)
		}
	})
}
```

Add `"time"` and `"github.com/audspect/bas/internal/jobs"` to `remediation_continuation_test.go`'s imports if not already present (check the file's existing import block first).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestHandleRemediationVerifyResult_ContinuousValidation" -v`
Expected: FAIL — `handleRemediationVerifyResult` doesn't read `continuous_validation` or create any jobs yet, so all three assertions on job count come back 0/wrong for the first test.

- [ ] **Step 3: Implement**

In `orchestrator/internal/api/remediation_continuation.go`, add `"encoding/json"` and `"time"` to the import block, then change `handleRemediationVerifyResult`:

```go
func (h *Handler) handleRemediationVerifyResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy, checkID string
	var continuousValidation bool
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by, check_id, continuous_validation FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy, &checkID, &continuousValidation)

	status := remediation.StatusCompleted
	outcome := "completed"
	if !passed {
		status = remediation.StatusVerificationFailed
		outcome = "verification_failed"
	}
	h.db.Exec(ctx,
		`UPDATE remediation_requests SET status=$1, verification_completed_at=NOW(), completed_at=NOW() WHERE id=$2`,
		status, requestID)
	h.auditLogAs(r, requestedBy, "remediation."+status, requestID,
		map[string]any{"remediationId": remediationID, "agentId": agentID}, outcome)

	if passed && continuousValidation && h.jobsStore != nil && h.EligibleForBASVerification(checkID) {
		h.scheduleRevalidationChain(ctx, requestID, agentID, checkID, requestedBy)
	}
}

// scheduleRevalidationChain creates the three bas_revalidation Jobs
// (T+24h/T+7d/T+30d) for one just-verified remediation. Each is a
// singleton-target Job -- a revalidation is inherently one endpoint
// re-checking one control, not a fleet-wide batch.
func (h *Handler) scheduleRevalidationChain(ctx context.Context, requestID, agentID, checkID, requestedBy string) {
	step, found := h.findStepByCheckID(checkID)
	if !found {
		return
	}
	payload, err := json.Marshal(basRevalidationPayload{
		RequestID: requestID, AgentID: agentID, CheckID: checkID, TechniqueID: step.TechniqueID,
	})
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, delay := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour} {
		at := now.Add(delay)
		h.jobsStore.CreateBatchScheduled(ctx, "bas_revalidation", payload, requestedBy, []string{agentID}, &at)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestHandleRemediationVerifyResult" -v`
Expected: all PASS, including pre-existing `handleRemediationVerifyResult` tests (they don't set `continuous_validation`, so it defaults to the column's `false` default — no new jobs, no behavior change).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/remediation_continuation.go orchestrator/internal/api/remediation_continuation_test.go
git commit -m "feat(api): auto-schedule 24h/7d/30d BAS revalidation chain on verified remediation"
```

---

### Task 8: Cancel pending revalidations on rollback confirmation

**Files:**
- Modify: `orchestrator/internal/api/remediation_continuation.go` (`handleRemediationRollbackVerifyResult`)
- Test: `orchestrator/internal/api/remediation_continuation_test.go`

**Interfaces:**
- Consumes: `h.jobsStore.CancelJob` (Sub-project 6, unchanged).
- Produces: every non-terminal `bas_revalidation` job for a rolled-back request transitions to `cancelled`.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/remediation_continuation_test.go`:
```go
func TestHandleRemediationRollbackVerifyResult_Confirmed_CancelsPendingRevalidations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('rb-cv1', 'RB-CV1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, continuous_validation)
			VALUES ('rr-rb-cv1', 'enable_windows_firewall', 'rb-cv1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true)`)

		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		payload, _ := json.Marshal(basRevalidationPayload{RequestID: "rr-rb-cv1", AgentID: "rb-cv1", CheckID: "windows-firewall-enabled", TechniqueID: "T1082"})
		future := time.Now().UTC().Add(24 * time.Hour)
		job, err := jobsStore.CreateBatchScheduled(context.Background(), "bas_revalidation", payload, "user-1", []string{"rb-cv1"}, &future)
		if err != nil {
			t.Fatalf("CreateBatchScheduled: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		// passed=false: the check fails again, confirming the rollback took effect.
		h.handleRemediationRollbackVerifyResult(req, "rr-rb-cv1", false)

		got, err := jobsStore.Get(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("Get job: %v", err)
		}
		if got.State != jobs.JobStateCancelled {
			t.Errorf("job.State = %q, want cancelled", got.State)
		}
	})
}
```

Check `remediation_continuation_test.go`'s imports for `"github.com/audspect/bas/internal/jobs"` (added in Task 7) — reused here.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/ -run "TestHandleRemediationRollbackVerifyResult_Confirmed_CancelsPendingRevalidations" -v`
Expected: FAIL — `handleRemediationRollbackVerifyResult` doesn't touch `jobs` at all yet, so the job stays `requested`.

- [ ] **Step 3: Implement**

In `orchestrator/internal/api/remediation_continuation.go`, change `handleRemediationRollbackVerifyResult`:

```go
func (h *Handler) handleRemediationRollbackVerifyResult(r *http.Request, requestID string, passed bool) {
	ctx := r.Context()
	var remediationID, agentID, requestedBy string
	h.db.QueryRow(ctx, `SELECT remediation_id, agent_id, requested_by FROM remediation_requests WHERE id=$1`, requestID).
		Scan(&remediationID, &agentID, &requestedBy)

	status := "completed"
	outcome := "ok"
	if passed {
		status = "failed"
		outcome = "rollback ran but the control is still active -- verify manually"
	}
	h.db.Exec(ctx, `UPDATE remediation_requests SET rollback_status=$1 WHERE id=$2`, status, requestID)
	h.auditLogAs(r, requestedBy, "remediation.rollback_"+status, requestID,
		map[string]any{"remediationId": remediationID, "agentId": agentID}, outcome)

	if status == "completed" && h.jobsStore != nil {
		h.cancelPendingRevalidations(ctx, requestID)
	}
}

// cancelPendingRevalidations cancels every still-pending bas_revalidation
// job for requestID -- revalidating a control that was just deliberately
// reverted would be actively misleading, not merely wasteful.
func (h *Handler) cancelPendingRevalidations(ctx context.Context, requestID string) {
	rows, err := h.db.Query(ctx,
		`SELECT id FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'=$1
		 AND state NOT IN ('completed','partial','failed','cancelled')`, requestID)
	if err != nil {
		return
	}
	defer rows.Close()
	var jobIDs []string
	for rows.Next() {
		var jobID string
		if rows.Scan(&jobID) == nil {
			jobIDs = append(jobIDs, jobID)
		}
	}
	for _, jobID := range jobIDs {
		h.jobsStore.CancelJob(ctx, jobID)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/ -run "TestHandleRemediationRollbackVerifyResult" -v`
Expected: all PASS, including pre-existing rollback-verify tests (they don't seed any `bas_revalidation` jobs, so `cancelPendingRevalidations` finds nothing and is a no-op).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/remediation_continuation.go orchestrator/internal/api/remediation_continuation_test.go
git commit -m "feat(api): cancel pending BAS revalidations when a remediation is rolled back"
```

---

### Task 9: `GET /api/remediation-requests/{requestId}/revalidations`

**Files:**
- Create: `orchestrator/internal/api/revalidations_handler.go`
- Create: `orchestrator/internal/api/revalidations_handler_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `h.jobsStore.Get`, `h.jobsStore.ListTargets` (Sub-project 6, unchanged).
- Produces: a read-only view of one remediation request's revalidation chain.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/revalidations_handler_test.go`:
```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetRemediationRevalidations_ReturnsChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('rv-h1', 'RV-H1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, continuous_validation)
			VALUES ('rr-rv-h1', 'enable_windows_firewall', 'rv-h1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test', true)`)

		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		payload, _ := json.Marshal(basRevalidationPayload{RequestID: "rr-rv-h1", AgentID: "rv-h1", CheckID: "windows-firewall-enabled", TechniqueID: "T1082"})
		at := time.Now().UTC().Add(24 * time.Hour)
		if _, err := jobsStore.CreateBatchScheduled(context.Background(), "bas_revalidation", payload, "user-1", []string{"rv-h1"}, &at); err != nil {
			t.Fatalf("CreateBatchScheduled: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "rr-rv-h1")
		w := httptest.NewRecorder()
		h.GetRemediationRevalidations(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var resp struct {
			Revalidations []map[string]any `json:"revalidations"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Revalidations) != 1 {
			t.Fatalf("got %d revalidations, want 1", len(resp.Revalidations))
		}
	})
}

func TestGetRemediationRevalidations_NoChain_ReturnsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "requestId", "rr-does-not-exist")
		w := httptest.NewRecorder()
		h.GetRemediationRevalidations(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Revalidations []map[string]any `json:"revalidations"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if len(resp.Revalidations) != 0 {
			t.Errorf("got %d revalidations, want 0", len(resp.Revalidations))
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetRemediationRevalidations" -v`
Expected: FAIL to compile — `GetRemediationRevalidations` doesn't exist yet.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/api/revalidations_handler.go`:
```go
package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// revalidationEntry is one bas_revalidation Job in a request's chain,
// paired with its single target's technique_verification_runs detail.
type revalidationEntry struct {
	JobID       string     `json:"jobId"`
	State       string     `json:"state"`
	ScheduledAt *time.Time `json:"scheduledAt,omitempty"`
	TargetState string     `json:"targetState"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason"`
}

// GET /api/remediation-requests/{requestId}/revalidations
// Lists every bas_revalidation job tied to requestId, letting an operator
// see e.g. "24h: pass, 7d: pending, 30d: not yet scheduled" for one
// remediation. Read-level, matches GetJob's precedent -- no new permission.
func (h *Handler) GetRemediationRevalidations(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT id, state, scheduled_at FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'=$1 ORDER BY scheduled_at`, requestID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	entries := []revalidationEntry{}
	for rows.Next() {
		var jobID, state string
		var scheduledAt *time.Time
		if err := rows.Scan(&jobID, &state, &scheduledAt); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		entry := revalidationEntry{JobID: jobID, State: state, ScheduledAt: scheduledAt}
		targets, err := h.jobsStore.ListTargets(r.Context(), jobID)
		if err == nil && len(targets) == 1 {
			entry.TargetState = targets[0].State
			if targets[0].RefID != "" {
				h.db.QueryRow(r.Context(), `SELECT status, reason FROM technique_verification_runs WHERE id=$1`, targets[0].RefID).Scan(&entry.Status, &entry.Reason)
			}
		}
		entries = append(entries, entry)
	}
	respond(w, map[string]any{"revalidations": entries})
}
```

`entries` is initialized as `[]revalidationEntry{}` rather than left as a nil slice, so `json.Marshal` emits `"revalidations": []` for a request with no chain (Task 9's second test) instead of `"revalidations": null`.

- [ ] **Step 4: Add the route**

In `orchestrator/internal/api/routes.go`, immediately after the existing line:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/remediation-requests/{requestId}/rollback", h.RollbackRemediation)
```
Wait — place it instead next to the other `remediation-requests` routes for locality. Add immediately after:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/remediation-requests/{requestId}", h.GetRemediation)
```
add:
```go
r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/remediation-requests/{requestId}/revalidations", h.GetRemediationRevalidations)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing line:
```go
{http.MethodGet, "/api/remediation-requests/{requestId}", tierPermission, auth.CanExecuteRemediation},
```
add:
```go
{http.MethodGet, "/api/remediation-requests/{requestId}/revalidations", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetRemediationRevalidations|TestRBACMatrix" -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/revalidations_handler.go orchestrator/internal/api/revalidations_handler_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add GET /api/remediation-requests/{requestId}/revalidations"
```

---

### Task 10: Full suite verification

**Files:** none (verification-only task).

- [ ] **Step 1: Run the full orchestrator test suite**

Run: `cd orchestrator && go build ./... && go test ./...`
Expected: builds clean, all tests PASS — including every pre-existing test across Sub-projects 1-7, confirming this sub-project introduced no regression.

- [ ] **Step 2: If any test fails, apply superpowers:systematic-debugging**

Do not patch symptoms — find root cause per that skill's process before making any fix. Common candidates given this plan's own recurring gotchas: `timestamptz` microsecond-precision mismatches in any test asserting `ScheduledAt` equality (fix: `.Truncate(time.Microsecond)` on the locally-generated value), or an accidentally-still-present unused import from Task 9's implementation note.

- [ ] **Step 3: Update project memory**

This step is a reminder for the session, not a code change: once the full suite is green, update `project_endpoint_health_remediation.md` with a new "Sub-project 8 — Continuous BAS Revalidation (Phase 5)" section (mirroring the existing Sub-project 6/7 entries' level of detail) and refresh `MEMORY.md`'s index line.
