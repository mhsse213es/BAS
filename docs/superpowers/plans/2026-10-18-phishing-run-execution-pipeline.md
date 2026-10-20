# Phishing Scenario Execution, Persistence & Reporting Pipeline (Vertical Slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Phishing BAS Mastery a real, authorized, persisted run lifecycle — API trigger → dispatch/evaluate → DB persistence → client-readable report — proven end-to-end for exactly one scenario (PH-DET-002), not a report-formatting exercise over invented data.

**Architecture:** Mirror `internal/emailgwrun`/`internal/db/emailgwrun_store.go`/`internal/api/emailgwrun_executor.go`/`internal/api/emailgwrun_handlers.go` exactly in shape (same Status enum, same id/result/error/initiated_by/started_at/completed_at columns, same idempotent `CREATE TABLE IF NOT EXISTS` schema-ensure convention, same `auth.RequirePermission(auth.CanRunScenario)` gate) — this is the proven, existing run-lifecycle template for a real-evidence BAS scenario, not a new engine. The one genuinely new piece is a **scenario executor registry** (`internal/phishingrun/registry.go`): `phishcatalog.Scenario.MappedImplementation` is plain documentation text today, not a callable reference, so nothing currently lets an API call "run PH-DET-002" — this registry is what makes a scenario executable, and its absence from the registry is exactly what keeps the other 43 catalog entries (including overlap decisions and PH-ID-004/005's heuristics) from appearing executable merely because they exist in the catalog.

**Tech Stack:** Go, `pgx/v5` (Postgres), `chi/v5` router, existing `internal/phishval`/`internal/phishbridge`/`internal/phishcatalog`/`internal/auth`/`internal/db` packages.

**Spec:** This plan's own stages 1–6 come directly from the user's own pasted implementation plan (this conversation, 2026-10-18) choosing "Option 1: build the full phishing scenario execution, persistence, and reporting pipeline," plus its non-negotiable acceptance criteria reproduced in Global Constraints below.

## Global Constraints

- Reuse `internal/emailgwrun`'s lifecycle shape (Status: pending/running/completed/failed/partial; columns id/scenario_id/result/error/initiated_by/started_at/completed_at) — do not invent a different status vocabulary or column shape.
- `Result` persists the marshaled `phishval.Outcome` (JSON), never a scenario-specific shape — this is the one unified evidence format across every phishing evidence source (`emailgwefficacy`, `phishidentity`, `internal/actions`, the EXPERIMENTAL heuristics), per `phishval`'s own role in this initiative.
- A scenario is executable **only** if present in `internal/phishingrun`'s registry — triggering any other catalog ID (the other 43 entries) must return 400, never silently no-op or fabricate a result.
- **Tenant isolation — flagged, not silently resolved:** no run-persistence table in this codebase (`email_gw_runs`, `cloud_runs`) currently scopes rows by Audspect-customer tenant (`cloud_runs.tenant_id` is the cloud **provider's** tenant, e.g. Azure AD, unrelated to `auth.Claims.TenantID`). This plan matches that existing precedent exactly — `phishing_runs` gets **no** tenant_id column or WHERE-clause scoping, for consistency with every sibling run table. Task 6 documents this decision in its own test comment rather than silently adding or silently dropping the acceptance criterion. If the user wants real tenant-row-isolation, that is a separate, larger change touching `email_gw_runs`/`cloud_runs` too, not something to build inconsistently for phishing alone.
- `EXPERIMENTAL` scenarios (PH-ID-004/PH-ID-005) are **not** in this slice's registry at all (only PH-DET-002 is) — so the "experimental must be unmistakably marked" criterion is satisfied by this plan's own report template structure (Task 5 renders `Evidence`/`Confidence` per dimension, which already read `EvidenceInferred`/`ConfidenceLow` for either heuristic) being generic enough to extend to them later, not by wiring them into the registry in this slice.
- A successful API request (HTTP 201/200) is never conflated with "the control passed" — `TriggerPhishingRun` returns 201 once the row exists at `StatusRunning`/`StatusPending`; the actual verdict only exists once `ExecutePhishingRun` reaches a terminal status and is read back via `GetPhishingRun`/the report endpoint. This mirrors `TriggerEmailGWRun`'s own exact posture.
- Live validation stays explicitly out of scope: this slice's one wired scenario (PH-DET-002) has no real ITSM connector (confirmed in this session's own QA log), so a run with no evidence provider configured correctly reaches `StatusCompleted` with `Response.Verdict = NotTested` — proving the pipeline, not fabricating evidence that doesn't exist.

## Review Focus

- **Triggering a non-registered scenario ID** (e.g. `"PH-BEC-002"`, a real catalog entry with no executor) must return 400 naming it as not executable, never 404 (it exists in the catalog) and never a fabricated 201.
- **Triggering with missing/malformed scenario-specific parameters** (PH-DET-002 needs `executionId`/`targetId`; a request with neither) must return 400 with a clear message, never a panic or a silently-wrong NotTested result that looks identical to "ran but found no evidence."
- **Unauthenticated or under-permissioned trigger attempts** must 401/403 before any row is ever inserted — proven by a test that then confirms zero rows exist, not just that the HTTP status was right.
- **A run whose configured evidence provider returns nothing** must land on `Response.Verdict = NotTested`, never `Pass` or `Fail` — this is the single most safety-critical behavior in the whole initiative (never fabricate a verdict from absent evidence) and deserves its own explicit test here, not just trust in `phishval.Evaluate`'s own unit tests.
- **Re-running `EnsurePhishingRunSchema` against an already-migrated database** (the startup path, every server restart) must be a no-op, never an error — proven directly, the same way `EnsureEmailGWRunSchema` itself would need to be if it didn't already have that property from `CREATE TABLE IF NOT EXISTS`.

---

### Task 1: `internal/phishingrun` — lifecycle types and the executor registry

**Files:**
- Create: `orchestrator/internal/phishingrun/types.go`
- Create: `orchestrator/internal/phishingrun/registry.go`
- Test: `orchestrator/internal/phishingrun/registry_test.go`

**Interfaces:**
- Produces: `type Status string` with `StatusPending, StatusRunning, StatusCompleted, StatusFailed, StatusPartial Status` (identical values/meaning to `emailgwrun.Status`).
- Produces: `type PhishingRun struct { ID, ScenarioID string; Status Status; Result json.RawMessage; Error string; InitiatedBy string; StartedAt time.Time; CompletedAt *time.Time }` (no dwell-window columns — PH-DET-002 evaluates synchronously; a future scenario needing a real dwell window extends this struct then, per `emailgwrun`'s own precedent of adding `environment` via `ALTER TABLE ADD COLUMN IF NOT EXISTS` later).
- Produces: `type ExecutorEnv struct { ReportTicketProvider phishbridge.ReportTicketEvidenceProvider }` — the one external dependency PH-DET-002's executor needs, injected rather than hardcoded so a future real ITSM connector can be swapped in without touching the registry.
- Produces: `type Executor func(ctx context.Context, env ExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error)`.
- Produces: `func LookupExecutor(scenarioID string) (Executor, bool)` — the registry read. Only `"PH-DET-002"` is registered in this slice.
- Produces: `func executePHDET002(ctx context.Context, env ExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error)` (unexported, registered under `"PH-DET-002"`) — reads `params["executionId"]`/`params["targetId"]` (string, required, 400-worthy if missing — validated by the caller in Task 3, not here), builds `phishbridge.ReportTicketExpectation{ExecutionID: executionID, TargetID: targetID, ExpectedTicketCreated: true}` (always `true` — the catalog's own fixed `Expectation`, never caller-selectable; "known-good/known-bad" was a test-only concept, not a production run parameter), calls `phishbridge.VerifyReportTicketExpectation` against `env.ReportTicketProvider` over a window from `time.Now().Add(-24*time.Hour)` to `time.Now()` (PH-DET-002 has no real dwell window; it looks back over whatever evidence already exists), bridges via `phishbridge.FromSingleDimensionResponseVerdict(verdict, "phishingrun-PH-DET-002")`, looks up PH-DET-002's own `phishval.Expectation` from `phishcatalog.AudspectPhishingCatalog()` (never hand-duplicated), and returns `phishval.Evaluate(runID, "", exp, obs)`.

- [ ] **Step 1: Write the failing test for the registry's executable/non-executable distinction**

```go
func TestLookupExecutor_PHDET002Registered(t *testing.T) {
	_, ok := LookupExecutor("PH-DET-002")
	if !ok {
		t.Fatal("PH-DET-002 must be registered as executable")
	}
}

func TestLookupExecutor_UnregisteredCatalogScenario_NotFound(t *testing.T) {
	// PH-BEC-002 is a real, adapter-tested catalog scenario with no
	// executor wired yet in this slice -- it must not appear executable
	// merely because it exists in phishcatalog.
	_, ok := LookupExecutor("PH-BEC-002")
	if ok {
		t.Fatal("PH-BEC-002 must not be executable in this slice")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/phishingrun/... -run TestLookupExecutor -v`
Expected: FAIL (package/function does not exist yet)

- [ ] **Step 3: Implement `types.go` and `registry.go` per the Interfaces block above**

- [ ] **Step 4: Write the failing test for `executePHDET002`'s own three evidence cases**

```go
func TestExecutePHDET002_TicketCreated_Pass(t *testing.T) {
	env := ExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
		ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: true, Timestamp: time.Now(),
	}})}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil { t.Fatalf("executePHDET002: %v", err) }
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictPass)
	}
}

func TestExecutePHDET002_NoEvidence_NotTested(t *testing.T) {
	env := ExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(nil)}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil { t.Fatalf("executePHDET002: %v", err) }
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (absent evidence must never become Pass or Fail)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}

func TestExecutePHDET002_TicketNotCreated_Fail(t *testing.T) {
	env := ExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
		ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: false, Timestamp: time.Now(),
	}})}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil { t.Fatalf("executePHDET002: %v", err) }
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}
```

- [ ] **Step 5: Run test to verify it fails, then implement `executePHDET002`, then verify it passes**

Run: `go test ./internal/phishingrun/... -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/phishingrun/
git commit -m "feat(phishingrun): add lifecycle types and PH-DET-002 executor registry"
```

---

### Task 2: `internal/db/phishingrun_store.go` — schema and persistence

**Files:**
- Create: `orchestrator/internal/db/phishingrun_store.go`
- Test: `orchestrator/internal/db/phishingrun_store_test.go` (follow `emailgwrun_store_test.go`'s own real-Postgres-via-testutil pattern exactly)

**Interfaces:**
- Consumes: `phishingrun.PhishingRun`, `phishingrun.Status` (Task 1).
- Produces: `func EnsurePhishingRunSchema(ctx context.Context, pool *pgxpool.Pool) error` — `CREATE TABLE IF NOT EXISTS phishing_runs (id text PRIMARY KEY DEFAULT gen_random_uuid()::text, scenario_id text NOT NULL, status text NOT NULL DEFAULT 'pending', result jsonb, error text, initiated_by text, started_at timestamptz NOT NULL DEFAULT NOW(), completed_at timestamptz, CONSTRAINT phishing_runs_status_check CHECK (status IN ('pending','running','completed','failed','partial')))` + `CREATE INDEX IF NOT EXISTS idx_phishing_runs_status ON phishing_runs (status)`. No `tenant_id` column — see Global Constraints.
- Produces: `func InsertPhishingRun(ctx context.Context, pool *pgxpool.Pool, run *phishingrun.PhishingRun) error`
- Produces: `func GetPhishingRun(ctx context.Context, pool *pgxpool.Pool, id string) (*phishingrun.PhishingRun, error)` (returns a wrapped `pgx.ErrNoRows` on miss, same as `GetEmailGWRun`)
- Produces: `func UpdatePhishingRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status phishingrun.Status, result json.RawMessage, errMsg string) error` (sets `completed_at = NOW()`)
- Produces: `func ListPhishingRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*phishingrun.PhishingRun, error)` (newest `started_at` first)

- [ ] **Step 1: Write the failing test**

```go
func TestEnsurePhishingRunSchema_Idempotent(t *testing.T) {
	pool := testutil.NewTestDB(t) // follow emailgwrun_store_test.go's own setup call exactly
	if err := EnsurePhishingRunSchema(context.Background(), pool); err != nil { t.Fatalf("first call: %v", err) }
	if err := EnsurePhishingRunSchema(context.Background(), pool); err != nil { t.Fatalf("second call (must be a no-op): %v", err) }
}

func TestInsertGetUpdateListPhishingRun_RoundTrip(t *testing.T) {
	pool := testutil.NewTestDB(t)
	run := &phishingrun.PhishingRun{ID: "run-1", ScenarioID: "PH-DET-002", Status: phishingrun.StatusPending, StartedAt: time.Now()}
	if err := InsertPhishingRun(context.Background(), pool, run); err != nil { t.Fatalf("insert: %v", err) }

	got, err := GetPhishingRun(context.Background(), pool, "run-1")
	if err != nil { t.Fatalf("get: %v", err) }
	if got.Status != phishingrun.StatusPending { t.Errorf("Status = %q, want pending", got.Status) }

	result, _ := json.Marshal(map[string]string{"ok": "true"})
	if err := UpdatePhishingRunStatus(context.Background(), pool, "run-1", phishingrun.StatusCompleted, result, ""); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = GetPhishingRun(context.Background(), pool, "run-1")
	if got.Status != phishingrun.StatusCompleted || got.CompletedAt == nil {
		t.Errorf("got = %+v, want StatusCompleted with CompletedAt set", got)
	}

	runs, err := ListPhishingRuns(context.Background(), pool, 10)
	if err != nil { t.Fatalf("list: %v", err) }
	if len(runs) != 1 || runs[0].ID != "run-1" { t.Errorf("runs = %+v, want exactly run-1", runs) }
}

func TestGetPhishingRun_NotFound(t *testing.T) {
	pool := testutil.NewTestDB(t)
	_, err := GetPhishingRun(context.Background(), pool, "missing")
	if !errors.Is(err, pgx.ErrNoRows) { t.Errorf("err = %v, want wrapped pgx.ErrNoRows", err) }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/... -run PhishingRun -v`
Expected: FAIL (package functions do not exist)

- [ ] **Step 3: Implement `phishingrun_store.go` per the Interfaces block**

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/... -run PhishingRun -v`
Expected: PASS (requires a real Postgres instance via `testutil`, same precondition every other `_store_test.go` in this package already has)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/db/phishingrun_store.go orchestrator/internal/db/phishingrun_store_test.go
git commit -m "feat(db): add phishing_runs schema and persistence, no tenant scoping (matches email_gw_runs/cloud_runs precedent)"
```

---

### Task 3: `internal/api/phishingrun_executor.go` — the run lifecycle orchestration

**Files:**
- Create: `orchestrator/internal/api/phishingrun_executor.go`
- Test: `orchestrator/internal/api/phishingrun_executor_test.go`

**Interfaces:**
- Consumes: `phishingrun.LookupExecutor`, `phishingrun.ExecutorEnv`, `db.InsertPhishingRun`/`UpdatePhishingRunStatus`/`GetPhishingRun`, `newID()` (`handlers.go:4150`).
- Produces: `type PhishingRunRequest struct { ScenarioID string; Parameters map[string]any; InitiatedBy string }`
- Produces: `func ExecutePhishingRun(ctx context.Context, pool *pgxpool.Pool, env phishingrun.ExecutorEnv, req PhishingRunRequest) (*phishingrun.PhishingRun, error)` — synchronous (unlike `ExecuteEmailGWRun`'s async dwell-window goroutine: PH-DET-002 has no real dwell window to wait out). Looks up the executor; returns an error (no row inserted) if `req.ScenarioID` isn't registered. Otherwise inserts a `StatusPending` row, runs the executor, marshals the resulting `phishval.Outcome`, and writes the terminal status (`StatusCompleted` if the executor returned no error, `StatusFailed` with `err.Error()` if it did — e.g. missing `executionId`/`targetId` params).

- [ ] **Step 1: Write the failing test**

```go
func TestExecutePhishingRun_UnregisteredScenario_NoRowInserted(t *testing.T) {
	pool := testutil.NewTestDB(t)
	db.EnsurePhishingRunSchema(context.Background(), pool)
	_, err := ExecutePhishingRun(context.Background(), pool, phishingrun.ExecutorEnv{}, PhishingRunRequest{ScenarioID: "PH-BEC-002"})
	if err == nil { t.Fatal("want an error for an unregistered scenario id") }
	runs, _ := db.ListPhishingRuns(context.Background(), pool, 10)
	if len(runs) != 0 { t.Errorf("rows inserted = %d, want 0 (an unregistered scenario must never create a row)", len(runs)) }
}

func TestExecutePhishingRun_MissingParams_StatusFailed(t *testing.T) {
	pool := testutil.NewTestDB(t)
	db.EnsurePhishingRunSchema(context.Background(), pool)
	run, err := ExecutePhishingRun(context.Background(), pool, phishingrun.ExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(nil)}, PhishingRunRequest{ScenarioID: "PH-DET-002"})
	if err == nil { t.Fatal("want an error for missing executionId/targetId") }
	if run.Status != phishingrun.StatusFailed { t.Errorf("Status = %q, want failed", run.Status) }
}

func TestExecutePhishingRun_PHDET002_EndToEnd_Completed(t *testing.T) {
	pool := testutil.NewTestDB(t)
	db.EnsurePhishingRunSchema(context.Background(), pool)
	env := phishingrun.ExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
		ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: true, Timestamp: time.Now(),
	}})}
	run, err := ExecutePhishingRun(context.Background(), pool, env, PhishingRunRequest{
		ScenarioID: "PH-DET-002", Parameters: map[string]any{"executionId": "exec-1", "targetId": "target-1"}, InitiatedBy: "user-1",
	})
	if err != nil { t.Fatalf("ExecutePhishingRun: %v", err) }
	if run.Status != phishingrun.StatusCompleted { t.Fatalf("Status = %q, want completed", run.Status) }

	persisted, err := db.GetPhishingRun(context.Background(), pool, run.ID)
	if err != nil { t.Fatalf("GetPhishingRun: %v", err) }
	var outcome phishval.Outcome
	if err := json.Unmarshal(persisted.Result, &outcome); err != nil { t.Fatalf("unmarshal result: %v", err) }
	if outcome.Response.Verdict != phishval.VerdictPass { t.Errorf("Response.Verdict = %q, want pass", outcome.Response.Verdict) }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/... -run ExecutePhishingRun -v`
Expected: FAIL

- [ ] **Step 3: Implement `ExecutePhishingRun` per the Interfaces block**

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/... -run ExecutePhishingRun -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/phishingrun_executor.go orchestrator/internal/api/phishingrun_executor_test.go
git commit -m "feat(api): add synchronous ExecutePhishingRun orchestration for PH-DET-002"
```

---

### Task 4: API handlers and routing

**Files:**
- Create: `orchestrator/internal/api/phishingrun_handlers.go`
- Modify: `orchestrator/internal/api/routes.go` (add routes alongside the `/api/emailgw-runs` block)
- Modify: `orchestrator/cmd/server/main.go` (add `db.EnsurePhishingRunSchema` call next to `db.EnsureEmailGWRunSchema`, `cmd/server/main.go:310`)
- Modify: `orchestrator/internal/testutil/testdb.go` (add the same call next to line 151, so every test using the shared test-DB setup gets the table)
- Test: `orchestrator/internal/api/phishingrun_handlers_test.go`

**Interfaces:**
- Consumes: `ExecutePhishingRun` (Task 3), `db.GetPhishingRun`/`ListPhishingRuns`, `auth.ClaimsFrom`, `auth.RequirePermission`, `auth.CanRunScenario`.
- Produces: `func (h *Handler) TriggerPhishingRun(w http.ResponseWriter, r *http.Request)` — decodes `{"scenarioId": "...", "parameters": {...}}`, sets `InitiatedBy` from `auth.ClaimsFrom` (never trusted from the body, matching `TriggerEmailGWRun`'s own convention exactly), calls `ExecutePhishingRun`, audit-logs via `h.auditLog` (same `"phishingrun.trigger"` action-name convention), responds 201 with the run on success or 400 with the error (unregistered scenario / missing params) on failure.
- Produces: `func (h *Handler) ListPhishingRuns(w http.ResponseWriter, r *http.Request)` and `func (h *Handler) GetPhishingRun(w http.ResponseWriter, r *http.Request)` (chi URL param `{id}`), mirroring `ListEmailGWRuns`/`GetEmailGWRun` exactly.
- Routes: `r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/phishing-runs", h.TriggerPhishingRun)` in the permission-gated block (next to line 513); `r.Get("/api/phishing-runs", h.ListPhishingRuns)` and `r.Get("/api/phishing-runs/{id}", h.GetPhishingRun)` in the baseline-auth block (next to line 310).

- [ ] **Step 1: Write the failing test**

```go
func TestTriggerPhishingRun_Unauthorized_NoRowCreated(t *testing.T) {
	// request with no auth claims / wrong permission
	// assert HTTP 401/403 and zero rows in phishing_runs afterward
}

func TestTriggerPhishingRun_UnregisteredScenario_400(t *testing.T) {
	// authorized request, scenarioId: "PH-BEC-002"
	// assert HTTP 400
}

func TestTriggerPhishingRun_PHDET002_201ThenGetReturnsCompletedRun(t *testing.T) {
	// authorized POST with executionId/targetId params and a fixture
	// provider wired on the test Handler -> 201, run.Status in
	// {pending, running} per TriggerEmailGWRun's own immediate-return
	// posture (this slice's executor is synchronous, so by the time the
	// handler responds the row may already be completed -- assert
	// Status is a valid value, not a specific one)
	// then GET /api/phishing-runs/{id} -> 200, Status == completed
}

func TestListPhishingRuns_ReturnsNewestFirst(t *testing.T) {
	// two runs inserted via ExecutePhishingRun, list returns both, newest first
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/... -run PhishingRun -v`
Expected: FAIL

- [ ] **Step 3: Implement handlers, wire `routes.go`, wire the two `EnsurePhishingRunSchema` call sites**

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/... -run PhishingRun -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/phishingrun_handlers.go orchestrator/internal/api/phishingrun_handlers_test.go orchestrator/internal/api/routes.go orchestrator/cmd/server/main.go orchestrator/internal/testutil/testdb.go
git commit -m "feat(api): wire phishing-runs trigger/list/get endpoints behind CanRunScenario"
```

---

### Task 5: Client-facing report

**Files:**
- Create: `orchestrator/internal/reporting/phishing_scenario_report.go`
- Create: `orchestrator/internal/api/phishingrun_report_handler.go`
- Modify: `orchestrator/internal/api/routes.go` (add `GET /api/phishing-runs/{id}/report`)
- Test: `orchestrator/internal/reporting/phishing_scenario_report_test.go`, `orchestrator/internal/api/phishingrun_report_handler_test.go`

**Interfaces:**
- Consumes: a persisted `phishingrun.PhishingRun` (via `db.GetPhishingRun`), its `Result` unmarshaled into `phishval.Outcome`, and `phishcatalog.AudspectPhishingCatalog()` for the scenario's own `Name`/`PrimaryObjective`/`Limitations` text. **Does not re-evaluate anything** — this is the one place this plan deliberately diverges from `av_efficacy_scenario.go`'s own convention of calling `avefficacy.EvaluateScenarioBySlug` fresh on every render, because the acceptance criteria require the report to reflect the actual persisted run, not a live recomputation that could drift from what was recorded.
- Produces: `type PhishingScenarioReport struct { RunID, ScenarioID, ScenarioName string; GeneratedAt, RunStartedAt time.Time; RunCompletedAt *time.Time; RunStatus string; Dimensions []PhishingReportDimension; CatalogLimitations string; Experimental bool }`
- Produces: `type PhishingReportDimension struct { Name, Verdict, Reason string; Evidence, Confidence string }` — one entry per non-`NotApplicable` dimension in the `phishval.Outcome` (Delivery/Enforcement/Detection/UserInteraction/Response).
- Produces: `func BuildPhishingScenarioReport(run *phishingrun.PhishingRun, catalogEntry phishcatalog.Scenario) (PhishingScenarioReport, error)` — unmarshals `run.Result`; sets `Experimental = true` when `catalogEntry.Coverage == phishcatalog.CoverageAdapterTested` **and** any dimension's `Evidence == "inferred"` (the exact signal `FromMFAFatigueHeuristic`/`FromSessionTheftResponseHeuristic`/this slice's own `FromSingleDimensionResponseVerdict`-on-Inconclusive would produce) — not scenario-ID string-matching, so this generalizes correctly if PH-ID-004/005 are registered in a later slice.
- Produces: `func PhishingScenarioReportHTML(w io.Writer, rep PhishingScenarioReport) error` — mirrors `av_efficacy_scenario.go`'s template style (per-dimension line showing Verdict + Confidence inline, e.g. `{{.Verdict}} ({{.Confidence}}) -- {{.Reason}}`), with an `{{if .Experimental}}` banner rendered **above** the dimension list, not buried in a footnote, reading "EXPERIMENTAL — not a vendor-verified detection; see this scenario's own catalog Limitations below" in visually distinct styling (red/amber border, not the same gray the rest of the page uses).
- Route: `GET /api/phishing-runs/{id}/report` → `(h *Handler) GetPhishingRunReport` → loads the run, looks up its catalog entry by `ScenarioID`, calls `BuildPhishingScenarioReport`, writes HTML (`Content-Type: text/html`). 404 if the run doesn't exist; the run's own `Status` (e.g. still `pending`) is rendered as-is, never papered over.

- [ ] **Step 1: Write the failing test for the Experimental flag specifically**

```go
func TestBuildPhishingScenarioReport_InferredEvidence_FlagsExperimental(t *testing.T) {
	outcome := phishval.Outcome{Response: phishval.DimensionResult{Verdict: phishval.VerdictNotTested, Evidence: phishval.EvidenceInferred}}
	resultJSON, _ := json.Marshal(outcome)
	run := &phishingrun.PhishingRun{ID: "run-1", ScenarioID: "PH-ID-004", Result: resultJSON, Status: phishingrun.StatusCompleted}
	rep, err := BuildPhishingScenarioReport(run, phishcatalog.Scenario{ID: "PH-ID-004", Coverage: phishcatalog.CoverageAdapterTested})
	if err != nil { t.Fatalf("BuildPhishingScenarioReport: %v", err) }
	if !rep.Experimental {
		t.Error("Experimental = false, want true for a dimension carrying EvidenceInferred")
	}
}

func TestBuildPhishingScenarioReport_VerifiedTelemetry_NotExperimental(t *testing.T) {
	outcome := phishval.Outcome{Response: phishval.DimensionResult{Verdict: phishval.VerdictPass, Evidence: phishval.EvidenceVerifiedTelemetry}}
	resultJSON, _ := json.Marshal(outcome)
	run := &phishingrun.PhishingRun{ID: "run-1", ScenarioID: "PH-DET-002", Result: resultJSON, Status: phishingrun.StatusCompleted}
	rep, _ := BuildPhishingScenarioReport(run, phishcatalog.Scenario{ID: "PH-DET-002", Coverage: phishcatalog.CoverageFixtureTested})
	if rep.Experimental {
		t.Error("Experimental = true, want false for ordinary verified/fixture evidence")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/reporting/... -run PhishingScenarioReport -v`
Expected: FAIL

- [ ] **Step 3: Implement `phishing_scenario_report.go` and the HTML template per the Interfaces block**

- [ ] **Step 4: Run test to verify it passes, then implement and test the API handler/route**

Run: `go test ./internal/reporting/... ./internal/api/... -run "PhishingScenarioReport|PhishingRunReport" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/reporting/phishing_scenario_report.go orchestrator/internal/reporting/phishing_scenario_report_test.go orchestrator/internal/api/phishingrun_report_handler.go orchestrator/internal/api/phishingrun_report_handler_test.go orchestrator/internal/api/routes.go
git commit -m "feat(reporting): add phishing scenario run report, EXPERIMENTAL banner for inferred-evidence dimensions"
```

---

### Task 6: End-to-end proof and final gate

**Files:**
- Create: `orchestrator/internal/api/phishingrun_e2e_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1–5. No new production code — this task is tests only, proving the full vertical slice as one path.

- [ ] **Step 1: Write the end-to-end test (API request → dispatch → persistence → report retrieval)**

```go
func TestPhishingRunPipeline_EndToEnd(t *testing.T) {
	// 1. POST /api/phishing-runs as an authorized CanRunScenario user,
	//    scenarioId=PH-DET-002, parameters={executionId, targetId} ->
	//    201, run.Status in {pending, running, completed}
	// 2. GET /api/phishing-runs/{id} -> 200, Status == completed,
	//    Result unmarshals to a phishval.Outcome with Response.Verdict == pass
	// 3. GET /api/phishing-runs/{id}/report -> 200, text/html, body
	//    contains the scenario name and "pass" (case-insensitive) and
	//    does NOT contain "EXPERIMENTAL" (PH-DET-002 isn't)
}

func TestPhishingRunPipeline_NoEvidence_ReportShowsNotTestedNeverPass(t *testing.T) {
	// same as above but the fixture provider has zero matching records
	// -> Response.Verdict == not_tested, report body must not contain "pass"
}

func TestPhishingRunPipeline_Unauthorized_401Then403(t *testing.T) {
	// no claims -> 401; claims without CanRunScenario -> 403; in both
	// cases assert zero rows in phishing_runs afterward
}

func TestPhishingRunPipeline_UnknownScenario_400NoRow(t *testing.T) {
	// scenarioId: "PH-BEC-002" (real catalog entry, not registered) -> 400, zero rows
}

func TestEnsurePhishingRunSchema_SafeAcrossRepeatedServerStartups(t *testing.T) {
	// call EnsurePhishingRunSchema 3 times against the same pool in a
	// row (simulating 3 server restarts) -- must never error, and a
	// row inserted between calls 1 and 2 must still be readable after
	// call 3 (schema-ensure must never be destructive)
}
```

- [ ] **Step 2: Run test to verify it fails, then verify it passes (it should already pass if Tasks 1-5 are correctly implemented -- this task validates the integration, it does not add new behavior)**

Run: `go test ./internal/api/... -run PhishingRunPipeline -v && go test ./internal/db/... -run EnsurePhishingRunSchema -v`
Expected: PASS

- [ ] **Step 3: Run the full phishing test suite plus `go vet` to confirm nothing regressed**

Run: `go build ./internal/... && go vet ./internal/phishval/... ./internal/phishcatalog/... ./internal/phishbridge/... ./internal/phishidentity/... ./internal/phishingrun/... ./internal/db/... ./internal/api/... ./internal/reporting/... && go test ./internal/phishval/... ./internal/phishcatalog/... ./internal/phishbridge/... ./internal/phishidentity/... ./internal/phishingrun/... ./internal/db/... ./internal/api/... ./internal/reporting/...`
Expected: all green

- [ ] **Step 4: Update `docs/phishing-mastery-qa-log.md`**

Add a new Resolved-items entry recording: the run pipeline now exists for exactly PH-DET-002; the other 30 adapter-tested scenarios remain un-wired (named as explicit future work, not a silent gap); the tenant-isolation decision from Global Constraints; live validation still explicitly not performed.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/phishingrun_e2e_test.go docs/phishing-mastery-qa-log.md
git commit -m "test(phishingrun): prove the full trigger-to-report pipeline end-to-end for PH-DET-002"
```

---

## What this plan deliberately does NOT do

- Wire any scenario besides PH-DET-002 into the executor registry. Expanding to the other 30 adapter-tested scenarios (each needing its own `params` shape and, for SMTP-dispatch scenarios, a real or test mail target plus the async dwell-window machinery `emailgwrun` already has) is substantial, separate follow-up work — doing it here would violate the user's own "smallest complete vertical slice first" instruction.
- Add tenant-row isolation. Flagged explicitly in Global Constraints as a decision that needs to be made consistently across `email_gw_runs`/`cloud_runs`/`phishing_runs` together, not invented alone for phishing.
- Touch `internal/emailgwrun`, `internal/cloudrun`, or either of their stores/executors. This plan only reads their shape as a template; zero lines in those packages change.
