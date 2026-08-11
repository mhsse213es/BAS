# Scheduled Assessments: Edit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an existing Scheduled Assessment be edited (every field, including scenario/mode/targets/recurrence), instead of only cancel-and-recreate.

**Architecture:** A new `Store.UpdateSchedule` (full-row UPDATE over the editable columns only) and a new `PUT /api/scheduled-assessments/{id}` handler that mirrors `CreateScheduledAssessment`'s validation and Telemetry authorization rule exactly — editing into/within Telemetry mode requires the editor to hold `CanApproveRemediation` and supply a reason, re-stamping approval and incrementing `ApprovalVersion`; editing to Posture clears approval. The frontend reuses the existing Create wizard, prefilled from the schedule's current values, with a small fix to a first-render bug in the Mode/Recurrence pane that would otherwise silently clobber the prefilled Mode and Timezone.

**Tech Stack:** Go (pgx/Postgres) backend; vanilla JS in `orchestrator/wwwroot/index.html` frontend, no framework, no JS test runner — verification is `node --check` plus manual QA, per established project convention.

## Global Constraints

- Every field is editable: scenario, mode, targets (groups/agents), recurrence, timezone, end date, concurrency limit.
- Editing a schedule into or within Telemetry mode requires `CanApproveRemediation` + a non-empty `reason`, exactly like creation — approval is re-stamped fresh and `ApprovalVersion` increments from the schedule's current value.
- Editing to Posture mode clears `ApprovedBy`/`ApprovedAt`/`ApprovalVersion`/`Reason` to zero-values.
- Saving an edit always sets `Enabled = true`, regardless of the schedule's prior status — editing a Cancelled schedule revives it.
- `id`, `type`, `created_by`, `created_at`, `last_occurrence_at`, `last_spawned_job_id` are never modified by an update.
- No partial/PATCH semantics — the update request carries the same complete field set `CreateScheduledAssessment` already requires.
- Frontend syntax verification for every task touching `index.html`:
  ```bash
  awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
  ```
  Run from the repo root (`C:\Users\Administrator\Downloads\Audspect_Cloud`).
- Go verification: `cd orchestrator && go build ./...` and the specified `go test` commands. Container-backed tests are guarded with `if testing.Short() { t.Skip(...) }`; run them without `-short`.

---

## Task 1: `Store.UpdateSchedule`

**Files:**
- Modify: `orchestrator/internal/jobs/schedule.go` (new method, placed after `CreateSchedule`, currently lines 205-226)
- Test: `orchestrator/internal/jobs/schedule_test.go`

**Interfaces:**
- Produces: `func (s *Store) UpdateSchedule(ctx context.Context, id string, sch Schedule) (Schedule, error)`, consumed by Task 2.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/jobs/schedule_test.go`:
```go
func TestUpdateSchedule_PersistsEditableFieldsAndPreservesIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall"})
		created, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 1, TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		// Deliberately leave Type/CreatedBy unset on the update struct to prove
		// UpdateSchedule's SQL never references those columns at all -- not just
		// that this test happened to pass matching values.
		newPayload, _ := json.Marshal(map[string]string{"remediationId": "disable_smbv1"})
		updated, err := store.UpdateSchedule(ctx, created.ID, Schedule{
			Payload: newPayload, AgentIDs: []string{"a2", "a3"}, DayOfWeek: 5, TimeOfDay: "23:00",
			Timezone: "Asia/Kolkata", Enabled: true, RecurrenceType: "weekly", ConcurrencyLimit: 3,
		})
		if err != nil {
			t.Fatalf("UpdateSchedule: %v", err)
		}
		if updated.ID != created.ID || updated.Type != "batch_remediation" || updated.CreatedBy != "user-1" || !updated.CreatedAt.Equal(created.CreatedAt) {
			t.Errorf("identity fields changed: got %+v, want ID/Type/CreatedBy/CreatedAt unchanged from %+v", updated, created)
		}
		if len(updated.AgentIDs) != 2 || updated.AgentIDs[0] != "a2" || updated.DayOfWeek != 5 || updated.TimeOfDay != "23:00" || updated.Timezone != "Asia/Kolkata" || updated.ConcurrencyLimit != 3 {
			t.Errorf("got = %+v, want AgentIDs=[a2 a3] DayOfWeek=5 TimeOfDay=23:00 Timezone=Asia/Kolkata ConcurrencyLimit=3", updated)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator && go test ./internal/jobs/... -run "TestUpdateSchedule_PersistsEditableFieldsAndPreservesIdentity" -v
```
Expected: FAIL with `store.UpdateSchedule undefined` (compile error — method doesn't exist yet).

- [ ] **Step 3: Implement `UpdateSchedule`**

Find `CreateSchedule` (`orchestrator/internal/jobs/schedule.go:205-226`). Add immediately after its closing `}`:
```go
// UpdateSchedule replaces every editable field on schedule id. Identity
// fields (id, type, created_by, created_at) and spawner-owned bookkeeping
// (last_occurrence_at, last_spawned_job_id) are never touched here -- only
// Store.MarkScheduleOccurrenceHandled writes those. See
// docs/superpowers/specs/2026-08-11-scheduled-assessment-edit-design.md.
func (s *Store) UpdateSchedule(ctx context.Context, id string, sch Schedule) (Schedule, error) {
	agentIDsJSON, err := json.Marshal(sch.AgentIDs)
	if err != nil {
		return Schedule{}, err
	}
	groupIDsJSON, err := json.Marshal(sch.GroupIDs)
	if err != nil {
		return Schedule{}, err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE job_schedules SET
		    payload=$1, agent_ids=$2, group_ids=$3, day_of_week=$4, time_of_day=$5, timezone=$6, enabled=$7,
		    recurrence_type=$8, run_at=$9, day_of_month=$10, end_date=$11, concurrency_limit=$12,
		    mode=$13, approved_by=$14, approved_at=$15, approval_version=$16, reason=$17
		 WHERE id=$18`,
		[]byte(sch.Payload), agentIDsJSON, groupIDsJSON, sch.DayOfWeek, sch.TimeOfDay, sch.Timezone, sch.Enabled,
		sch.RecurrenceType, sch.RunAt, sch.DayOfMonth, sch.EndDate, sch.ConcurrencyLimit,
		sch.Mode, sch.ApprovedBy, sch.ApprovedAt, sch.ApprovalVersion, sch.Reason, id,
	); err != nil {
		return Schedule{}, err
	}
	return s.GetSchedule(ctx, id)
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator && go test ./internal/jobs/... -run "TestUpdateSchedule_PersistsEditableFieldsAndPreservesIdentity" -v
```
Expected: PASS.

- [ ] **Step 5: Full package regression**

```bash
cd orchestrator && go build ./... && go test ./internal/jobs/... -v
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/jobs/schedule.go orchestrator/internal/jobs/schedule_test.go
git commit -m "feat(scheduled-assessments): add Store.UpdateSchedule"
```

---

## Task 2: `UpdateScheduledAssessment` handler + route

**Files:**
- Modify: `orchestrator/internal/api/scheduled_assessment_handlers.go` (new handler; update `CreateScheduledAssessment`'s stale doc comment, lines 14-22)
- Modify: `orchestrator/internal/api/routes.go` (new route, near lines 525-527)
- Test: `orchestrator/internal/api/scheduled_assessment_handlers_test.go`

**Interfaces:**
- Consumes: `Store.UpdateSchedule` (Task 1), `scheduledAssessmentPayload` (`internal/api/scheduled_assessment_dispatch.go:17`), `parseTimeOfDayForAPI` (`internal/api/schedule_handlers.go:138`).
- Produces: `func (h *Handler) UpdateScheduledAssessment(w http.ResponseWriter, r *http.Request)`, route `PUT /api/scheduled-assessments/{id}`.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/scheduled_assessment_handlers_test.go`:
```go
func TestUpdateScheduledAssessment_Posture_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{"scenarioId":"fixture-scenario","mode":"posture"}`),
			AgentIDs: []string{"sa-u1"}, RecurrenceType: "weekly", DayOfWeek: 1, TimeOfDay: "02:00",
			Timezone: "UTC", Enabled: true, Mode: "posture",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-u1", "sa-u2"},
			"recurrenceType": "daily", "timeOfDay": "03:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if len(got.AgentIDs) != 2 || got.RecurrenceType != "daily" || got.TimeOfDay != "03:00" {
			t.Errorf("got = %+v, want AgentIDs len 2, RecurrenceType=daily, TimeOfDay=03:00", got)
		}
	})
}

func TestUpdateScheduledAssessment_Telemetry_AnalystForbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-u3"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "posture",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-u3"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC", "reason": "test",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestUpdateScheduledAssessment_Telemetry_AdminWithReason_ReapprovesAndIncrementsVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		approvedAt := time.Now().Add(-24 * time.Hour)
		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-u4"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "telemetry",
			ApprovedBy: "admin-0", ApprovedAt: &approvedAt, ApprovalVersion: 1, Reason: "original reason",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-u4"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
			"reason": "re-approved after target change",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.ApprovedBy != "admin-1" || got.ApprovalVersion != 2 || got.Reason != "re-approved after target change" {
			t.Errorf("got = %+v, want ApprovedBy=admin-1 ApprovalVersion=2 Reason='re-approved after target change'", got)
		}
		if got.ApprovedAt == nil || !got.ApprovedAt.After(approvedAt) {
			t.Errorf("ApprovedAt = %v, want non-nil and after the original %v", got.ApprovedAt, approvedAt)
		}
	})
}

func TestUpdateScheduledAssessment_ModeChangeToPosture_ClearsApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		approvedAt := time.Now()
		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-u5"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "telemetry",
			ApprovedBy: "admin-0", ApprovedAt: &approvedAt, ApprovalVersion: 1, Reason: "original reason",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-u5"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.ApprovedBy != "" || got.ApprovedAt != nil || got.ApprovalVersion != 0 || got.Reason != "" {
			t.Errorf("got = %+v, want approval fields cleared after mode change to posture", got)
		}
	})
}

func TestUpdateScheduledAssessment_RevivesCancelledSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-u6"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "posture",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		if err := jobsStore.DisableSchedule(context.Background(), sch.ID); err != nil {
			t.Fatalf("DisableSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-u6"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if !got.Enabled {
			t.Error("schedule should be re-enabled after edit, still disabled")
		}
	})
}

func TestUpdateScheduledAssessment_UnknownID_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-u7"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", "does-not-exist")
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body = %s", w.Code, w.Body.String())
		}
	})
}
```
(`bytes`, `context`, `encoding/json`, `net/http`, `net/http/httptest`, `testing`, `time`, `github.com/jackc/pgx/v5/pgxpool`, `github.com/audspect/bas/internal/auth`, `github.com/audspect/bas/internal/jobs`, `github.com/audspect/bas/internal/scenario`, `github.com/audspect/bas/internal/ws` are all already imported in this file per its existing tests — `time` specifically is needed for the new tests' `time.Now()` calls; confirm it's already imported, add it if not.)

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd orchestrator && go test ./internal/api/... -run "TestUpdateScheduledAssessment" -v
```
Expected: FAIL with `h.UpdateScheduledAssessment undefined`.

- [ ] **Step 3: Update the stale doc comment on `CreateScheduledAssessment`**

Find (`orchestrator/internal/api/scheduled_assessment_handlers.go:14-22`, exact):
```go
// POST /api/scheduled-assessments
// Mode-conditional permission: posture needs CanExecuteRemediation (the
// same tier as batch remediation); telemetry needs CanApproveRemediation
// (Admin-only) PLUS a non-empty reason -- together these ARE the Scheduled
// Execution Authorization (see the design spec's "Execution mode and
// authorization" section). Lab mode is rejected outright: it can never be
// scheduled. Schedules are immutable -- there is no update endpoint;
// changing anything means cancelling this one and creating a new one,
// which is always freshly authorized by construction.
func (h *Handler) CreateScheduledAssessment(w http.ResponseWriter, r *http.Request) {
```
Replace with:
```go
// POST /api/scheduled-assessments
// Mode-conditional permission: posture needs CanExecuteRemediation (the
// same tier as batch remediation); telemetry needs CanApproveRemediation
// (Admin-only) PLUS a non-empty reason -- together these ARE the Scheduled
// Execution Authorization (see the design spec's "Execution mode and
// authorization" section). Lab mode is rejected outright: it can never be
// scheduled. See UpdateScheduledAssessment (PUT /api/scheduled-assessments/{id})
// for editing an existing schedule -- it enforces this exact same
// authorization rule against the edited configuration, not the original one.
func (h *Handler) CreateScheduledAssessment(w http.ResponseWriter, r *http.Request) {
```

- [ ] **Step 4: Implement `UpdateScheduledAssessment`**

Add to `orchestrator/internal/api/scheduled_assessment_handlers.go`, after `CreateScheduledAssessment`'s closing `}` (currently line 154):
```go
// PUT /api/scheduled-assessments/{id}
// Mirrors CreateScheduledAssessment's validation and authorization rule
// exactly -- editing a schedule INTO or WITHIN telemetry mode re-runs the
// same Scheduled Execution Authorization (CanApproveRemediation + a fresh
// reason), since the prior approval was captured against the OLD
// configuration and must not silently carry over to a changed one. Saving
// an edit always re-enables the schedule. See
// docs/superpowers/specs/2026-08-11-scheduled-assessment-edit-design.md.
func (h *Handler) UpdateScheduledAssessment(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "id")
	var req struct {
		ScenarioID       string     `json:"scenarioId"`
		Mode             string     `json:"mode"`
		Techniques       []string   `json:"techniques"`
		Steps            []int      `json:"steps"`
		AgentIDs         []string   `json:"agentIds"`
		GroupIDs         []int64    `json:"groupIds"`
		RecurrenceType   string     `json:"recurrenceType"`
		RunAt            *time.Time `json:"runAt"`
		DayOfWeek        int        `json:"dayOfWeek"`
		DayOfMonth       int        `json:"dayOfMonth"`
		TimeOfDay        string     `json:"timeOfDay"`
		Timezone         string     `json:"timezone"`
		EndDate          *time.Time `json:"endDate"`
		ConcurrencyLimit int        `json:"concurrencyLimit"`
		Reason           string     `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.ScenarioID == "" {
		jsonError(w, "scenarioId is required", http.StatusBadRequest)
		return
	}
	if req.Mode != "posture" && req.Mode != "telemetry" {
		jsonError(w, "mode must be posture or telemetry -- lab mode cannot be scheduled", http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 && len(req.GroupIDs) == 0 {
		jsonError(w, "at least one agentId or groupId is required", http.StatusBadRequest)
		return
	}
	switch req.RecurrenceType {
	case "once":
		if req.RunAt == nil {
			jsonError(w, "runAt is required for a once schedule", http.StatusBadRequest)
			return
		}
	case "daily":
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	case "weekly":
		if req.DayOfWeek < 0 || req.DayOfWeek > 6 {
			jsonError(w, "dayOfWeek must be 0-6", http.StatusBadRequest)
			return
		}
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	case "monthly":
		if req.DayOfMonth < 1 || req.DayOfMonth > 28 {
			jsonError(w, "dayOfMonth must be 1-28 (29-31 excluded -- not every month has them)", http.StatusBadRequest)
			return
		}
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	default:
		jsonError(w, "recurrenceType must be once, daily, weekly, or monthly", http.StatusBadRequest)
		return
	}
	tz := req.Timezone
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		jsonError(w, "timezone is not a valid IANA name", http.StatusBadRequest)
		return
	}
	if h.engine == nil {
		jsonError(w, "scenario engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if _, ok := h.engine.Get(req.ScenarioID); !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}

	existing, err := h.jobsStore.GetSchedule(r.Context(), scheduleID)
	if err != nil || existing.Type != "scheduled_assessment" {
		jsonError(w, "schedule not found", http.StatusNotFound)
		return
	}

	claims, _ := auth.ClaimsFrom(r.Context())
	var approvedBy string
	var approvedAt *time.Time
	approvalVersion := 0
	if req.Mode == "telemetry" {
		if claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation) {
			jsonError(w, "scheduling a telemetry-mode assessment requires an Administrator's standing authorization", http.StatusForbidden)
			return
		}
		if req.Reason == "" {
			jsonError(w, "reason is required to authorize a telemetry-mode schedule", http.StatusBadRequest)
			return
		}
		now := time.Now()
		approvedAt = &now
		approvalVersion = existing.ApprovalVersion + 1
		approvedBy = claims.UserID
	}

	payload, err := json.Marshal(scheduledAssessmentPayload{
		ScenarioID: req.ScenarioID, Mode: req.Mode, Techniques: req.Techniques, Steps: req.Steps,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sch, err := h.jobsStore.UpdateSchedule(r.Context(), scheduleID, jobs.Schedule{
		Type: "scheduled_assessment", Payload: payload, AgentIDs: req.AgentIDs, GroupIDs: req.GroupIDs,
		RecurrenceType: req.RecurrenceType, RunAt: req.RunAt, DayOfWeek: req.DayOfWeek, DayOfMonth: req.DayOfMonth,
		TimeOfDay: req.TimeOfDay, Timezone: tz, EndDate: req.EndDate, ConcurrencyLimit: req.ConcurrencyLimit,
		Enabled: true, Mode: req.Mode, ApprovedBy: approvedBy, ApprovedAt: approvedAt,
		ApprovalVersion: approvalVersion, Reason: req.Reason,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.update", sch.ID, map[string]any{
		"scenarioId": req.ScenarioID, "mode": req.Mode, "recurrenceType": req.RecurrenceType,
		"agentCount": len(req.AgentIDs), "groupCount": len(req.GroupIDs), "approvedBy": approvedBy,
		"previousApprovalVersion": existing.ApprovalVersion, "newApprovalVersion": approvalVersion,
	}, "updated")
	respond(w, map[string]any{"scheduleId": sch.ID})
}
```

- [ ] **Step 5: Register the route**

`orchestrator/internal/api/routes.go`, find (lines 525-527, exact):
```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/scheduled-assessments", h.CreateScheduledAssessment)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/scheduled-assessments", h.ListScheduledAssessments)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/scheduled-assessments/{id}/cancel", h.CancelScheduledAssessment)
```
Add, right after:
```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/scheduled-assessments", h.CreateScheduledAssessment)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/scheduled-assessments", h.ListScheduledAssessments)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Put("/api/scheduled-assessments/{id}", h.UpdateScheduledAssessment)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/scheduled-assessments/{id}/cancel", h.CancelScheduledAssessment)
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd orchestrator && go test ./internal/api/... -run "TestUpdateScheduledAssessment" -v
```
Expected: all 6 PASS.

- [ ] **Step 7: Full regression check**

```bash
cd orchestrator && go build ./... && go test ./internal/api/... -run "TestCreateScheduledAssessment|TestListScheduledAssessments|TestCancelScheduledAssessment|TestUpdateScheduledAssessment" -v
```
Expected: all PASS — confirms Create/List/Cancel are unaffected.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/scheduled_assessment_handlers.go orchestrator/internal/api/scheduled_assessment_handlers_test.go orchestrator/internal/api/routes.go
git commit -m "feat(scheduled-assessments): add PUT /api/scheduled-assessments/{id} to edit a schedule"
```

---

## Task 3: Frontend — Edit button, wizard prefill, submit branching

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (Edit button in `renderScheduledAssessmentsList()`, currently lines 17337-17364; `SCHED` namespace, lines 17275-17284; wizard `<h3>` title, line 3833; `openSchedWizard()`, lines 17375-17399; `renderSchedModeRecurrencePane()`, ~lines 17472-17495; `submitScheduledAssessment()`, lines 17581-17595)

**Interfaces:**
- Consumes: `PUT /api/scheduled-assessments/{id}` (Task 2), pre-existing `schedFlattenGroupNames`, `renderSchedGroupTree`, `renderSchedAgentList`, `schedWizardSet`, `apicall`, `x`, `showToast`, `scenarios` (global).
- Produces: `openSchedWizardForEdit(id)`, `SCHED.editingId`, `SCHED.editPrefillMode`, `SCHED.editPrefillTimezone` — none consumed by later tasks, this is the last task.

- [ ] **Step 1: Give the wizard title an id**

Find (`orchestrator/wwwroot/index.html:3833`, exact):
```html
    <h3>New Scheduled Assessment</h3>
```
Replace with:
```html
    <h3 id="sched-wz-title">New Scheduled Assessment</h3>
```

- [ ] **Step 2: Add new `SCHED` fields**

Find the `SCHED` namespace (lines 17275-17284, exact):
```js
var SCHED = {
  schedules: [],   // raw list from GET /api/scheduled-assessments
  groups: [],      // nested group tree, fetched fresh when the wizard opens
  groupsById: {},  // flat id -> name, built from `groups`
  agentsAll: [],   // flat agent list, fetched fresh when the wizard opens
  selGroups: {},   // groupId -> true for wizard checkbox state
  selAgents: {},   // agentId -> true for wizard checkbox state
  groupsAccessDenied: false, // true when /api/agent-groups 403'd (Analyst), not just empty
  step: 1
};
```
Replace with:
```js
var SCHED = {
  schedules: [],   // raw list from GET /api/scheduled-assessments
  groups: [],      // nested group tree, fetched fresh when the wizard opens
  groupsById: {},  // flat id -> name, built from `groups`
  agentsAll: [],   // flat agent list, fetched fresh when the wizard opens
  selGroups: {},   // groupId -> true for wizard checkbox state
  selAgents: {},   // agentId -> true for wizard checkbox state
  groupsAccessDenied: false, // true when /api/agent-groups 403'd (Analyst), not just empty
  step: 1,
  editingId: null,        // null when creating; the schedule's ID when editing
  editPrefillMode: '',    // consumed once by renderSchedModeRecurrencePane's first render --
  editPrefillTimezone: '' // see that function for why Mode/Timezone need this indirection
};
```

- [ ] **Step 3: Add the Edit button to every schedule row**

Find (`orchestrator/wwwroot/index.html:17361`, exact, the actions cell inside `renderScheduledAssessmentsList()`'s row template):
```js
      '<td>' + (sch.Enabled ? '<button class="btn btn-outline btn-sm" onclick="cancelScheduledAssessment(\'' + x(sch.ID) + '\')">Cancel</button>' : '') + '</td>' +
```
Replace with:
```js
      '<td>' +
        '<button class="btn btn-outline btn-sm" onclick="openSchedWizardForEdit(\'' + x(sch.ID) + '\')">Edit</button>' +
        (sch.Enabled ? ' <button class="btn btn-outline btn-sm" onclick="cancelScheduledAssessment(\'' + x(sch.ID) + '\')">Cancel</button>' : '') +
      '</td>' +
```

- [ ] **Step 4: Reset the new fields in `openSchedWizard()` (the Create path)**

Find (`orchestrator/wwwroot/index.html:17375-17399`, exact):
```js
function openSchedWizard() {
  SCHED.selGroups = {}; SCHED.selAgents = {};
  SCHED.modeInitialized = false;
  SCHED.groupsAccessDenied = false;
  document.getElementById('sched-reason').value = '';
```
Replace with:
```js
function openSchedWizard() {
  SCHED.selGroups = {}; SCHED.selAgents = {};
  SCHED.modeInitialized = false;
  SCHED.groupsAccessDenied = false;
  SCHED.editingId = null;
  SCHED.editPrefillMode = '';
  SCHED.editPrefillTimezone = '';
  document.getElementById('sched-wz-title').textContent = 'New Scheduled Assessment';
  document.getElementById('sched-create-btn').textContent = 'Create Schedule';
  document.getElementById('sched-group-cnt').textContent = '(0 selected)';
  document.getElementById('sched-agent-cnt').textContent = '(0 selected)';
  document.getElementById('sched-reason').value = '';
```
(The rest of `openSchedWizard()`, from `document.getElementById('sched-recurrence-type').value = 'weekly';` through its closing `}`, is unchanged.)

- [ ] **Step 5: Add `openSchedWizardForEdit(id)`**

Add immediately after `openSchedWizard()`'s closing `}` (before `closeSchedWizard()`):
```js
// openSchedWizardForEdit prefills the same wizard openSchedWizard() uses,
// from an existing schedule's current values. Every field can be set with a
// direct .value assignment at this point EXCEPT Mode and Timezone -- #sched-mode
// starts with zero <option> elements (entirely built by
// renderSchedModeRecurrencePane() the first time step 3 renders) and that
// same function's first-render branch unconditionally resets Timezone to the
// browser's local zone. SCHED.editPrefillMode/editPrefillTimezone route
// around that -- see renderSchedModeRecurrencePane's updated first-render
// branch below.
function openSchedWizardForEdit(id) {
  var sch = SCHED.schedules.find(function(s) { return s.ID === id; });
  if (!sch) { showToast('Schedule not found', 'err'); return; }
  var payload = {};
  try { payload = JSON.parse(sch.Payload || '{}'); } catch (e) { payload = {}; }

  SCHED.selGroups = {};
  (sch.GroupIDs || []).forEach(function(gid) { SCHED.selGroups[gid] = true; });
  SCHED.selAgents = {};
  (sch.AgentIDs || []).forEach(function(aid) { SCHED.selAgents[aid] = true; });
  SCHED.modeInitialized = false;
  SCHED.groupsAccessDenied = false;
  SCHED.editingId = sch.ID;
  SCHED.editPrefillMode = sch.Mode || 'posture';
  SCHED.editPrefillTimezone = sch.Timezone || '';

  document.getElementById('sched-wz-title').textContent = 'Edit Scheduled Assessment';
  document.getElementById('sched-create-btn').textContent = 'Save Changes';
  document.getElementById('sched-group-cnt').textContent = '(' + Object.keys(SCHED.selGroups).length + ' selected)';
  document.getElementById('sched-agent-cnt').textContent = '(' + Object.keys(SCHED.selAgents).length + ' selected)';
  document.getElementById('sched-reason').value = sch.Reason || '';
  document.getElementById('sched-recurrence-type').value = sch.RecurrenceType || 'weekly';
  document.getElementById('sched-runat').value = sch.RunAt ? new Date(sch.RunAt).toISOString().slice(0, 16) : '';
  document.getElementById('sched-dow').value = String(sch.DayOfWeek || 0);
  document.getElementById('sched-dom').value = String(sch.DayOfMonth || 1);
  document.getElementById('sched-timeofday').value = sch.TimeOfDay || '02:00';
  document.getElementById('sched-enddate').value = sch.EndDate ? new Date(sch.EndDate).toISOString().slice(0, 10) : '';
  document.getElementById('sched-concurrency').value = sch.ConcurrencyLimit || '';

  var sel = document.getElementById('sched-scenario');
  sel.innerHTML = scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  sel.value = payload.scenarioId || '';

  Promise.all([apicall('/api/agent-groups'), apicall('/api/agents')]).then(function(res) {
    SCHED.groupsAccessDenied = !!(res[0] && res[0].error);
    SCHED.groups = Array.isArray(res[0]) ? res[0] : [];
    SCHED.groupsById = schedFlattenGroupNames(SCHED.groups, {});
    SCHED.agentsAll = Array.isArray(res[1]) ? res[1] : [];
    renderSchedGroupTree();
    renderSchedAgentList();
  }).catch(function(e) { showToast(e.message, 'err'); });
  document.getElementById('sched-overlay').classList.add('open');
  schedWizardSet(1);
}
```

- [ ] **Step 6: Fix `renderSchedModeRecurrencePane()`'s first-render branch**

Find (exact, confirmed):
```js
  if (SCHED.modeInitialized) {
    modeSel.value = prevMode;
    // If the previously-selected mode's option no longer exists (e.g. Back-navigated
    // to step 1 and picked a non-executable scenario while Telemetry was selected),
    // the assignment above silently fails to select anything -- fall back to Posture.
    if (modeSel.value !== prevMode) modeSel.value = 'posture';
  } else {
    modeSel.value = 'posture';
    document.getElementById('sched-timezone').value = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    SCHED.modeInitialized = true;
  }
```
Replace with:
```js
  if (SCHED.modeInitialized) {
    modeSel.value = prevMode;
    // If the previously-selected mode's option no longer exists (e.g. Back-navigated
    // to step 1 and picked a non-executable scenario while Telemetry was selected),
    // the assignment above silently fails to select anything -- fall back to Posture.
    if (modeSel.value !== prevMode) modeSel.value = 'posture';
  } else {
    // First render: default to Posture + the browser's local timezone, UNLESS
    // openSchedWizardForEdit() stashed a prefill (SCHED.editPrefillMode/
    // editPrefillTimezone) -- #sched-mode has no <option> elements until this
    // function builds them above, so an earlier direct .value= assignment at
    // wizard-open time would have been a no-op; this indirection is required.
    var wantMode = SCHED.editPrefillMode || 'posture';
    modeSel.value = wantMode;
    if (modeSel.value !== wantMode) modeSel.value = 'posture';
    document.getElementById('sched-timezone').value = SCHED.editPrefillTimezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    SCHED.modeInitialized = true;
  }
```

- [ ] **Step 7: Branch `submitScheduledAssessment()` on `SCHED.editingId`**

Find (`orchestrator/wwwroot/index.html:17581-17595`, exact):
```js
function submitScheduledAssessment() {
  var payload = schedBuildPayload();
  if (!payload.scenarioId) { showToast('Select a scenario', 'err'); return; }
  if (!payload.agentIds.length && !payload.groupIds.length) { showToast('Select at least one target group or agent', 'err'); return; }
  if (payload.mode === 'telemetry' && !payload.reason) { showToast('Reason is required for a telemetry-mode schedule', 'err'); return; }

  var btn = document.getElementById('sched-create-btn');
  btn.disabled = true;
  apicall('/api/scheduled-assessments', { method: 'POST', body: JSON.stringify(payload) }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); btn.disabled = false; return; }
    showToast('Scheduled assessment created', 'ok');
    closeSchedWizard();
    loadScheduledAssessments();
  }).catch(function(e) { showToast(e.message, 'err'); btn.disabled = false; });
}
```
Replace with:
```js
function submitScheduledAssessment() {
  var payload = schedBuildPayload();
  if (!payload.scenarioId) { showToast('Select a scenario', 'err'); return; }
  if (!payload.agentIds.length && !payload.groupIds.length) { showToast('Select at least one target group or agent', 'err'); return; }
  if (payload.mode === 'telemetry' && !payload.reason) { showToast('Reason is required for a telemetry-mode schedule', 'err'); return; }

  var btn = document.getElementById('sched-create-btn');
  btn.disabled = true;
  var isEdit = !!SCHED.editingId;
  var url = isEdit ? '/api/scheduled-assessments/' + encodeURIComponent(SCHED.editingId) : '/api/scheduled-assessments';
  var method = isEdit ? 'PUT' : 'POST';
  apicall(url, { method: method, body: JSON.stringify(payload) }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); btn.disabled = false; return; }
    showToast(isEdit ? 'Scheduled assessment updated' : 'Scheduled assessment created', 'ok');
    closeSchedWizard();
    loadScheduledAssessments();
  }).catch(function(e) { showToast(e.message, 'err'); btn.disabled = false; });
}
```

- [ ] **Step 8: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 9: Manual browser QA checklist**

(Flag as deferred if no live orchestrator instance with real registered agents/groups is available — same caveat as every other frontend task this session, logged to the Pending Manual QA Backlog memory.)
- Create a Posture-mode schedule, then Edit it: confirm every field (scenario, targets, recurrence, timezone, end date, concurrency) is prefilled correctly across all 4 wizard steps, including after navigating forward to step 3 (Mode/Timezone must NOT reset).
- Save the edit: confirm the toast says "updated", the row reflects the new values, and no re-authorization prompt appeared.
- Create a Telemetry-mode schedule as Admin, then Edit it (change a target): confirm step 4 shows the Telemetry authorization warning and requires re-checking `#sched-auth-check` before Save is enabled; after saving, confirm `ApprovalVersion` incremented (check via the audit log or a direct API call).
- Edit a Telemetry schedule's mode to Posture: confirm no authorization prompt appears and the save succeeds.
- Cancel a schedule, then Edit it: confirm the row's status flips back to Enabled after saving.
- Click "New Scheduled Assessment" (Create) immediately after closing an Edit: confirm the wizard opens blank (no leftover prefilled values), title says "New Scheduled Assessment", and the button says "Create Schedule".

- [ ] **Step 10: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(scheduled-assessments): add Edit to the Scheduled Assessments UI, reusing the Create wizard"
```

---

## Post-implementation

After Task 3's QA passes, this feature is complete: every field of a Scheduled Assessment is editable through the existing Create wizard, Telemetry-mode edits are re-authorized exactly like creation with `ApprovalVersion` tracking the re-approval, and saving an edit revives a Cancelled schedule.
