# Posture Finding Remediation Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the most recent remediation attempt for each SLA finding's current open episode, read-only, on the existing SLA-aware endpoints.

**Architecture:** A read-time `LEFT JOIN LATERAL` from `posture_findings`/`finding_slas` to the pre-existing `remediation_requests` table by `(agent_id, check_id)`, scoped to the current episode's `started_at`. No new schema. A single-record read (`GetPostureFinding`) additionally applies the existing `reapTimedOutRemediation` staleness correction; list reads deliberately do not, matching this codebase's existing `GetRemediation`-vs-`ListAgentRemediations` precedent exactly.

**Tech Stack:** Go, Postgres (`pgxpool`), testcontainers-backed Go tests. No new package, no migration, no live server needed.

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-29-posture-finding-remediation-telemetry-design.md`

## Global Constraints

- Build directly on `main` — no worktree, no branches/PRs.
- Commit after each task; push immediately after every commit.
- Every response this sub-project touches builds `map[string]any`, never a typed struct — `latestRemediation` follows the same convention via `buildLatestRemediation`.
- `latestRemediation` is scoped to the finding's *current* open episode (`requested_at >= finding_slas.started_at`) — never a prior, already-closed episode's attempt.
- `TickSLABreaches` and breach detection/notification are completely untouched by this sub-project.
- No new endpoint, no new permission — only the 3 existing SLA-aware reads gain a field.

---

### Task 1: `latestRemediation` on `ListAgentPostureFindings`/`GetPostureFinding`

**Files:**
- Modify: `orchestrator/internal/api/posture_finding_handlers.go` (`postureFindingCols`, `postureFindingJoin`, `scanPostureFindings`, `GetPostureFinding`; new `buildLatestRemediation`/`reapLatestRemediation`)
- Test: `orchestrator/internal/api/posture_finding_handlers_test.go`

**Interfaces:**
- Consumes: `remediation.IsTerminal(status string) bool`, `remediation.RemediationRequest` (existing, `internal/remediation`), `h.reapTimedOutRemediation(ctx, *remediation.RemediationRequest)` (existing, `remediation_query.go:39`).
- Produces: `buildLatestRemediation(id, remediationID, status, errText *string, tier *int, requestedAt, dispatchedAt, executionCompletedAt, verificationCompletedAt, completedAt *time.Time) map[string]any` — reused by Task 2. A response map gains an optional `"latestRemediation"` key of this shape.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/posture_finding_handlers_test.go`:

```go
func seedRemediationRequest(t *testing.T, pool *pgxpool.Pool, id, agentID, checkID, status string, requestedAt time.Time) {
	t.Helper()
	mustExecAPI(t, pool,
		`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at)
		 VALUES ($1, 'test-remediation', $2, $3, 1, $4, 'user-1', 'test', $5)`,
		id, agentID, checkID, status, requestedAt)
}

func TestListAgentPostureFindings_NoRemediationAttempt_LatestRemediationAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-none", "rt-none", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-none")

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "rt-none")
		w := httptest.NewRecorder()
		h.ListAgentPostureFindings(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if _, present := got[0]["latestRemediation"]; present {
			t.Errorf("latestRemediation present = %v, want absent", got[0]["latestRemediation"])
		}
	})
}

func TestGetPostureFinding_OneRemediationAttempt_Surfaced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-one", "rt-one", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-one")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='rt-one' AND check_id='windows-firewall-enabled'`).Scan(&pfID)
		seedRemediationRequest(t, pool, "rr-one", "rt-one", "windows-firewall-enabled", "running", time.Now().Add(time.Minute))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", pfID)
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)

		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		lr, ok := got["latestRemediation"].(map[string]any)
		if !ok {
			t.Fatalf("latestRemediation missing or wrong shape: %v", got["latestRemediation"])
		}
		if lr["id"] != "rr-one" || lr["status"] != "running" || lr["inProgress"] != true {
			t.Errorf("latestRemediation = %+v, want id=rr-one status=running inProgress=true", lr)
		}
	})
}

func TestGetPostureFinding_MultipleAttempts_NewestWins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-multi", "rt-multi", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-multi")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='rt-multi' AND check_id='windows-firewall-enabled'`).Scan(&pfID)
		seedRemediationRequest(t, pool, "rr-older", "rt-multi", "windows-firewall-enabled", "failed", time.Now().Add(time.Minute))
		seedRemediationRequest(t, pool, "rr-newer", "rt-multi", "windows-firewall-enabled", "completed", time.Now().Add(2*time.Minute))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", pfID)
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)

		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		lr := got["latestRemediation"].(map[string]any)
		if lr["id"] != "rr-newer" {
			t.Errorf("latestRemediation.id = %v, want rr-newer (newest by requested_at)", lr["id"])
		}
	})
}

func TestGetPostureFinding_AttemptFromPriorEpisode_NotSurfaced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('rt-prior', 'RT-PRIOR')`)
		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-rt-prior', 'rt-prior', 'windows-firewall-enabled', 'security-configuration', 'Windows Firewall disabled', 'High', 'open', NOW(), NOW(), NOW())`)

		priorStart := time.Now().Add(-48 * time.Hour)
		priorEnd := time.Now().Add(-24 * time.Hour)
		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status, resolved_at)
			 VALUES ('fs-rt-prior', 'pf-rt-prior', 'High', $1, $2, 'resolved', $2)`,
			priorStart, priorEnd)
		seedRemediationRequest(t, pool, "rr-prior-episode", "rt-prior", "windows-firewall-enabled", "completed", priorStart.Add(time.Hour))

		currentStart := time.Now().Add(-time.Hour)
		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status)
			 VALUES ('fs-rt-current', 'pf-rt-prior', 'High', $1, $2, 'active')`,
			currentStart, time.Now().Add(time.Hour))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "pf-rt-prior")
		w := httptest.NewRecorder()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		h.GetPostureFinding(w, req)

		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if _, present := got["latestRemediation"]; present {
			t.Errorf("latestRemediation present = %v, want absent (only attempt is from a prior, closed episode)", got["latestRemediation"])
		}
	})
}

func TestGetPostureFinding_RemediationInProgress_ReflectsStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	cases := []struct {
		name           string
		status         string
		wantInProgress bool
	}{
		{"non-terminal status is in progress", "verifying", true},
		{"terminal status is not in progress", "completed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
				h := newPostureTestHandler(t, pool)
				agentID := "rt-inprog-" + c.status
				seedPostureCheckRun(t, pool, "rt-run-"+c.status, agentID, "fail", time.Now())
				h.upsertPostureFindingsForRun(context.Background(), "rt-run-"+c.status)

				var pfID string
				pool.QueryRow(context.Background(),
					`SELECT id FROM posture_findings WHERE agent_id=$1 AND check_id='windows-firewall-enabled'`, agentID).Scan(&pfID)
				seedRemediationRequest(t, pool, "rr-"+c.status, agentID, "windows-firewall-enabled", c.status, time.Now().Add(time.Minute))

				req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", pfID)
				w := httptest.NewRecorder()
				h.GetPostureFinding(w, req)

				var got map[string]any
				json.Unmarshal(w.Body.Bytes(), &got)
				lr := got["latestRemediation"].(map[string]any)
				if lr["inProgress"] != c.wantInProgress {
					t.Errorf("inProgress = %v, want %v", lr["inProgress"], c.wantInProgress)
				}
			})
		})
	}
}

func TestGetPostureFinding_StaleDispatchedAttempt_ReapedToTimedOut(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-stale-get", "rt-stale-get", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-stale-get")

		var pfID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM posture_findings WHERE agent_id='rt-stale-get' AND check_id='windows-firewall-enabled'`).Scan(&pfID)
		mustExecAPI(t, pool,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at, dispatched_at)
			 VALUES ('rr-stale-get', 'test-remediation', 'rt-stale-get', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', $1, $2)`,
			time.Now().Add(time.Minute), time.Now().Add(-2*time.Hour))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", pfID)
		w := httptest.NewRecorder()
		h.GetPostureFinding(w, req)

		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		lr := got["latestRemediation"].(map[string]any)
		if lr["status"] != "timed_out" {
			t.Errorf("status = %v, want timed_out (GetPostureFinding must reap a stale dispatched attempt)", lr["status"])
		}

		var dbStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id='rr-stale-get'`).Scan(&dbStatus)
		if dbStatus != "timed_out" {
			t.Errorf("db status = %q, want timed_out (reap must persist, not just affect the response)", dbStatus)
		}
	})
}

func TestListAgentPostureFindings_StaleDispatchedAttempt_NotReaped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newPostureTestHandler(t, pool)
		seedPostureCheckRun(t, pool, "rt-run-stale-list", "rt-stale-list", "fail", time.Now())
		h.upsertPostureFindingsForRun(context.Background(), "rt-run-stale-list")
		mustExecAPI(t, pool,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at, dispatched_at)
			 VALUES ('rr-stale-list', 'test-remediation', 'rt-stale-list', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test', $1, $2)`,
			time.Now().Add(time.Minute), time.Now().Add(-2*time.Hour))

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "rt-stale-list")
		w := httptest.NewRecorder()
		h.ListAgentPostureFindings(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		lr := got[0]["latestRemediation"].(map[string]any)
		if lr["status"] != "dispatched" {
			t.Errorf("status = %v, want still dispatched (ListAgentPostureFindings must NOT reap, matching ListAgentRemediations' precedent)", lr["status"])
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListAgentPostureFindings_NoRemediationAttempt|TestGetPostureFinding_OneRemediationAttempt|TestGetPostureFinding_MultipleAttempts|TestGetPostureFinding_AttemptFromPriorEpisode|TestGetPostureFinding_RemediationInProgress|TestGetPostureFinding_StaleDispatchedAttempt|TestListAgentPostureFindings_StaleDispatchedAttempt' -v`
Expected: FAIL — `latestRemediation` never appears (columns not yet queried), or compile errors if a referenced field doesn't exist yet

- [ ] **Step 3: Add `buildLatestRemediation` and extend the join**

In `orchestrator/internal/api/posture_finding_handlers.go`, replace `postureFindingCols`/`postureFindingJoin`/`scanPostureFindings` with:

```go
const postureFindingCols = `pf.id, pf.agent_id, pf.check_id, pf.category, pf.title, pf.severity, pf.status,
	pf.occurrence_count, pf.reopened_count, pf.first_seen, pf.last_seen, pf.last_observed_at,
	COALESCE(pf.last_run_id,''), pf.resolved_at, pf.resolved_reason,
	fs.status, fs.started_at, fs.deadline_at, fs.breached_at,
	rr.id, rr.remediation_id, rr.tier, rr.status, rr.error, rr.requested_at, rr.dispatched_at,
	rr.execution_completed_at, rr.verification_completed_at, rr.completed_at`

const postureFindingJoin = `FROM posture_findings pf
	LEFT JOIN LATERAL (
		SELECT status, started_at, deadline_at, breached_at
		  FROM finding_slas
		 WHERE posture_finding_id = pf.id
		 ORDER BY started_at DESC LIMIT 1
	) fs ON true
	LEFT JOIN LATERAL (
		SELECT id, remediation_id, tier, status, error, requested_at, dispatched_at,
		       execution_completed_at, verification_completed_at, completed_at
		  FROM remediation_requests
		 WHERE agent_id = pf.agent_id AND check_id = pf.check_id
		   AND requested_at >= COALESCE(fs.started_at, '-infinity')
		 ORDER BY requested_at DESC, id DESC LIMIT 1
	) rr ON true`

// buildLatestRemediation turns one rr.* row (all nullable -- a LEFT JOIN
// LATERAL ... ON true still yields exactly one row of NULLs when nothing
// matches) into the latestRemediation JSON object, or nil when nothing
// matched. Shared by scanPostureFindings and GetSLABreaches.
func buildLatestRemediation(id, remediationID, status, errText *string, tier *int,
	requestedAt, dispatchedAt, executionCompletedAt, verificationCompletedAt, completedAt *time.Time) map[string]any {
	if id == nil {
		return nil
	}
	m := map[string]any{
		"id": *id, "remediationId": *remediationID, "tier": *tier, "status": *status,
		"inProgress": !remediation.IsTerminal(*status), "requestedAt": *requestedAt,
	}
	if errText != nil && *errText != "" {
		m["error"] = *errText
	}
	if dispatchedAt != nil {
		m["dispatchedAt"] = *dispatchedAt
	}
	if executionCompletedAt != nil {
		m["executionCompletedAt"] = *executionCompletedAt
	}
	if verificationCompletedAt != nil {
		m["verificationCompletedAt"] = *verificationCompletedAt
	}
	if completedAt != nil {
		m["completedAt"] = *completedAt
	}
	return m
}

func scanPostureFindings(rows findingScanner) []map[string]any {
	out := []map[string]any{}
	for rows.Next() {
		var id, agentID, checkID, category, title, severity, status, lastRunID string
		var occ, reopened int
		var firstSeen, lastSeen, lastObserved time.Time
		var resolvedAt *time.Time
		var resolvedReason *string
		var slaStatus *string
		var slaStartedAt, slaDeadlineAt, slaBreachedAt *time.Time
		var rrID, rrRemediationID, rrStatus, rrError *string
		var rrTier *int
		var rrRequestedAt, rrDispatchedAt, rrExecutionCompletedAt, rrVerificationCompletedAt, rrCompletedAt *time.Time
		if rows.Scan(&id, &agentID, &checkID, &category, &title, &severity, &status,
			&occ, &reopened, &firstSeen, &lastSeen, &lastObserved, &lastRunID, &resolvedAt, &resolvedReason,
			&slaStatus, &slaStartedAt, &slaDeadlineAt, &slaBreachedAt,
			&rrID, &rrRemediationID, &rrTier, &rrStatus, &rrError, &rrRequestedAt, &rrDispatchedAt,
			&rrExecutionCompletedAt, &rrVerificationCompletedAt, &rrCompletedAt) != nil {
			continue
		}
		m := map[string]any{
			"id": id, "agentId": agentID, "checkId": checkID, "category": category,
			"title": title, "severity": severity, "status": status,
			"occurrenceCount": occ, "reopenedCount": reopened,
			"firstSeen": firstSeen, "lastSeen": lastSeen, "lastObservedAt": lastObserved,
			"lastRunId": lastRunID,
		}
		if resolvedAt != nil {
			m["resolvedAt"] = *resolvedAt
		}
		if resolvedReason != nil {
			m["resolvedReason"] = *resolvedReason
		}
		if slaStatus != nil {
			m["slaStatus"] = *slaStatus
		}
		if slaStartedAt != nil {
			m["slaStartedAt"] = *slaStartedAt
		}
		if slaDeadlineAt != nil {
			m["slaDeadlineAt"] = *slaDeadlineAt
		}
		if slaBreachedAt != nil {
			m["slaBreachedAt"] = *slaBreachedAt
		}
		if lr := buildLatestRemediation(rrID, rrRemediationID, rrStatus, rrError, rrTier,
			rrRequestedAt, rrDispatchedAt, rrExecutionCompletedAt, rrVerificationCompletedAt, rrCompletedAt); lr != nil {
			m["latestRemediation"] = lr
		}
		out = append(out, m)
	}
	return out
}
```

Add `"github.com/audspect/bas/internal/remediation"` to this file's import block.

- [ ] **Step 4: Add `reapLatestRemediation` and call it from `GetPostureFinding`**

Replace `GetPostureFinding` with:

```go
// GetPostureFinding returns one posture finding by ID. GET /api/posture-findings/{id}
func (h *Handler) GetPostureFinding(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` `+postureFindingJoin+` WHERE pf.id=$1`, chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list := scanPostureFindings(rows)
	rows.Close()
	if len(list) == 0 {
		jsonError(w, "posture finding not found", http.StatusNotFound)
		return
	}
	found := list[0]
	h.reapLatestRemediation(r.Context(), found)
	respond(w, found)
}

// reapLatestRemediation applies the same on-read staleness correction
// GetRemediation already does (reapTimedOutRemediation, remediation_query.go)
// to found's latestRemediation entry, if present, mutating found in place.
// Only called from GetPostureFinding (single-record read) -- list endpoints
// deliberately skip this, matching ListAgentRemediations' own existing
// precedent of not reaping on every list poll.
func (h *Handler) reapLatestRemediation(ctx context.Context, found map[string]any) {
	lr, ok := found["latestRemediation"].(map[string]any)
	if !ok {
		return
	}
	req := remediation.RemediationRequest{
		ID:            lr["id"].(string),
		RemediationID: lr["remediationId"].(string),
		Status:        lr["status"].(string),
	}
	if dispatchedAt, ok := lr["dispatchedAt"].(time.Time); ok {
		req.DispatchedAt = &dispatchedAt
	}
	h.reapTimedOutRemediation(ctx, &req)
	if req.Status != lr["status"] {
		lr["status"] = req.Status
		lr["inProgress"] = !remediation.IsTerminal(req.Status)
	}
}
```

`ListAgentPostureFindings` is unmodified — it automatically gains `latestRemediation` via the extended `scanPostureFindings`, with no reap call.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListAgentPostureFindings_NoRemediationAttempt|TestGetPostureFinding_OneRemediationAttempt|TestGetPostureFinding_MultipleAttempts|TestGetPostureFinding_AttemptFromPriorEpisode|TestGetPostureFinding_RemediationInProgress|TestGetPostureFinding_StaleDispatchedAttempt|TestListAgentPostureFindings_StaleDispatchedAttempt' -v`
Expected: PASS (all 7 test functions, including both subtests of `TestGetPostureFinding_RemediationInProgress_ReflectsStatus`)

- [ ] **Step 6: Run the full posture/SLA test surface to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'PostureFinding|SLA' -v`
Expected: all PASS — every test from Sub-projects A, B, and this task

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/posture_finding_handlers.go orchestrator/internal/api/posture_finding_handlers_test.go
git commit -m "feat: surface latest remediation attempt on posture-finding reads

ListAgentPostureFindings and GetPostureFinding now include
latestRemediation (id/status/tier/timestamps/inProgress) via a second
LEFT JOIN LATERAL to remediation_requests, scoped to the finding's
current open episode. GetPostureFinding additionally reaps a stale
dispatched/running/verifying attempt to timed_out before responding,
matching GetRemediation's existing precedent; the list endpoint
deliberately does not, matching ListAgentRemediations'."
git push
```

---

### Task 2: `latestRemediation` on `GetSLABreaches`

**Files:**
- Modify: `orchestrator/internal/api/sla_handlers.go` (`GetSLABreaches`)
- Test: `orchestrator/internal/api/sla_handlers_test.go`

**Interfaces:**
- Consumes: `buildLatestRemediation` (Task 1, same package `api`, no import needed).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/sla_handlers_test.go`:

```go
func TestGetSLABreaches_IncludesLatestRemediation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('breach-rt1', 'BREACH-RT1')`)
		breachedAt := time.Now().Add(-1 * time.Hour)
		seedFindingSLA(t, pool, "fs-breach-rt", "breach-rt1", "windows-firewall-enabled", "High", "breached", time.Now().Add(-2*time.Hour), &breachedAt)
		mustExecAPI(t, pool,
			`INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason, requested_at)
			 VALUES ('rr-breach-rt', 'test-remediation', 'breach-rt1', 'windows-firewall-enabled', 1, 'failed', 'user-1', 'test', $1)`,
			time.Now().Add(-30*time.Minute))

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/breaches", nil)
		w := httptest.NewRecorder()
		h.GetSLABreaches(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		lr, ok := got[0]["latestRemediation"].(map[string]any)
		if !ok {
			t.Fatalf("latestRemediation missing or wrong shape: %v", got[0]["latestRemediation"])
		}
		if lr["id"] != "rr-breach-rt" || lr["status"] != "failed" || lr["inProgress"] != false {
			t.Errorf("latestRemediation = %+v, want id=rr-breach-rt status=failed inProgress=false", lr)
		}
	})
}

func TestGetSLABreaches_NoRemediationAttempt_LatestRemediationAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('breach-rt2', 'BREACH-RT2')`)
		breachedAt := time.Now().Add(-1 * time.Hour)
		seedFindingSLA(t, pool, "fs-breach-rt2", "breach-rt2", "windows-smbv1-disabled", "High", "breached", time.Now().Add(-2*time.Hour), &breachedAt)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/breaches", nil)
		w := httptest.NewRecorder()
		h.GetSLABreaches(w, req)

		var got []map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if _, present := got[0]["latestRemediation"]; present {
			t.Errorf("latestRemediation present = %v, want absent", got[0]["latestRemediation"])
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetSLABreaches_IncludesLatestRemediation|TestGetSLABreaches_NoRemediationAttempt' -v`
Expected: FAIL — `latestRemediation` never appears

- [ ] **Step 3: Extend `GetSLABreaches`**

Replace `GetSLABreaches` in `orchestrator/internal/api/sla_handlers.go` with:

```go
// GetSLABreaches returns every currently-breached finding, oldest breach
// first. GET /api/sla/breaches
func (h *Handler) GetSLABreaches(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT pf.agent_id, pf.check_id, pf.title, pf.severity, pf.category, fs.breached_at, fs.deadline_at,
		        rr.id, rr.remediation_id, rr.tier, rr.status, rr.error, rr.requested_at, rr.dispatched_at,
		        rr.execution_completed_at, rr.verification_completed_at, rr.completed_at
		   FROM finding_slas fs
		   JOIN posture_findings pf ON pf.id = fs.posture_finding_id
		   LEFT JOIN LATERAL (
		       SELECT id, remediation_id, tier, status, error, requested_at, dispatched_at,
		              execution_completed_at, verification_completed_at, completed_at
		         FROM remediation_requests
		        WHERE agent_id = pf.agent_id AND check_id = pf.check_id
		          AND requested_at >= COALESCE(fs.started_at, '-infinity')
		        ORDER BY requested_at DESC, id DESC LIMIT 1
		   ) rr ON true
		  WHERE fs.status = 'breached'
		  ORDER BY fs.breached_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var agentID, checkID, title, severity, category string
		var breachedAt, deadlineAt time.Time
		var rrID, rrRemediationID, rrStatus, rrError *string
		var rrTier *int
		var rrRequestedAt, rrDispatchedAt, rrExecutionCompletedAt, rrVerificationCompletedAt, rrCompletedAt *time.Time
		if rows.Scan(&agentID, &checkID, &title, &severity, &category, &breachedAt, &deadlineAt,
			&rrID, &rrRemediationID, &rrTier, &rrStatus, &rrError, &rrRequestedAt, &rrDispatchedAt,
			&rrExecutionCompletedAt, &rrVerificationCompletedAt, &rrCompletedAt) != nil {
			continue
		}
		m := map[string]any{
			"agentId": agentID, "checkId": checkID, "title": title, "severity": severity,
			"category": category, "breachedAt": breachedAt, "deadlineAt": deadlineAt,
		}
		if lr := buildLatestRemediation(rrID, rrRemediationID, rrStatus, rrError, rrTier,
			rrRequestedAt, rrDispatchedAt, rrExecutionCompletedAt, rrVerificationCompletedAt, rrCompletedAt); lr != nil {
			m["latestRemediation"] = lr
		}
		out = append(out, m)
	}
	respond(w, out)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetSLABreaches' -v`
Expected: PASS (both new tests plus the existing `TestGetSLABreaches_ReturnsOnlyBreachedOldestFirst` from Sub-project B)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/sla_handlers.go orchestrator/internal/api/sla_handlers_test.go
git commit -m "feat: surface latest remediation attempt on the fleet breach report

GET /api/sla/breaches now includes latestRemediation on each row, same
join and scoping as ListAgentPostureFindings/GetPostureFinding."
git push
```

---

### Task 3: Full-suite verification

No commit for this task — verification only, mirroring Sub-projects A and B's final task.

- [ ] **Step 1: Run the full `internal/api` package**

Run: `cd orchestrator && go test ./internal/api/... -v`
Expected: zero `FAIL` lines. If the whole-package run times out or hits a resource-contention-shaped failure (the documented class in `[[project_endpoint_health_remediation]]` — a `panic: test timed out` with a goroutine dump, unrelated to any file this plan touches), re-run just that failing test name in isolation with `-run '^TestName$'` to confirm it passes clean alone before concluding it's contention and not a real regression. Do not skip this confirmation step.

- [ ] **Step 2: Run the adjacent packages directly**

Run: `cd orchestrator && go test ./internal/slapolicy/... ./internal/findings/... ./internal/endpointrisk/... ./internal/notifications/... ./internal/remediation/... -v`
Expected: all PASS

- [ ] **Step 3: Confirm no unrelated diff**

Run: `cd "C:\Users\Administrator\Downloads\Audspect_Cloud" && git status --porcelain orchestrator/internal/findings orchestrator/internal/endpointrisk orchestrator/internal/remediation orchestrator/wwwroot`
Expected: empty output (this plan never touches any of these)

- [ ] **Step 4: Report completion**

Summarize what shipped (both implementation tasks + this verification) and confirm nothing is pending. This repo builds directly on `main` with no worktree, so `finishing-a-development-branch`'s cleanup step is a no-op here, same as Sub-projects A and B.
