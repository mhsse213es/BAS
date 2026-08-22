package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

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

func TestGetJob_IncludesProgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gj-a1', 'GJ-A1')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gj-a2', 'GJ-A2')`)

		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"gj-a1", "gj-a2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, err := jobsStore.ListTargets(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if err := jobsStore.MarkTargetTerminal(context.Background(), targets[0].ID, jobs.TargetStateCompleted, ""); err != nil {
			t.Fatalf("MarkTargetTerminal: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "jobId", job.ID)
		w := httptest.NewRecorder()
		h.GetJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var resp struct {
			Progress jobs.JobProgress `json:"progress"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Progress.Total != 2 || resp.Progress.Completed != 1 || resp.Progress.Pending != 1 {
			t.Errorf("progress = %+v, want Total=2 Completed=1 Pending=1", resp.Progress)
		}
		if resp.Progress.PercentComplete != 50 {
			t.Errorf("PercentComplete = %v, want 50", resp.Progress.PercentComplete)
		}
	})
}

func TestCreateBatchRemediationJob_CreatesJobWithOneTargetPerAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbh-a1', 'JBH-A1')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbh-a2', 'JBH-A2')`)

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		dispatcher := jobs.NewDispatcher(jobsStore)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, dispatcher)

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "test batch",
			"agentIds":      []string{"jbh-a1", "jbh-a2"},
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			JobID       string `json:"jobId"`
			TargetCount int    `json:"targetCount"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.TargetCount != 2 {
			t.Errorf("targetCount = %d, want 2", resp.TargetCount)
		}
		targets, err := jobsStore.ListTargets(context.Background(), resp.JobID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if len(targets) != 2 {
			t.Fatalf("ListTargets() = %d rows, want 2", len(targets))
		}
	})
}

func TestCreateBatchRemediationJob_Tier2WithoutApprovePermission_Forbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbh-a3', 'JBH-A3')`)

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		dispatcher := jobs.NewDispatcher(jobsStore)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, dispatcher)

		body, _ := json.Marshal(map[string]any{
			"remediationId": "disable_windows_smbv1", // Tier 2
			"reason":        "test batch",
			"agentIds":      []string{"jbh-a3"},
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 (Tier 2 requires an Administrator)", w.Code)
		}
	})
}

func TestCreateBatchRemediationJob_TierManualGuidance_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		dispatcher := jobs.NewDispatcher(jobsStore)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, dispatcher)

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_bitlocker", // Tier 4, manual guidance only
			"reason":        "test batch",
			"agentIds":      []string{"jbh-a4"},
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (Tier 4 is manual guidance only)", w.Code)
		}
	})
}

func TestCreateBatchRemediationJob_EmptyAgentIds_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		dispatcher := jobs.NewDispatcher(jobsStore)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, dispatcher)

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "test batch",
			"agentIds":      []string{},
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (empty agentIds)", w.Code)
		}
	})
}

func TestGetJob_ReturnsJobAndTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbg-a1', 'JBG-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"jbg-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "jobId", created.ID)
		w := httptest.NewRecorder()
		h.GetJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Job     jobs.Job         `json:"job"`
			Targets []jobs.JobTarget `json:"targets"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Job.ID != created.ID || len(resp.Targets) != 1 {
			t.Errorf("resp = %+v, want Job.ID=%s and 1 target", resp, created.ID)
		}
	})
}

func TestGetJob_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "jobId", "no-such-job")
		w := httptest.NewRecorder()
		h.GetJob(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestCancelJob_CancelsPendingTargetsAndJob(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbc-a1', 'JBC-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"jbc-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "jobId", created.ID)
		w := httptest.NewRecorder()
		h.CancelJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		got, err := jobsStore.Get(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.State != jobs.JobStateCancelled {
			t.Errorf("job State = %q, want cancelled", got.State)
		}
	})
}

func TestCancelJob_EmitsJobCancelledNotification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jcn-a1', 'JCN-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"jcn-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithNotifications(notifStore)

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "jobId", created.ID)
		w := httptest.NewRecorder()
		h.CancelJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		events, err := notifStore.List(context.Background(), notifications.ListFilter{JobID: created.ID, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 1 || events[0].Type != notifications.EventJobCancelled {
			t.Fatalf("events = %+v, want exactly one job_cancelled event", events)
		}
		if events[0].Metadata["cancelledCount"] != float64(1) {
			t.Errorf("Metadata[cancelledCount] = %v, want 1 (json.Unmarshal decodes numbers as float64)", events[0].Metadata["cancelledCount"])
		}
	})
}

func TestCancelJob_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "jobId", "no-such-job")
		w := httptest.NewRecorder()
		h.CancelJob(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestCreateBatchRemediationJob_ScheduledAt_SetsJobScheduledAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbs-a1', 'JBS-A1')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "scheduled batch",
			"agentIds":      []string{"jbs-a1"},
			"scheduledAt":   future,
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			JobID string `json:"jobId"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got, err := jobsStore.Get(context.Background(), resp.JobID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.ScheduledAt == nil {
			t.Fatal("job.ScheduledAt is nil, want the requested future time")
		}
	})
}

func TestCreateBatchRemediationJob_InvalidScheduledAt_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jbs-a2', 'JBS-A2')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "test",
			"agentIds":      []string{"jbs-a2"},
			"scheduledAt":   "not-a-timestamp",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateBatchRemediationJob(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for an unparseable scheduledAt", w.Code)
		}
	})
}

func TestListJobs_NoFilterReturnsEverything(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('lj-a1', 'LJ-A1')`)
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"lj-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/jobs", nil)
		w := httptest.NewRecorder()
		h.ListJobs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Jobs []struct {
				ID string `json:"id"`
			} `json:"jobs"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		found := false
		for _, j := range resp.Jobs {
			if j.ID == job.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("jobs = %+v, want to include %q", resp.Jobs, job.ID)
		}
	})
}

func TestListJobs_EmptyInitiativeIdFiltersToUnassigned(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('lj-a2', 'LJ-A2')`)
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		unassigned, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"lj-a2"})
		if err != nil {
			t.Fatalf("CreateBatch unassigned: %v", err)
		}
		assigned, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"lj-a2"})
		if err != nil {
			t.Fatalf("CreateBatch assigned: %v", err)
		}
		if _, err := jobsStore.SetJobInitiative(context.Background(), assigned.ID, "some-initiative"); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/jobs?initiativeId=", nil)
		w := httptest.NewRecorder()
		h.ListJobs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Jobs []struct {
				ID string `json:"id"`
			} `json:"jobs"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		foundUnassigned, foundAssigned := false, false
		for _, j := range resp.Jobs {
			if j.ID == unassigned.ID {
				foundUnassigned = true
			}
			if j.ID == assigned.ID {
				foundAssigned = true
			}
		}
		if !foundUnassigned {
			t.Error("expected the unassigned job in the response")
		}
		if foundAssigned {
			t.Error("did not expect the assigned job in an initiativeId=\"\" filtered response")
		}
	})
}
