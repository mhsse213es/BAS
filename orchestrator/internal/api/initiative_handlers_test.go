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

	"github.com/audspect/bas/internal/initiatives"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// waitForAuditLog polls for an audit_logs row up to 2s -- auditLog/auditLogAs
// write asynchronously via a fire-and-forget goroutine (see audit.go), so
// asserting immediately after a handler call races that write.
func waitForAuditLog(t *testing.T, pool *pgxpool.Pool, action, resource string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM audit_logs WHERE action=$1 AND resource=$2`, action, resource,
		).Scan(&count); err != nil {
			t.Fatalf("query audit_logs: %v", err)
		}
		if count == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no audit_logs row for action=%q resource=%q within 2s", action, resource)
}

func TestCreateInitiative_CreatesActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithInitiatives(initiatives.NewStore(pool))

		body, _ := json.Marshal(map[string]string{"name": "Q3 Patch Compliance", "description": "quarterly push"})
		req := httptest.NewRequest(http.MethodPost, "/api/initiatives", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.CreateInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Initiative initiatives.Initiative `json:"initiative"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Initiative.State != initiatives.StateActive {
			t.Errorf("State = %q, want %q", resp.Initiative.State, initiatives.StateActive)
		}
	})
}

func TestAssignJobInitiative_RejectsNonActiveInitiative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('aji-a1', 'AJI-A1')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"aji-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		it, err := initStore.Create(context.Background(), "closed-init", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := initStore.Close(context.Background(), it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}

		body, _ := json.Marshal(map[string]string{"initiativeId": it.ID})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "jobId", job.ID)
		w := httptest.NewRecorder()
		h.SetJobInitiative(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, body = %s, want 409", w.Code, w.Body.String())
		}
	})
}

func TestAssignJobInitiative_NonexistentInitiative_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('aji-a2', 'AJI-A2')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"aji-a2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		body, _ := json.Marshal(map[string]string{"initiativeId": "no-such-initiative"})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "jobId", job.ID)
		w := httptest.NewRecorder()
		h.SetJobInitiative(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want 404", w.Code, w.Body.String())
		}
	})
}

func TestAssignJobInitiative_DetachAlwaysAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('aji-a3', 'AJI-A3')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"aji-a3"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		it, err := initStore.Create(context.Background(), "detach-target", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := initStore.Close(context.Background(), it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := jobsStore.SetJobInitiative(context.Background(), job.ID, it.ID); err != nil {
			t.Fatalf("seed SetJobInitiative: %v", err)
		}

		body, _ := json.Marshal(map[string]string{"initiativeId": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/x", bytes.NewReader(body)), "jobId", job.ID)
		w := httptest.NewRecorder()
		h.SetJobInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s, want 200 (detach always allowed even from a closed initiative)", w.Code, w.Body.String())
		}
	})
}

func TestCloseInitiative_WritesAuditLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "audit-close", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.CloseInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		waitForAuditLog(t, pool, "initiatives.closed", it.ID)
	})
}

func TestArchiveInitiative_RejectsNonClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "archive-reject", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.ArchiveInitiative(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, body = %s, want 409", w.Code, w.Body.String())
		}
	})
}

func TestGetInitiative_ReturnsProgressAndJobList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gi-a1', 'GI-A1')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "detail-view", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"gi-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if _, err := jobsStore.SetJobInitiative(context.Background(), job.ID, it.ID); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.GetInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Initiative initiatives.Initiative `json:"initiative"`
			Progress   initiatives.Progress   `json:"progress"`
			Jobs       []struct {
				ID string `json:"id"`
			} `json:"jobs"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Progress.Total != 1 {
			t.Errorf("Progress.Total = %d, want 1", resp.Progress.Total)
		}
		if len(resp.Jobs) != 1 || resp.Jobs[0].ID != job.ID {
			t.Errorf("Jobs = %+v, want exactly the one seeded job", resp.Jobs)
		}
	})
}

func TestDeleteInitiative_RejectsNonArchived(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "delete-reject", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.DeleteInitiative(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, body = %s, want 409", w.Code, w.Body.String())
		}
	})
}

func TestDeleteInitiative_RejectsWithJobsAttached(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('di-a1', 'DI-A1')`)
		jobsStore := jobs.NewStore(pool)
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "delete-jobs-reject", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := initStore.Close(context.Background(), it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := initStore.Archive(context.Background(), it.ID); err != nil {
			t.Fatalf("Archive: %v", err)
		}
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"di-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if _, err := jobsStore.SetJobInitiative(context.Background(), job.ID, it.ID); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.DeleteInitiative(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, body = %s, want 409", w.Code, w.Body.String())
		}
	})
}

func TestDeleteInitiative_SucceedsAndWritesAuditLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		initStore := initiatives.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithInitiatives(initStore)

		it, err := initStore.Create(context.Background(), "delete-succeeds", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := initStore.Close(context.Background(), it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := initStore.Archive(context.Background(), it.ID); err != nil {
			t.Fatalf("Archive: %v", err)
		}

		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "initiativeId", it.ID)
		w := httptest.NewRecorder()
		h.DeleteInitiative(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		if _, err := initStore.Get(context.Background(), it.ID); err == nil {
			t.Error("Get after delete: expected an error, got nil")
		}
		waitForAuditLog(t, pool, "initiatives.deleted", it.ID)
	})
}
