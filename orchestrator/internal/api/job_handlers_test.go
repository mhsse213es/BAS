package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

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
