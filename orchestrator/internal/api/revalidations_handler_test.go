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
