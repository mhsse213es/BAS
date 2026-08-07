package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUninstallAgent_RequiresReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		body, _ := json.Marshal(map[string]string{"reason": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/agent-x/uninstall", bytes.NewReader(body)), "agentId", "agent-x")
		rec := httptest.NewRecorder()
		h.UninstallAgent(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("empty reason: status = %d, want 400", rec.Code)
		}
	})
}

// Uninstall Agent must never silently claim success for an unreachable
// endpoint -- unlike Force Remove, it requires a live connection.
func TestUninstallAgent_NotConnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-uninstall-notconn"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))

		body, _ := json.Marshal(map[string]string{"reason": "decommissioning"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/uninstall", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.UninstallAgent(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("agent not connected: status = %d, want 503", rec.Code)
		}

		var state string
		if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, agentID).Scan(&state); err != nil {
			t.Fatalf("read state: %v", err)
		}
		if state == string(models.AgentStateUninstalling) {
			t.Fatalf("state = %q, must not become uninstalling when dispatch failed", state)
		}
	})
}

// A connected agent gets marked uninstalling and keeps its prior state on
// record so a failed/timed-out attempt can restore it.
func TestUninstallAgent_Connected_MarksUninstalling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		hub := ws.NewHub()
		h := New(pool, hub, nil, "")
		agentID := "agent-uninstall-connected"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		fake := startFakeAgent(t, hub, agentID)

		body, _ := json.Marshal(map[string]string{"reason": "decommissioning"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/uninstall", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.UninstallAgent(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("dispatch: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandUninstallAgent {
			t.Fatalf("WS message type = %q, want %q", env.Type, models.MsgCommandUninstallAgent)
		}

		var state, priorState string
		if err := pool.QueryRow(context.Background(),
			`SELECT state, uninstall_prior_state FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&state, &priorState); err != nil {
			t.Fatalf("read: %v", err)
		}
		if state != string(models.AgentStateUninstalling) {
			t.Fatalf("state = %q, want uninstalling", state)
		}
		if priorState != "active" {
			t.Fatalf("uninstall_prior_state = %q, want active", priorState)
		}
	})
}

// A successful result must move the agent to 'uninstalled' and clear any
// prior error.
func TestUninstallAgentResult_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-uninstall-result-ok"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET state='uninstalling', uninstall_prior_state='active', uninstall_error='stale' WHERE agent_id=$1`, agentID); err != nil {
			t.Fatalf("seed uninstalling state: %v", err)
		}

		body, _ := json.Marshal(map[string]any{"success": true})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/uninstall-result", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.UninstallAgentResult(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var state string
		var uninstallError *string
		if err := pool.QueryRow(context.Background(),
			`SELECT state, uninstall_error FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&state, &uninstallError); err != nil {
			t.Fatalf("read: %v", err)
		}
		if state != string(models.AgentStateUninstalled) {
			t.Fatalf("state = %q, want uninstalled", state)
		}
		if uninstallError != nil {
			t.Fatalf("uninstall_error = %q, want cleared", *uninstallError)
		}
	})
}

// A failed result must restore the prior state and record the error, not
// leave the agent stuck in 'uninstalling' or silently marked gone.
func TestUninstallAgentResult_Failure_RestoresPriorState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-uninstall-result-fail"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET state='uninstalling', uninstall_prior_state='restricted' WHERE agent_id=$1`, agentID); err != nil {
			t.Fatalf("seed uninstalling state: %v", err)
		}

		body, _ := json.Marshal(map[string]any{"success": false, "error": "service delete failed: access denied"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/uninstall-result", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.UninstallAgentResult(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var state, uninstallError string
		if err := pool.QueryRow(context.Background(),
			`SELECT state, uninstall_error FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&state, &uninstallError); err != nil {
			t.Fatalf("read: %v", err)
		}
		if state != "restricted" {
			t.Fatalf("state = %q, want restored to restricted", state)
		}
		if uninstallError != "service delete failed: access denied" {
			t.Fatalf("uninstall_error = %q, want the reported message", uninstallError)
		}
	})
}

// GetAgents must surface a live timeout message for an agent stuck in
// 'uninstalling' past the timeout window, without writing anything to the DB.
func TestGetAgents_UninstallTimeoutDisplayedLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-uninstall-timeout"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		staleRequestedAt := time.Now().Add(-5 * time.Minute)
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET state='uninstalling', uninstall_requested_at=$1 WHERE agent_id=$2`, staleRequestedAt, agentID); err != nil {
			t.Fatalf("seed stale uninstalling state: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		var agents []models.Agent
		if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var found *models.Agent
		for i := range agents {
			if agents[i].AgentID == agentID {
				found = &agents[i]
			}
		}
		if found == nil {
			t.Fatal("agent missing from GetAgents")
		}
		if found.UninstallError == nil || *found.UninstallError == "" {
			t.Fatal("expected a live timeout message, got none")
		}

		var storedError *string
		if err := pool.QueryRow(context.Background(), `SELECT uninstall_error FROM agents WHERE agent_id=$1`, agentID).Scan(&storedError); err != nil {
			t.Fatalf("read stored error: %v", err)
		}
		if storedError != nil {
			t.Fatalf("stored uninstall_error = %q, want nil -- timeout display must not write to the DB", *storedError)
		}
	})
}
