package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ws"
)

func TestUnenrollAgent_SetsStateToRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `
			INSERT INTO agents (agent_id, hostname, status, state, last_update)
			VALUES ('agent-1', 'host-1', 'idle', 'active', NOW())`)

		h := &Handler{db: pool, hub: ws.NewHub()}
		body := strings.NewReader(`{"agentId":"agent-1"}`)
		rec := httptest.NewRecorder()
		h.UnenrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/unenroll", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got struct {
			AgentID string `json:"agentId"`
			State   string `json:"state"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if got.State != "retired" {
			t.Errorf("response state = %q, want retired", got.State)
		}

		var dbState string
		if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id = 'agent-1'`).Scan(&dbState); err != nil {
			t.Fatalf("query agent state: %v", err)
		}
		if dbState != "retired" {
			t.Errorf("agents.state = %q, want retired", dbState)
		}
	})
}

func TestUnenrollAgent_UnknownAgent_Returns404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		body := strings.NewReader(`{"agentId":"does-not-exist"}`)
		rec := httptest.NewRecorder()
		h.UnenrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/unenroll", body))
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404, body: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestUnenrollAgent_WrongToken_Returns401(t *testing.T) {
	h := &Handler{agentSecret: "shh"}
	body := strings.NewReader(`{"agentId":"agent-1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/agents/unenroll", body)
	req.Header.Set("X-Agent-Token", "wrong")
	rec := httptest.NewRecorder()
	h.UnenrollAgent(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body: %s", rec.Code, rec.Body.String())
	}
}
