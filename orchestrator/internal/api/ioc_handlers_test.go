package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedIOC(t *testing.T, pool *pgxpool.Pool, iocType, value, agentID, scenarioID string) {
	t.Helper()
	var id string
	mustExecAPIReturning(t, pool, &id, `
		INSERT INTO iocs (type, value, source) VALUES ($1, $2, 'detection_alert')
		ON CONFLICT (type, value) DO UPDATE SET last_seen = NOW() RETURNING id`,
		iocType, value)
	mustExecAPI(t, pool, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, agent_id) VALUES ($1, $2, $3)`,
		id, scenarioID, agentID)
}

func TestGetIOCs_FiltersByType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "whoami /all", "agent-1", "sc-1")
		seedIOC(t, pool, "process", "powershell.exe", "agent-1", "sc-1")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?type=process", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 1 || got[0]["type"] != "process" {
			t.Errorf("got %+v, want exactly 1 process IOC", got)
		}
	})
}

func TestGetIOCs_FiltersByAgentId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "cmd-a", "agent-a", "sc-1")
		seedIOC(t, pool, "command_line", "cmd-b", "agent-b", "sc-1")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?agentId=agent-a", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 1 || got[0]["value"] != "cmd-a" {
			t.Errorf("got %+v, want exactly 1 IOC (cmd-a, seen by agent-a)", got)
		}
	})
}

func TestGetIOCs_NoResults_ReturnsEmptyArrayNotNull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?type=domain", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() == "null" {
			t.Error("body is literal \"null\" -- must be an empty JSON array")
		}
	})
}
