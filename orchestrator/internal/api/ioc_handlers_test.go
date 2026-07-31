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
	seedIOCFull(t, pool, iocType, value, agentID, scenarioID, "", "")
}

func seedIOCFull(t *testing.T, pool *pgxpool.Pool, iocType, value, agentID, scenarioID, techniqueID, verdict string) {
	t.Helper()
	var id string
	mustExecAPIReturning(t, pool, &id, `
		INSERT INTO iocs (type, value, source) VALUES ($1, $2, 'detection_alert')
		ON CONFLICT (type, value) DO UPDATE SET last_seen = NOW() RETURNING id`,
		iocType, value)
	mustExecAPI(t, pool, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, agent_id, technique_id, detection_verdict) VALUES ($1, $2, $3, $4, $5)`,
		id, scenarioID, agentID, techniqueID, verdict)
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

func TestGetIOCs_FiltersByTechniqueId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCFull(t, pool, "command_line", "cmd-t1059", "agent-1", "sc-1", "T1059", "detected")
		seedIOCFull(t, pool, "command_line", "cmd-t1136", "agent-1", "sc-1", "T1136", "prevented")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?techniqueId=T1059", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got) != 1 || got[0]["value"] != "cmd-t1059" {
			t.Errorf("got %+v, want exactly 1 IOC (cmd-t1059)", got)
		}
	})
}

func TestGetIOCs_FiltersBySourceOriginStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "cmd-src", "agent-1", "sc-1")
		mustExecAPI(t, pool, `UPDATE iocs SET origin = 'openaev', status = 'detected' WHERE value = 'cmd-src'`)

		h := &Handler{db: pool}

		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?source=detection_alert", nil))
		var bySource []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &bySource)
		if len(bySource) != 1 {
			t.Errorf("source filter: got %+v, want exactly 1", bySource)
		}

		rec = httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?origin=openaev", nil))
		var byOrigin []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &byOrigin)
		if len(byOrigin) != 1 {
			t.Errorf("origin filter: got %+v, want exactly 1", byOrigin)
		}

		rec = httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?status=detected", nil))
		var byStatus []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &byStatus)
		if len(byStatus) != 1 {
			t.Errorf("status filter: got %+v, want exactly 1", byStatus)
		}
	})
}

func TestGetIOCs_FiltersBySinceUntil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "cmd-old", "agent-1", "sc-1")
		mustExecAPI(t, pool, `UPDATE iocs SET last_seen = '2020-01-01T00:00:00Z' WHERE value = 'cmd-old'`)
		seedIOC(t, pool, "command_line", "cmd-new", "agent-1", "sc-1")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?since=2025-01-01T00:00:00Z", nil))
		var got []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &got)
		if len(got) != 1 || got[0]["value"] != "cmd-new" {
			t.Errorf("since filter: got %+v, want exactly 1 (cmd-new)", got)
		}

		rec = httptest.NewRecorder()
		h.GetIOCs(rec, httptest.NewRequest(http.MethodGet, "/api/iocs?until=2021-01-01T00:00:00Z", nil))
		var got2 []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &got2)
		if len(got2) != 1 || got2[0]["value"] != "cmd-old" {
			t.Errorf("until filter: got %+v, want exactly 1 (cmd-old)", got2)
		}
	})
}
