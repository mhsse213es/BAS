package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func receiveEventsReq(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/api/agents/events", strings.NewReader(body))
}

func TestReceiveEvents_Unauthorized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool).WithAgentSecret("s3cr3t")
		rec := httptest.NewRecorder()
		h.ReceiveEvents(rec, receiveEventsReq(`{"events":[]}`))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func TestReceiveEvents_InvalidBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool)
		cases := []string{`{"events":`, `{"events":[]}`, `{}`}
		for _, body := range cases {
			rec := httptest.NewRecorder()
			h.ReceiveEvents(rec, receiveEventsReq(body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body %q: status = %d, want 400", body, rec.Code)
			}
		}
	})
}

// TestReceiveEvents_RoutesByEventType pins the per-type table routing and
// the accepted-count contract: a valid op_log/sec_log/telemetry event each
// land in their own table, an unknown event_type and an event missing
// agentId/eventType are silently skipped (not counted, not errored).
func TestReceiveEvents_RoutesByEventType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool)
		agentID := "re-agent"
		ts := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
		body := `{"events":[
			{"schema_version":1,"event_type":"op_log","agent_id":"` + agentID + `","seq":1,"ts":"` + ts + `",
			 "payload":{"level":"info","category":"lifecycle","message":"agent started"}},
			{"schema_version":1,"event_type":"sec_log","agent_id":"` + agentID + `","seq":2,"ts":"` + ts + `",
			 "payload":{"level":"warn","scenario_id":"sc1","run_id":"run1","step_id":"s1","technique_id":"T1059.001","category":"scenario_step","message":"blocked"}},
			{"schema_version":1,"event_type":"telemetry","agent_id":"` + agentID + `","seq":3,"ts":"` + ts + `",
			 "payload":{"metric":"cpu_pct","value":42.5,"unit":"pct"}},
			{"schema_version":1,"event_type":"unknown_type","agent_id":"` + agentID + `","seq":4,"ts":"` + ts + `","payload":{}},
			{"schema_version":1,"event_type":"op_log","agent_id":"","seq":5,"ts":"` + ts + `","payload":{}}
		]}`
		rec := httptest.NewRecorder()
		h.ReceiveEvents(rec, receiveEventsReq(body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Accepted int `json:"accepted"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Accepted != 3 {
			t.Fatalf("accepted = %d, want 3 (unknown type + missing agentId both skipped)", out.Accepted)
		}

		var opMsg, secMsg, secTech string
		var telValue float64
		if err := pool.QueryRow(context.Background(), `SELECT message FROM agent_op_logs WHERE agent_id=$1`, agentID).Scan(&opMsg); err != nil {
			t.Fatalf("query agent_op_logs: %v", err)
		}
		if err := pool.QueryRow(context.Background(), `SELECT message, technique_id FROM agent_sec_logs WHERE agent_id=$1`, agentID).Scan(&secMsg, &secTech); err != nil {
			t.Fatalf("query agent_sec_logs: %v", err)
		}
		if err := pool.QueryRow(context.Background(), `SELECT value FROM agent_telemetry WHERE agent_id=$1`, agentID).Scan(&telValue); err != nil {
			t.Fatalf("query agent_telemetry: %v", err)
		}
		if opMsg != "agent started" {
			t.Errorf("op_log message = %q", opMsg)
		}
		if secMsg != "blocked" || secTech != "T1059.001" {
			t.Errorf("sec_log message=%q technique=%q", secMsg, secTech)
		}
		if telValue != 42.5 {
			t.Errorf("telemetry value = %v, want 42.5", telValue)
		}
	})
}

func TestReceiveEvents_DefaultsTimestampWhenMissing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool)
		before := time.Now().Add(-2 * time.Second)
		body := `{"events":[{"schema_version":1,"event_type":"op_log","agent_id":"re-notime-agent","seq":1,
			"payload":{"level":"info","category":"lifecycle","message":"no ts given"}}]}`
		rec := httptest.NewRecorder()
		h.ReceiveEvents(rec, receiveEventsReq(body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var createdAt time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT created_at FROM agent_op_logs WHERE agent_id='re-notime-agent'`).Scan(&createdAt); err != nil {
			t.Fatalf("query: %v", err)
		}
		if createdAt.Before(before) {
			t.Errorf("created_at = %v, want a timestamp close to now (server default when ts is zero)", createdAt)
		}
	})
}

func seedOpLog(t *testing.T, pool *pgxpool.Pool, agentID, level, category, message string, createdAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agent_op_logs (agent_id, level, category, message, created_at) VALUES ($1,$2,$3,$4,$5)`,
		agentID, level, category, message, createdAt); err != nil {
		t.Fatalf("seed agent_op_logs: %v", err)
	}
}

func seedSecLog(t *testing.T, pool *pgxpool.Pool, agentID, runID, techID, message string, createdAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agent_sec_logs (agent_id, run_id, technique_id, message, created_at) VALUES ($1,$2,$3,$4,$5)`,
		agentID, runID, techID, message, createdAt); err != nil {
		t.Fatalf("seed agent_sec_logs: %v", err)
	}
}

func seedTelemetry(t *testing.T, pool *pgxpool.Pool, agentID, metric string, value float64, createdAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agent_telemetry (agent_id, metric, value, created_at) VALUES ($1,$2,$3,$4)`,
		agentID, metric, value, createdAt); err != nil {
		t.Fatalf("seed agent_telemetry: %v", err)
	}
}

func agentLogReq(path, agentID, query string) *http.Request {
	full := "/api/agents/" + agentID + path
	if query != "" {
		full += "?" + query
	}
	return withURLParam(httptest.NewRequest(http.MethodGet, full, nil), "agentId", agentID)
}

func TestGetOpLogs_OrderingAndBeforeFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		agentID := "gol-agent"
		seedOpLog(t, pool, agentID, "info", "lifecycle", "old", t0)
		seedOpLog(t, pool, agentID, "info", "lifecycle", "new", t0.Add(1*time.Hour))
		seedOpLog(t, pool, "other-agent", "info", "lifecycle", "other agent's log", t0)
		h := tamperHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetOpLogs(rec, agentLogReq("/logs/operational", agentID, ""))
		var out []struct {
			Message string `json:"message"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 2 || out[0].Message != "new" || out[1].Message != "old" {
			t.Fatalf("out = %+v, want [new, old] (most recent first, scoped to this agent)", out)
		}

		beforeRec := httptest.NewRecorder()
		h.GetOpLogs(beforeRec, agentLogReq("/logs/operational", agentID, "before="+t0.Add(1*time.Hour).Format(time.RFC3339)))
		var beforeOut []struct {
			Message string `json:"message"`
		}
		json.Unmarshal(beforeRec.Body.Bytes(), &beforeOut)
		if len(beforeOut) != 1 || beforeOut[0].Message != "old" {
			t.Fatalf("before-filtered out = %+v, want just [old]", beforeOut)
		}
	})
}

func TestGetOpLogs_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetOpLogs(rec, agentLogReq("/logs/operational", "no-such-agent", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out == nil || len(out) != 0 {
			t.Fatalf("out = %v, want empty (non-nil) array", out)
		}
	})
}

func TestGetSecLogs_RunIDFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		agentID := "gsl-agent"
		seedSecLog(t, pool, agentID, "run-a", "T1059.001", "from run a", t0)
		seedSecLog(t, pool, agentID, "run-b", "T1003.001", "from run b", t0.Add(1*time.Minute))
		h := tamperHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetSecLogs(rec, agentLogReq("/logs/security", agentID, "run_id=run-a"))
		var out []struct {
			Message string `json:"message"`
			RunID   string `json:"runId"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 || out[0].RunID != "run-a" || out[0].Message != "from run a" {
			t.Fatalf("out = %+v, want just the run-a entry", out)
		}

		allRec := httptest.NewRecorder()
		h.GetSecLogs(allRec, agentLogReq("/logs/security", agentID, ""))
		var allOut []map[string]any
		json.Unmarshal(allRec.Body.Bytes(), &allOut)
		if len(allOut) != 2 {
			t.Fatalf("unfiltered: got %d entries, want 2", len(allOut))
		}
	})
}

func TestGetTelemetry_MetricFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		agentID := "gt-agent"
		seedTelemetry(t, pool, agentID, "cpu_pct", 55.5, t0)
		seedTelemetry(t, pool, agentID, "ram_pct", 70.0, t0.Add(1*time.Minute))
		h := tamperHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetTelemetry(rec, agentLogReq("/telemetry", agentID, "metric=cpu_pct"))
		var out []struct {
			Metric string  `json:"metric"`
			Value  float64 `json:"value"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 || out[0].Metric != "cpu_pct" || out[0].Value != 55.5 {
			t.Fatalf("out = %+v, want just cpu_pct=55.5", out)
		}
	})
}

// TestLogQueryParams_Table is a pure-function table for the shared
// limit/before parsing: limit clamps to [1,500] with a default of 100 for
// invalid input, and before defaults to "now+1s" (deterministic enough to
// bound in the test as "well after now, well before an hour from now").
func TestLogQueryParams_Table(t *testing.T) {
	cases := []struct {
		name      string
		query     string
		wantLimit int
	}{
		{"no params", "", 100},
		{"valid limit", "limit=42", 42},
		{"zero limit ignored", "limit=0", 100},
		{"negative limit ignored", "limit=-5", 100},
		{"over-cap limit clamps to 500", "limit=9999", 500},
		{"non-numeric limit ignored", "limit=abc", 100},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/x?"+c.query, nil)
		limit, before := logQueryParams(req)
		if limit != c.wantLimit {
			t.Errorf("%s: limit = %d, want %d", c.name, limit, c.wantLimit)
		}
		if before.Before(time.Now()) {
			t.Errorf("%s: before = %v, want a timestamp at/after now (default now+1s)", c.name, before)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/x?before=2026-07-01T12:00:00Z", nil)
	_, before := logQueryParams(req)
	want := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if !before.Equal(want) {
		t.Errorf("explicit before = %v, want %v", before, want)
	}

	badReq := httptest.NewRequest(http.MethodGet, "/x?before=not-a-timestamp", nil)
	_, badBefore := logQueryParams(badReq)
	if badBefore.Before(time.Now()) {
		t.Errorf("malformed before should fall back to the default (now+1s), got %v", badBefore)
	}
}
