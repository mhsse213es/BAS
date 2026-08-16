package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func seedRun(t *testing.T, pool *pgxpool.Pool, runID string) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ($1,$1)
		ON CONFLICT (agent_id) DO NOTHING`, "agent-x")
	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status)
		 VALUES ($1,'sc','agent-x','t','running')`, runID); err != nil {
		t.Fatalf("seed run: %v", err)
	}
}

func postEvents(t *testing.T, h *Handler, evs []map[string]any) {
	t.Helper()
	body, _ := json.Marshal(evs)
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/events", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.SubmitRunEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func summary(t *testing.T, pool *pgxpool.Pool, runID string) (total, done, running, passed, failed, timeout int) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout
		 FROM scenario_runs WHERE id = $1`, runID).
		Scan(&total, &done, &running, &passed, &failed, &timeout)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	return
}

func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestSubmitRunEventsSummaryAndIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		runID := "run-sum-1"
		seedRun(t, pool, runID)

		ev := func(seq int, typ string, payload map[string]any) map[string]any {
			return map[string]any{"runId": runID, "seq": seq, "type": typ,
				"ts": "2026-06-09T16:40:12Z", "payload": payload}
		}
		postEvents(t, h, []map[string]any{
			ev(1, "run_started", map[string]any{"stepsTotal": 3}),
			ev(2, "started", nil),
			ev(3, "completed", map[string]any{"verdict": "pass"}),
			ev(4, "started", nil),
			ev(5, "timeout", map[string]any{"reason": "execute"}),
		})

		total, done, running, passed, failed, timeout := summary(t, pool, runID)
		if total != 3 || done != 2 || running != 0 || passed != 1 || failed != 0 || timeout != 1 {
			t.Fatalf("after first batch: total=%d done=%d running=%d passed=%d failed=%d timeout=%d",
				total, done, running, passed, failed, timeout)
		}

		postEvents(t, h, []map[string]any{
			ev(3, "completed", map[string]any{"verdict": "pass"}),
			ev(5, "timeout", map[string]any{"reason": "execute"}),
		})
		total2, done2, _, passed2, _, timeout2 := summary(t, pool, runID)
		if total2 != 3 || done2 != 2 || passed2 != 1 || timeout2 != 1 {
			t.Fatalf("after replay (must be unchanged): total=%d done=%d passed=%d timeout=%d",
				total2, done2, passed2, timeout2)
		}
	})
}

func TestSubmitRunEventsRunningCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		runID := "run-running-1"
		seedRun(t, pool, runID)
		ev := func(seq int, typ string) map[string]any {
			return map[string]any{"runId": runID, "seq": seq, "type": typ, "ts": "2026-06-09T16:40:12Z"}
		}
		postEvents(t, h, []map[string]any{ev(1, "started"), ev(2, "started")})
		if _, _, running, _, _, _ := summary(t, pool, runID); running != 2 {
			t.Fatalf("running after 2 starts = %d, want 2", running)
		}
		postEvents(t, h, []map[string]any{{"runId": runID, "seq": 3, "type": "completed", "ts": "2026-06-09T16:40:12Z", "payload": map[string]any{"verdict": "pass"}}})
		if _, _, running, _, _, _ := summary(t, pool, runID); running != 1 {
			t.Fatalf("running after 1 completion = %d, want 1", running)
		}
	})
}

func TestListRunEventsOrderedBySeq(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		runID := "run-order-1"
		seedRun(t, pool, runID)
		ev := func(seq int) map[string]any {
			return map[string]any{"runId": runID, "seq": seq, "type": "started", "ts": "2026-06-09T16:40:12Z"}
		}
		postEvents(t, h, []map[string]any{ev(12), ev(11), ev(13)})

		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/events", nil)
		req = withURLParam(req, "runId", runID)
		rec := httptest.NewRecorder()
		h.ListRunEvents(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var got []map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if len(got) != 3 {
			t.Fatalf("expected 3 events, got %d", len(got))
		}
		seqs := []float64{got[0]["seq"].(float64), got[1]["seq"].(float64), got[2]["seq"].(float64)}
		if seqs[0] != 11 || seqs[1] != 12 || seqs[2] != 13 {
			t.Fatalf("events not ordered by seq: %v", seqs)
		}
	})
}

func pausedState(t *testing.T, pool *pgxpool.Pool, runID string) bool {
	t.Helper()
	var p bool
	if err := pool.QueryRow(context.Background(),
		`SELECT paused FROM scenario_runs WHERE id = $1`, runID).Scan(&p); err != nil {
		t.Fatalf("pausedState: %v", err)
	}
	return p
}

func TestSubmitRunEvents_PausedResumedSetsPausedColumn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		runID := "run-pause-1"
		seedRun(t, pool, runID)

		ev := func(seq int, typ string) map[string]any {
			return map[string]any{"runId": runID, "seq": seq, "type": typ, "ts": "2026-06-09T16:40:12Z"}
		}

		postEvents(t, h, []map[string]any{ev(1, "run_started")})
		if pausedState(t, pool, runID) {
			t.Fatal("paused = true before any pause event, want false")
		}

		postEvents(t, h, []map[string]any{ev(2, "paused")})
		if !pausedState(t, pool, runID) {
			t.Fatal("paused = false after a 'paused' event, want true")
		}

		postEvents(t, h, []map[string]any{ev(3, "resumed")})
		if pausedState(t, pool, runID) {
			t.Fatal("paused = true after a 'resumed' event, want false")
		}
	})
}

func TestBuildRunEventMsg(t *testing.T) {
	batch := []models.RunEvent{
		{RunID: "r9", Seq: 1, Type: "started", TaskID: "a1"},
		{RunID: "r9", Seq: 2, Type: "completed", TaskID: "a1"},
	}
	msg := buildRunEventMsg(batch)
	if msg.Type != models.MsgRunEvent {
		t.Fatalf("type = %q, want %q", msg.Type, models.MsgRunEvent)
	}
	data, ok := msg.Data.(map[string]any)
	if !ok {
		t.Fatalf("data not a map: %T", msg.Data)
	}
	if data["runId"] != "r9" {
		t.Fatalf("runId = %v", data["runId"])
	}
	evs, ok := data["events"].([]models.RunEvent)
	if !ok || len(evs) != 2 {
		t.Fatalf("events = %v", data["events"])
	}
}
