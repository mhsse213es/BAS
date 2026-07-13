package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func seedReadinessHistory(t *testing.T, pool *pgxpool.Pool, runID, agentID, actor string, prevention, detection float64, tested, total int, recordedAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO threat_readiness_history (run_id, agent_id, actor_name, prevention, detection, tested, total, confidence, recorded_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,'high',$8)`,
		runID, agentID, actor, prevention, detection, tested, total, recordedAt); err != nil {
		t.Fatalf("seed readiness history: %v", err)
	}
}

func TestGetTIReadinessHistory_MissingAgentId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetTIReadinessHistory(rec, tiReq("/api/ti/readiness/history", ""))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestGetTIReadinessHistory_EmptyState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetTIReadinessHistory(rec, tiReq("/api/ti/readiness/history", "agentId=trh-empty-agent"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			Trends []map[string]any `json:"trends"`
			Total  int              `json:"total"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Trends == nil || len(out.Trends) != 0 || out.Total != 0 {
			t.Fatalf("out = %+v, want an empty (non-nil) trends array and total=0", out)
		}
	})
}

func TestGetTIReadinessHistory_ActorFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		agent := "trh-filter-agent"
		seedReadinessHistory(t, pool, "trh-f-run-1", agent, "Wizard Spider", 50, 30, 5, 10, t0)
		seedReadinessHistory(t, pool, "trh-f-run-2", agent, "FIN11", 70, 40, 5, 10, t0)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		rec := httptest.NewRecorder()
		h.GetTIReadinessHistory(rec, tiReq("/api/ti/readiness/history", "agentId="+agent+"&actor="+url.QueryEscape("Wizard Spider")))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			Trends []struct {
				ActorName string `json:"actorName"`
			} `json:"trends"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Trends) != 1 || out.Trends[0].ActorName != "Wizard Spider" {
			t.Fatalf("trends = %+v, want exactly [Wizard Spider]", out.Trends)
		}
	})
}

// TestGetTIReadinessHistory_LimitClamping pins the limit parameter's
// validation: only 1..100 is honored; anything else (missing, non-numeric,
// zero, negative, >100) falls back to the default of 10.
func TestGetTIReadinessHistory_LimitClamping(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agent := "trh-limit-agent"
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		for i := range 15 {
			seedReadinessHistory(t, pool, "trh-limit-run-"+string(rune('a'+i)), agent, "Wizard Spider",
				float64(i), float64(i), 5, 10, t0.Add(time.Duration(i)*time.Hour))
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		fetchCount := func(query string) int {
			rec := httptest.NewRecorder()
			h.GetTIReadinessHistory(rec, tiReq("/api/ti/readiness/history", query))
			var out struct {
				Trends []struct {
					History []map[string]any `json:"history"`
				} `json:"trends"`
			}
			json.Unmarshal(rec.Body.Bytes(), &out)
			if len(out.Trends) != 1 {
				t.Fatalf("query %q: trends = %+v, want exactly 1 actor", query, out.Trends)
			}
			return len(out.Trends[0].History)
		}

		if n := fetchCount("agentId=" + agent); n != 10 {
			t.Errorf("default (no limit param): got %d rows, want 10", n)
		}
		if n := fetchCount("agentId=" + agent + "&limit=3"); n != 3 {
			t.Errorf("limit=3: got %d rows, want 3", n)
		}
		if n := fetchCount("agentId=" + agent + "&limit=0"); n != 10 {
			t.Errorf("limit=0 (invalid): got %d rows, want default 10", n)
		}
		if n := fetchCount("agentId=" + agent + "&limit=-5"); n != 10 {
			t.Errorf("limit=-5 (invalid): got %d rows, want default 10", n)
		}
		if n := fetchCount("agentId=" + agent + "&limit=999"); n != 10 {
			t.Errorf("limit=999 (out of range): got %d rows, want default 10", n)
		}
		if n := fetchCount("agentId=" + agent + "&limit=notanumber"); n != 10 {
			t.Errorf("limit=notanumber (invalid): got %d rows, want default 10", n)
		}
	})
}

// TestGetTIReadinessHistory_TrendDirectionAndDelta pins the handler's own
// trend math: delta = latest - oldest (rounded to 1 decimal), and direction
// is up/down/stable based on a ±1 threshold on the prevention delta.
func TestGetTIReadinessHistory_TrendDirectionAndDelta(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		// "up": oldest prevention=40, latest=75 → delta=+35.
		seedReadinessHistory(t, pool, "trh-up-run-1", "trh-up-agent", "Wizard Spider", 40, 20, 5, 10, t0)
		seedReadinessHistory(t, pool, "trh-up-run-2", "trh-up-agent", "Wizard Spider", 75, 60, 5, 10, t0.Add(1*time.Hour))

		// "down": oldest=80, latest=50 → delta=-30.
		seedReadinessHistory(t, pool, "trh-down-run-1", "trh-down-agent", "FIN11", 80, 70, 5, 10, t0)
		seedReadinessHistory(t, pool, "trh-down-run-2", "trh-down-agent", "FIN11", 50, 40, 5, 10, t0.Add(1*time.Hour))

		// "stable": oldest=60, latest=60.5 → delta=+0.5, within the ±1 threshold.
		seedReadinessHistory(t, pool, "trh-stable-run-1", "trh-stable-agent", "Lazarus", 60, 30, 5, 10, t0)
		seedReadinessHistory(t, pool, "trh-stable-run-2", "trh-stable-agent", "Lazarus", 60.5, 30.5, 5, 10, t0.Add(1*time.Hour))

		check := func(agent, wantDirection string, wantDelta float64) {
			rec := httptest.NewRecorder()
			h.GetTIReadinessHistory(rec, tiReq("/api/ti/readiness/history", "agentId="+agent))
			var out struct {
				Trends []struct {
					Direction       string  `json:"direction"`
					PreventionDelta float64 `json:"preventionDelta"`
					DataPoints      int     `json:"dataPoints"`
				} `json:"trends"`
			}
			json.Unmarshal(rec.Body.Bytes(), &out)
			if len(out.Trends) != 1 {
				t.Fatalf("%s: trends = %+v, want 1 entry", agent, out.Trends)
			}
			tr := out.Trends[0]
			if tr.Direction != wantDirection {
				t.Errorf("%s: direction = %q, want %q", agent, tr.Direction, wantDirection)
			}
			if tr.PreventionDelta != wantDelta {
				t.Errorf("%s: preventionDelta = %v, want %v", agent, tr.PreventionDelta, wantDelta)
			}
			if tr.DataPoints != 2 {
				t.Errorf("%s: dataPoints = %d, want 2", agent, tr.DataPoints)
			}
		}
		check("trh-up-agent", "up", 35)
		check("trh-down-agent", "down", -30)
		check("trh-stable-agent", "stable", 0.5)
	})
}

// TestGetTIReadinessHistory_MultiActorNoFilter pins that omitting actor=
// returns every actor's trend for the agent, each capped at the per-actor
// limit independently (the window-function query in the handler).
func TestGetTIReadinessHistory_MultiActorNoFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		agent := "trh-multi-agent"
		seedReadinessHistory(t, pool, "trh-multi-run-1", agent, "Wizard Spider", 50, 30, 5, 10, t0)
		seedReadinessHistory(t, pool, "trh-multi-run-2", agent, "FIN11", 60, 40, 5, 10, t0)
		seedReadinessHistory(t, pool, "trh-multi-run-3", agent, "Lazarus", 70, 50, 5, 10, t0)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		rec := httptest.NewRecorder()
		h.GetTIReadinessHistory(rec, tiReq("/api/ti/readiness/history", "agentId="+agent))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			Total int `json:"total"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Total != 3 {
			t.Fatalf("total = %d, want 3 (one trend per actor)", out.Total)
		}
	})
}
