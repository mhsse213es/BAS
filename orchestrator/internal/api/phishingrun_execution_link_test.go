package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
)

// seedExecution creates a plan and one execution for it and returns the execution ID.
func seedExecution(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx := context.Background()
	var planID, execID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO exercise_plans (name) VALUES ($1) RETURNING id`, "plan-"+name).Scan(&planID); err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO exercise_executions (plan_id, name) VALUES ($1, $2) RETURNING id`, planID, name).Scan(&execID); err != nil {
		t.Fatalf("seed execution: %v", err)
	}
	return execID
}

// A run named to an execution that does not exist is refused before any row is written.
func TestTriggerPhishingRun_UnknownExecutionRefusedWithNoRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, nil, nil, testJWTSecret)
		body := map[string]any{"scenarioId": "PH-ID-001", "parameters": map[string]any{"executionId": "no-such-execution"}}
		rec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
		var rows int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM phishing_runs WHERE execution_id = 'no-such-execution'`).Scan(&rows); err != nil {
			t.Fatalf("count: %v", err)
		}
		if rows != 0 {
			t.Errorf("%d run row(s) written for an unknown execution; want 0", rows)
		}
	})
}

// A run named to a real execution is stored against it and reported back with it.
func TestTriggerPhishingRun_LinksRunToExecution(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, nil, nil, testJWTSecret)
		execID := seedExecution(t, pool, "link-test")
		body := map[string]any{"scenarioId": "PH-ID-001", "parameters": map[string]any{"executionId": execID}}
		rec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, body))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
		}
		var run struct {
			ID          string `json:"id"`
			ExecutionID string `json:"executionId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if run.ExecutionID != execID {
			t.Errorf("response executionId = %q, want %q", run.ExecutionID, execID)
		}
		var stored string
		if err := pool.QueryRow(context.Background(),
			`SELECT execution_id FROM phishing_runs WHERE id = $1`, run.ID).Scan(&stored); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if stored != execID {
			t.Errorf("stored execution_id = %q, want %q", stored, execID)
		}
	})
}

// GET /api/exercises/executions/{id}/phishing-runs lists only that execution's runs.
func TestListExecutionPhishingRuns_OnlyThatExecution(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, nil, nil, testJWTSecret)
		mine := seedExecution(t, pool, "list-mine")
		other := seedExecution(t, pool, "list-other")
		for _, id := range []string{mine, other} {
			body := map[string]any{"scenarioId": "PH-ID-001", "parameters": map[string]any{"executionId": id}}
			if rec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, body)); rec.Code != http.StatusCreated {
				t.Fatalf("seed run for %s: status %d", id, rec.Code)
			}
		}
		userID := seedUser(t, pool, "exec-link-viewer", "pw12345678", string(auth.RoleAnalyst), true)
		req := withURLParam(authedRequest(t, http.MethodGet, "/api/exercises/executions/"+mine+"/phishing-runs", nil, auth.RoleAnalyst, userID), "id", mine)
		rec := callAuthed(h.ListExecutionPhishingRuns, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		var runs []struct {
			ExecutionID string `json:"executionId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 1 || runs[0].ExecutionID != mine {
			t.Errorf("runs = %+v, want exactly one run for %s", runs, mine)
		}
	})
}

// seedExecutionID creates a plan and an execution with the given ID, so a phishing run
// that names it passes the execution-link check. Idempotent across repeated calls.
func seedExecutionID(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	ctx := context.Background()
	var planID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO exercise_plans (name) VALUES ($1) RETURNING id`, "plan-"+id).Scan(&planID); err != nil {
		t.Fatalf("seed plan for %s: %v", id, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO exercise_executions (id, plan_id, name) VALUES ($1, $2, $1) ON CONFLICT (id) DO NOTHING`,
		id, planID); err != nil {
		t.Fatalf("seed execution %s: %v", id, err)
	}
}
