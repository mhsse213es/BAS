package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// attackpathHandler wires a real Handler with no agent secret configured
// (matching most test fixtures elsewhere — validateAgentAuth's own precedence
// matrix is already exhaustively tested in agent_auth_test.go, so agent-authed
// endpoints here only need one unauthorized-path smoke test each).
func attackpathHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func minimalCollection(agentID, hostname, source string) attackpath.Collection {
	return attackpath.Collection{
		AgentID:  agentID,
		Hostname: hostname,
		Source:   source,
		Nodes: []attackpath.Node{
			{ID: hostname, Kind: attackpath.KindHost, Label: hostname},
		},
	}
}

func collectionReq(c attackpath.Collection) *http.Request {
	b, _ := json.Marshal(c)
	return httptest.NewRequest(http.MethodPost, "/api/attackpath/collect", bytes.NewReader(b))
}

func TestSubmitAttackPathCollection_Unauthorized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool).WithAgentSecret("shh")
		rec := httptest.NewRecorder()
		h.SubmitAttackPathCollection(rec, collectionReq(minimalCollection("a1", "HOST1", "agent")))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func TestSubmitAttackPathCollection_MissingAgentID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.SubmitAttackPathCollection(rec, collectionReq(minimalCollection("", "HOST1", "agent")))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestSubmitAttackPathCollection_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte(`{"agentId":`)))
		rec := httptest.NewRecorder()
		h.SubmitAttackPathCollection(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestSubmitAttackPathCollection_Success pins the full ingestion contract:
// the collection persists, a history row is written, source defaults to
// "agent" when omitted, and collected_at defaults to now when zero.
func TestSubmitAttackPathCollection_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		c := minimalCollection("sac1-agent", "SAC1-HOST", "")
		rec := httptest.NewRecorder()
		h.SubmitAttackPathCollection(rec, collectionReq(c))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["source"] != "agent" {
			t.Errorf("source = %v, want agent (defaulted)", out["source"])
		}

		var storedSource string
		var collectedAt time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT source, collected_at FROM attackpath_collections WHERE agent_id=$1`, "sac1-agent",
		).Scan(&storedSource, &collectedAt); err != nil {
			t.Fatalf("read collection: %v", err)
		}
		if storedSource != "agent" {
			t.Errorf("stored source = %q, want agent", storedSource)
		}
		if collectedAt.IsZero() {
			t.Error("expected collected_at to default to now, got zero")
		}

		var histCount int
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM attackpath_collection_history WHERE agent_id=$1`, "sac1-agent").Scan(&histCount)
		if histCount != 1 {
			t.Fatalf("history rows = %d, want 1", histCount)
		}
	})
}

// TestSubmitAttackPathCollection_UpsertReplacesPriorForSameAgentSource pins
// idempotent re-delivery: a second submission for the same (agent_id, source)
// replaces the live collection (not appends), matching the at-least-once
// pipeline pattern used elsewhere ([[project_run_reconciliation]]).
func TestSubmitAttackPathCollection_UpsertReplacesPriorForSameAgentSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		first := minimalCollection("upsert-agent", "FIRST-HOST", "agent")
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(first))

		second := minimalCollection("upsert-agent", "SECOND-HOST", "agent")
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(second))

		var n int
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM attackpath_collections WHERE agent_id=$1`, "upsert-agent").Scan(&n)
		if n != 1 {
			t.Fatalf("row count = %d, want 1 (upsert, not append)", n)
		}
		var hostname string
		pool.QueryRow(context.Background(),
			`SELECT hostname FROM attackpath_collections WHERE agent_id=$1`, "upsert-agent").Scan(&hostname)
		if hostname != "SECOND-HOST" {
			t.Fatalf("hostname = %q, want SECOND-HOST (latest wins)", hostname)
		}
	})
}

// TestSubmitAttackPathCollection_DifferentSourceCoexists pins that
// attackpath_collections is keyed by (agent_id, source) — an agent's
// "agent"-source reachability payload and its "sharphound"-source payload
// coexist as two rows rather than overwriting each other.
func TestSubmitAttackPathCollection_DifferentSourceCoexists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(minimalCollection("dual-agent", "H1", "agent")))
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(minimalCollection("dual-agent", "H1", "sharphound")))

		var n int
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM attackpath_collections WHERE agent_id=$1`, "dual-agent").Scan(&n)
		if n != 2 {
			t.Fatalf("row count = %d, want 2 (agent + sharphound coexist)", n)
		}
	})
}

// TestSubmitAttackPathCollection_CompletesJobWhenJobIDPresent pins that
// submitting a collection carrying a jobId marks that job completed with
// execution metrics — the bridge between the async job queue
// (attackpath_jobs.go) and the actual ingestion path.
func TestSubmitAttackPathCollection_CompletesJobWhenJobIDPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		jobID, err := h.createAPJob(context.Background(), "job-linked-agent", map[string]any{"targets": []string{"10.0.0.1"}}, 1)
		if err != nil {
			t.Fatalf("createAPJob: %v", err)
		}
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET started_at=NOW() WHERE id=$1`, jobID)

		body := map[string]any{
			"agentId": "job-linked-agent", "hostname": "H1", "source": "agent", "jobId": jobID,
			"nodes": []attackpath.Node{{ID: "H1", Kind: attackpath.KindHost, Label: "H1"}},
		}
		b, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		h.SubmitAttackPathCollection(rec, httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(b)))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM attackpath_jobs WHERE id=$1`, jobID).Scan(&status)
		if status != APJobCompleted {
			t.Fatalf("job status = %q, want completed", status)
		}
	})
}

func TestGetAttackPathSummary_NotCollected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetAttackPathSummary(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["collected"] != false {
			t.Fatalf("out = %+v, want collected:false", out)
		}
	})
}

// TestGetAttackPathSummary_Success pins that summary aggregates every stored
// collection into one fleet graph plus per-agent metadata for the "Current
// Graph" panel.
func TestGetAttackPathSummary_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(minimalCollection("sum-agent", "SUM-HOST", "agent")))

		rec := httptest.NewRecorder()
		h.GetAttackPathSummary(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Collected bool `json:"collected"`
			Agents    int  `json:"agents"`
			AgentMeta []struct {
				AgentID   string `json:"agentId"`
				Hostname  string `json:"hostname"`
				NodeCount int    `json:"nodeCount"`
			} `json:"agentMeta"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if !out.Collected || out.Agents != 1 {
			t.Fatalf("out = %+v, want collected:true agents:1", out)
		}
		if len(out.AgentMeta) != 1 || out.AgentMeta[0].NodeCount != 1 {
			t.Fatalf("agentMeta = %+v, want 1 entry with nodeCount 1", out.AgentMeta)
		}
	})
}

func TestGetAttackPathHistory_EmptyThenPopulatedWithFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		emptyRec := httptest.NewRecorder()
		h.GetAttackPathHistory(emptyRec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var empty []map[string]any
		json.Unmarshal(emptyRec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 history rows, got %d", len(empty))
		}

		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(minimalCollection("hist-a", "HA", "agent")))
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(minimalCollection("hist-b", "HB", "agent")))

		allRec := httptest.NewRecorder()
		h.GetAttackPathHistory(allRec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var all []map[string]any
		json.Unmarshal(allRec.Body.Bytes(), &all)
		if len(all) != 2 {
			t.Fatalf("expected 2 history rows across both agents, got %d", len(all))
		}

		filteredRec := httptest.NewRecorder()
		h.GetAttackPathHistory(filteredRec, httptest.NewRequest(http.MethodGet, "/x?agentId=hist-a", nil))
		var filtered []map[string]any
		json.Unmarshal(filteredRec.Body.Bytes(), &filtered)
		if len(filtered) != 1 || filtered[0]["agentId"] != "hist-a" {
			t.Fatalf("filtered = %+v, want 1 row for hist-a", filtered)
		}
	})
}

// TestGetAttackPathSummary_CoverageReconciliation pins that Coverage compares
// the most recent request-log row against which targets ended up represented
// in the resulting graph -- never claiming to know *why* a target is missing.
func TestGetAttackPathSummary_CoverageReconciliation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)

		targetsJSON, _ := json.Marshal([]string{"REPRESENTED-HOST", "MISSING-HOST"})
		pool.Exec(context.Background(),
			`INSERT INTO attackpath_collection_requests (agent_id, targets, run_sharphound) VALUES ($1, $2, $3)`,
			"cov-agent", targetsJSON, false)

		c := minimalCollection("cov-agent", "REPRESENTED-HOST", "agent")
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(c))

		rec := httptest.NewRecorder()
		h.GetAttackPathSummary(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Coverage struct {
				TargetsRequested   int    `json:"targetsRequested"`
				TargetsRepresented int    `json:"targetsRepresented"`
				Completeness       string `json:"completeness"`
			} `json:"coverage"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Coverage.TargetsRequested != 2 {
			t.Errorf("TargetsRequested = %d, want 2", out.Coverage.TargetsRequested)
		}
		if out.Coverage.TargetsRepresented != 1 {
			t.Errorf("TargetsRepresented = %d, want 1 (only REPRESENTED-HOST appears in the graph)", out.Coverage.TargetsRepresented)
		}
		if out.Coverage.Completeness != "Limited" {
			t.Errorf("Completeness = %q, want Limited", out.Coverage.Completeness)
		}
	})
}

func TestGetAttackPathSummary_CoverageNoRequestLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		c := minimalCollection("no-reqlog-agent", "H1", "agent")
		h.SubmitAttackPathCollection(httptest.NewRecorder(), collectionReq(c))

		rec := httptest.NewRecorder()
		h.GetAttackPathSummary(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out struct {
			Coverage struct {
				Completeness string `json:"completeness"`
			} `json:"coverage"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Coverage.Completeness != "Unknown" {
			t.Errorf("Completeness = %q, want Unknown when no request log exists", out.Coverage.Completeness)
		}
	})
}
