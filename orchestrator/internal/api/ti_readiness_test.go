package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func tiReq(path, query string) *http.Request {
	if query != "" {
		path += "?" + query
	}
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func TestGetTIReadiness_NilEngine503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, nil, nil, "") // no WithReporting
		rec := httptest.NewRecorder()
		h.GetTIReadiness(rec, tiReq("/api/ti/readiness", "agentId=a1"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestGetTIReadiness_MissingParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetTIReadiness(rec, tiReq("/api/ti/readiness", ""))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestGetTIReadiness_UnknownAgent_EmptyState pins the actual (agentId path)
// contract: reportingEngine.Build never errors for an unknown agent — it
// returns a mostly-empty report — so an unrecognized agentId reads as an
// empty-but-200 scores array, not a 404. Only the runId path 404s (a
// specific run genuinely not existing is a harder error — see BuildFromRun).
func TestGetTIReadiness_UnknownAgent_EmptyState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetTIReadiness(rec, tiReq("/api/ti/readiness", "agentId=nope"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (empty state for an unknown agent)", rec.Code)
		}
		var out struct {
			Scores []map[string]any `json:"scores"`
			Total  int              `json:"total"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Total != 0 || len(out.Scores) != 0 {
			t.Fatalf("out = %+v, want empty scores for an unknown agent", out)
		}
	})
}

func TestGetTIReadiness_RunNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetTIReadiness(rec, tiReq("/api/ti/readiness", "runId=nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestGetTIReadiness_Success pins the response shape (scores array + total
// count reconciling). BuildReadinessScores excludes ATT&CK groups with fewer
// than 3 tested techniques, so a small fixture legitimately yields zero
// scores — this test asserts the envelope, not a specific count (the scoring
// formula itself belongs to internal/reporting, out of this API-layer
// sub-phase's scope).
func TestGetTIReadiness_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "tir-ok-run", "tir-ok-agent", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetTIReadiness(rec, tiReq("/api/ti/readiness", "agentId=tir-ok-agent"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Scores []map[string]any `json:"scores"`
			Total  int              `json:"total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Total != len(out.Scores) {
			t.Errorf("total = %d, want len(scores) = %d", out.Total, len(out.Scores))
		}
	})
}

func TestGetTIPriority_NilEngine503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, nil, nil, "")
		rec := httptest.NewRecorder()
		h.GetTIPriority(rec, tiReq("/api/ti/priority", "agentId=a1"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestGetTIPriority_MissingParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetTIPriority(rec, tiReq("/api/ti/priority", ""))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestGetTIPriority_RunNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetTIPriority(rec, tiReq("/api/ti/priority", "runId=nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestGetTIPriority_UnknownAgent_EmptyState mirrors
// TestGetTIReadiness_UnknownAgent_EmptyState — the agentId path never 404s.
func TestGetTIPriority_UnknownAgent_EmptyState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetTIPriority(rec, tiReq("/api/ti/priority", "agentId=nope"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (empty state for an unknown agent)", rec.Code)
		}
		var out struct {
			Total int `json:"total"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Total != 0 {
			t.Fatalf("total = %d, want 0 for an unknown agent", out.Total)
		}
	})
}

// TestGetTIPriority_Success pins the tier-count reconciliation: every scored
// technique is bucketed into exactly one of critical/high/medium/low, so
// their sum must equal total. canonicalResults' 5 techniques all populate
// PriorityScores even with no CVE/EPSS/actor data seeded (those default to
// zero/false — see engine.go's priority computation), so this is
// deterministic without extra threat-intel fixtures.
func TestGetTIPriority_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "tip-ok-run", "tip-ok-agent", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetTIPriority(rec, tiReq("/api/ti/priority", "agentId=tip-ok-agent"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Total int `json:"total"`
			Tiers struct {
				Critical, High, Medium, Low int
			} `json:"tiers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Total == 0 {
			t.Fatal("expected at least one priority score from canonicalResults' 5 techniques")
		}
		sum := out.Tiers.Critical + out.Tiers.High + out.Tiers.Medium + out.Tiers.Low
		if sum != out.Total {
			t.Errorf("tier counts sum to %d, want %d (total)", sum, out.Total)
		}
	})
}
