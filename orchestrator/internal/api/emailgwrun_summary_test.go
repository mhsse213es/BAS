package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwrun"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestBuildEmailGWRunsSummary_EmptyInput_ReturnsZeroValueSummary(t *testing.T) {
	summary := buildEmailGWRunsSummary(nil)
	if summary.Total != 0 {
		t.Errorf("Total = %d, want 0", summary.Total)
	}
	if len(summary.ByStatus) != 0 {
		t.Errorf("ByStatus = %+v, want empty", summary.ByStatus)
	}
	if len(summary.Scenarios) != 0 {
		t.Errorf("Scenarios = %+v, want empty", summary.Scenarios)
	}
}

func TestBuildEmailGWRunsSummary_AggregatesByStatusAndScenario(t *testing.T) {
	now := time.Now()
	runs := []*emailgwrun.EmailGWRun{
		{ID: "r1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusCompleted, StartedAt: now},
		{ID: "r2", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusPartial, StartedAt: now.Add(time.Minute)},
		{ID: "r3", ScenarioID: "EG-005.known-good", Status: emailgwrun.StatusFailed, StartedAt: now},
	}
	summary := buildEmailGWRunsSummary(runs)

	if summary.Total != 3 {
		t.Errorf("Total = %d, want 3", summary.Total)
	}
	wantByStatus := map[string]int{"completed": 1, "partial": 1, "failed": 1}
	for status, want := range wantByStatus {
		if got := summary.ByStatus[status]; got != want {
			t.Errorf("ByStatus[%q] = %d, want %d", status, got, want)
		}
	}
	if len(summary.Scenarios) != 2 {
		t.Fatalf("len(Scenarios) = %d, want 2", len(summary.Scenarios))
	}

	byID := map[string]EmailGWScenarioSummary{}
	for _, sc := range summary.Scenarios {
		byID[sc.ScenarioID] = sc
	}
	eg002 := byID["EG-002.known-bad"]
	if eg002.RunCount != 2 || eg002.ByStatus["completed"] != 1 || eg002.ByStatus["partial"] != 1 {
		t.Errorf("EG-002.known-bad summary = %+v, want RunCount=2, completed=1, partial=1", eg002)
	}
	eg005 := byID["EG-005.known-good"]
	if eg005.RunCount != 1 || eg005.ByStatus["failed"] != 1 {
		t.Errorf("EG-005.known-good summary = %+v, want RunCount=1, failed=1", eg005)
	}
}

func TestBuildEmailGWRunsSummary_LatestRunIsMostRecentStartedAt_NotListOrder(t *testing.T) {
	now := time.Now()
	runs := []*emailgwrun.EmailGWRun{
		{ID: "oldest", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusFailed, StartedAt: now.Add(-time.Hour)},
		{ID: "newest", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusCompleted, StartedAt: now},
		{ID: "middle", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusPartial, StartedAt: now.Add(-time.Minute)},
	}
	summary := buildEmailGWRunsSummary(runs)
	if len(summary.Scenarios) != 1 {
		t.Fatalf("len(Scenarios) = %d, want 1", len(summary.Scenarios))
	}
	sc := summary.Scenarios[0]
	if sc.LatestRunID != "newest" || sc.LatestStatus != emailgwrun.StatusCompleted {
		t.Errorf("latest run = %+v, want id=newest status=completed (the max StartedAt, not list position)", sc)
	}
}

func TestBuildEmailGWRunsSummary_ScenarioOrderIsFirstSeenInInput(t *testing.T) {
	runs := []*emailgwrun.EmailGWRun{
		{ID: "r1", ScenarioID: "EG-005.known-good", Status: emailgwrun.StatusCompleted, StartedAt: time.Now()},
		{ID: "r2", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusCompleted, StartedAt: time.Now()},
		{ID: "r3", ScenarioID: "EG-005.known-good", Status: emailgwrun.StatusCompleted, StartedAt: time.Now()},
	}
	summary := buildEmailGWRunsSummary(runs)
	if len(summary.Scenarios) != 2 || summary.Scenarios[0].ScenarioID != "EG-005.known-good" || summary.Scenarios[1].ScenarioID != "EG-002.known-bad" {
		t.Errorf("Scenarios = %+v, want [EG-005.known-good, EG-002.known-bad] in first-seen order", summary.Scenarios)
	}
}

func TestGetEmailGWRunsSummary_ReflectsRealPersistedRuns(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run1 := &emailgwrun.EmailGWRun{ID: "summary-run-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusCompleted, StartedAt: time.Now().UTC()}
		run2 := &emailgwrun.EmailGWRun{ID: "summary-run-2", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusFailed, StartedAt: time.Now().UTC()}
		for _, r := range []*emailgwrun.EmailGWRun{run1, run2} {
			if err := db.InsertEmailGWRun(ctx, pool, r); err != nil {
				t.Fatalf("insert %s: %v", r.ID, err)
			}
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/emailgw-runs/summary", nil, auth.RoleAnalyst, "any-authenticated-user")
		rec := callAuthed(h.GetEmailGWRunsSummary, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var summary EmailGWRunsSummary
		if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if summary.Total < 2 {
			t.Fatalf("Total = %d, want at least 2 (the two just-inserted rows)", summary.Total)
		}
		var found bool
		for _, sc := range summary.Scenarios {
			if sc.ScenarioID == "EG-002.known-bad" && sc.RunCount >= 2 {
				found = true
			}
		}
		if !found {
			t.Errorf("summary.Scenarios missing EG-002.known-bad with RunCount >= 2: %+v", summary.Scenarios)
		}
	})
}

// TestEmailGWRunsSummaryRoute_ResolvesToSummaryNotID proves, through the
// real chi router (not a direct handler call, which would bypass path
// matching entirely), that GET /api/emailgw-runs/summary hits
// GetEmailGWRunsSummary and not GetEmailGWRun with id="summary".
func TestEmailGWRunsSummaryRoute_ResolvesToSummaryNotID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		router := Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)

		req := authedRequest(t, http.MethodGet, "/api/emailgw-runs/summary", nil, auth.RoleAnalyst, "any-authenticated-user")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code == http.StatusNotFound {
			t.Fatalf("status = 404 -- GET /api/emailgw-runs/summary did not resolve to GetEmailGWRunsSummary, body = %s", rec.Body.String())
		}
		var summary EmailGWRunsSummary
		if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
			t.Fatalf("response is not an EmailGWRunsSummary (resolved to the wrong handler?): status=%d body=%s err=%v", rec.Code, rec.Body.String(), err)
		}
	})
}

func TestGetEmailGWMetrics_ReflectsRealPersistedRunsSplitByEnvironment(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		labRun := &emailgwrun.EmailGWRun{ID: "metrics-lab-1", ScenarioID: "EG-002.known-bad", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusFailed, StartedAt: time.Now().UTC()}
		customerRun := &emailgwrun.EmailGWRun{ID: "metrics-customer-1", ScenarioID: "EG-002.known-bad", Environment: emailgwrun.EnvironmentCustomer, Status: emailgwrun.StatusFailed, StartedAt: time.Now().UTC()}
		for _, r := range []*emailgwrun.EmailGWRun{labRun, customerRun} {
			if err := db.InsertEmailGWRun(ctx, pool, r); err != nil {
				t.Fatalf("insert %s: %v", r.ID, err)
			}
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/emailgw/metrics", nil, auth.RoleAnalyst, "any-authenticated-user")
		rec := callAuthed(h.GetEmailGWMetrics, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var got EmailGWMetricsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Lab.Detection.Outcomes.Failed < 1 {
			t.Errorf("lab failed = %d, want at least 1 (the just-inserted lab run)", got.Lab.Detection.Outcomes.Failed)
		}
		if got.Customer.Detection.Outcomes.Failed < 1 {
			t.Errorf("customer failed = %d, want at least 1 (the just-inserted customer run)", got.Customer.Detection.Outcomes.Failed)
		}
		if got.Lab.Environment != emailgwrun.EnvironmentLab || got.Customer.Environment != emailgwrun.EnvironmentCustomer {
			t.Errorf("Lab.Environment=%q Customer.Environment=%q, want each tagged with its own bucket", got.Lab.Environment, got.Customer.Environment)
		}
	})
}
