package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func doObservabilitySummary(t *testing.T, pool *pgxpool.Pool) (*httptest.ResponseRecorder, ObservabilitySummary) {
	t.Helper()
	h := New(pool, ws.NewHub(), nil, "")
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/api/observability/summary", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	rr := httptest.NewRecorder()
	h.GetObservabilitySummary(rr, req)
	var summary ObservabilitySummary
	_ = json.Unmarshal(rr.Body.Bytes(), &summary)
	return rr, summary
}

func TestObservabilitySummaryEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		rr, summary := doObservabilitySummary(t, pool)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status OK, got %d", rr.Code)
		}
		ct := rr.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected content-type application/json, got %s", ct)
		}
		if summary.Timestamp == "" {
			t.Error("summary.Timestamp should not be empty")
		}
		if summary.SchedulerHealth == nil {
			t.Error("summary.SchedulerHealth should not be nil")
		}
		if summary.RecentRuns == nil {
			t.Error("summary.RecentRuns should not be nil")
		}
	})
}

func TestObservabilitySummaryResponseStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, summary := doObservabilitySummary(t, pool)

		if summary.SchedulerHealth.TicksPerSecond < 0 {
			t.Error("TicksPerSecond should be >= 0")
		}
		if summary.SchedulerHealth.ActiveTasks < 0 {
			t.Error("ActiveTasks should be >= 0")
		}
		if summary.SchedulerHealth.QueueDepth < 0 {
			t.Error("QueueDepth should be >= 0")
		}
		if summary.ExecutionMetrics.TotalRuns < 0 {
			t.Error("TotalRuns should be >= 0")
		}
		if summary.ExecutionMetrics.RunningRuns < 0 {
			t.Error("RunningRuns should be >= 0")
		}
		if summary.ExecutionMetrics.CompletedRuns < 0 {
			t.Error("CompletedRuns should be >= 0")
		}
		if summary.ExecutionMetrics.FailedRuns < 0 {
			t.Error("FailedRuns should be >= 0")
		}
	})
}

func TestObservabilitySummaryRecentRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, summary := doObservabilitySummary(t, pool)

		if summary.RecentRuns == nil {
			t.Error("RecentRuns should not be nil")
		}
		for _, run := range summary.RecentRuns {
			if run.ID == "" {
				t.Error("RunSummary.ID should not be empty")
			}
			if run.Status == "" {
				t.Error("RunSummary.Status should not be empty")
			}
			if run.StartedAt == "" {
				t.Error("RunSummary.StartedAt should not be empty")
			}
		}
	})
}

func TestObservabilitySummaryJSONMarshalling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, summary1 := doObservabilitySummary(t, pool)

		data, err := json.Marshal(summary1)
		if err != nil {
			t.Errorf("failed to marshal summary: %v", err)
		}
		var summary2 ObservabilitySummary
		if err := json.Unmarshal(data, &summary2); err != nil {
			t.Errorf("failed to unmarshal summary: %v", err)
		}
		if summary1.Timestamp != summary2.Timestamp {
			t.Error("timestamp should survive round-trip")
		}
	})
}

func TestObservabilitySummaryContentNotEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		rr, _ := doObservabilitySummary(t, pool)

		if rr.Body.Len() == 0 {
			t.Error("response body should not be empty")
		}
		if !json.Valid(rr.Body.Bytes()) {
			t.Error("response body should be valid JSON")
		}
	})
}
