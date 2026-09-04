package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/api"
)

func TestObservabilitySummaryEndpoint(t *testing.T) {
	// Create a test request to the observability summary endpoint
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/api/observability/summary", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Record the response
	rr := httptest.NewRecorder()

	// Create a simple handler to test
	handler := http.HandlerFunc(api.HandleObservabilitySummary)
	handler.ServeHTTP(rr, req)

	// Verify response status
	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", rr.Code)
	}

	// Verify response content type
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected content-type application/json, got %s", ct)
	}

	// Verify response is valid JSON
	var summary api.ObservabilitySummary
	if err := json.NewDecoder(rr.Body).Decode(&summary); err != nil {
		t.Errorf("response is not valid JSON: %v", err)
	}

	// Verify summary has required fields
	if summary.Timestamp == "" {
		t.Error("summary.Timestamp should not be empty")
	}
	if summary.SchedulerHealth == nil {
		t.Error("summary.SchedulerHealth should not be nil")
	}
	if summary.RecentRuns == nil {
		t.Error("summary.RecentRuns should not be nil")
	}
}

func TestObservabilitySummaryResponseStructure(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/observability/summary", nil)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(api.HandleObservabilitySummary)
	handler.ServeHTTP(rr, req)

	var summary api.ObservabilitySummary
	json.NewDecoder(rr.Body).Decode(&summary)

	// Verify SchedulerHealth fields
	if summary.SchedulerHealth.TicksPerSecond < 0 {
		t.Error("TicksPerSecond should be >= 0")
	}
	if summary.SchedulerHealth.ActiveTasks < 0 {
		t.Error("ActiveTasks should be >= 0")
	}
	if summary.SchedulerHealth.QueueDepth < 0 {
		t.Error("QueueDepth should be >= 0")
	}

	// Verify ExecutionMetrics fields
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
}

func TestObservabilitySummaryRecentRuns(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/observability/summary", nil)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(api.HandleObservabilitySummary)
	handler.ServeHTTP(rr, req)

	var summary api.ObservabilitySummary
	json.NewDecoder(rr.Body).Decode(&summary)

	// RecentRuns should be a slice (may be empty)
	if summary.RecentRuns == nil {
		t.Error("RecentRuns should not be nil")
	}

	// Verify each run has required fields if any exist
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
}

func TestObservabilitySummaryJSONMarshalling(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/observability/summary", nil)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(api.HandleObservabilitySummary)
	handler.ServeHTTP(rr, req)

	// Verify the response is valid JSON by round-tripping
	var summary1 api.ObservabilitySummary
	json.NewDecoder(rr.Body).Decode(&summary1)

	// Marshal it back
	data, err := json.Marshal(summary1)
	if err != nil {
		t.Errorf("failed to marshal summary: %v", err)
	}

	// Unmarshal it again
	var summary2 api.ObservabilitySummary
	if err := json.Unmarshal(data, &summary2); err != nil {
		t.Errorf("failed to unmarshal summary: %v", err)
	}

	// Verify round-trip equality
	if summary1.Timestamp != summary2.Timestamp {
		t.Error("timestamp should survive round-trip")
	}
}

func TestObservabilitySummaryContentNotEmpty(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/observability/summary", nil)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(api.HandleObservabilitySummary)
	handler.ServeHTTP(rr, req)

	// Verify response body is not empty
	if rr.Body.Len() == 0 {
		t.Error("response body should not be empty")
	}

	// Verify it's valid JSON
	if !json.Valid(rr.Body.Bytes()) {
		t.Error("response body should be valid JSON")
	}
}
