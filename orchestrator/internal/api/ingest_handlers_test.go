package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func withTestPool(t *testing.T, fn func(pool *pgxpool.Pool)) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, fn)
}

func newTestIngestHandler(t *testing.T, pool *pgxpool.Pool, key string) *Handler {
	t.Helper()
	if err := db.EnsureIngestSchema(context.Background(), pool); err != nil {
		t.Fatalf("EnsureIngestSchema: %v", err)
	}
	h := New(pool, nil, nil, "test-jwt-secret")
	h.WithIngestAPIKey(key)
	return h
}

func TestIngestEvents_NoAPIKeyConfigured_Returns404(t *testing.T) {
	withTestPool(t, func(pool *pgxpool.Pool) {
		h := newTestIngestHandler(t, pool, "")
		req := httptest.NewRequest(http.MethodPost, "/api/ingest/v1/events", bytes.NewReader([]byte(`{}`)))
		w := httptest.NewRecorder()
		h.IngestEvents(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (endpoint disabled when no key is configured)", w.Code)
		}
	})
}

func TestIngestEvents_WrongKey_Returns401(t *testing.T) {
	withTestPool(t, func(pool *pgxpool.Pool) {
		h := newTestIngestHandler(t, pool, "right-key")
		req := httptest.NewRequest(http.MethodPost, "/api/ingest/v1/events", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Authorization", "Bearer wrong-key")
		w := httptest.NewRecorder()
		h.IngestEvents(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
	})
}

func TestIngestEvents_UnsupportedSchemaVersion_Returns400(t *testing.T) {
	withTestPool(t, func(pool *pgxpool.Pool) {
		h := newTestIngestHandler(t, pool, "right-key")
		body, _ := json.Marshal(map[string]any{"schema_version": 2, "events": []any{}})
		req := httptest.NewRequest(http.MethodPost, "/api/ingest/v1/events", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer right-key")
		w := httptest.NewRecorder()
		h.IngestEvents(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})
}

func TestIngestEvents_ValidBatch_ReturnsPerEventResults(t *testing.T) {
	withTestPool(t, func(pool *pgxpool.Pool) {
		h := newTestIngestHandler(t, pool, "right-key")
		body, _ := json.Marshal(map[string]any{
			"schema_version": 1,
			"events": []map[string]any{
				{"source": "splunk", "external_event_id": "evt-1", "event_type": "detection",
					"ioc": map[string]string{"type": "ip", "value": "203.0.113.9"}},
				{"source": "splunk", "external_event_id": ""}, // invalid: missing id
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/ingest/v1/events", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer right-key")
		w := httptest.NewRecorder()
		h.IngestEvents(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (per-event results, not a batch-level failure)", w.Code)
		}
		var resp struct {
			Results []struct {
				ExternalEventID string `json:"external_event_id"`
				Status          string `json:"status"`
				IOCID           string `json:"ioc_id"`
				Error           string `json:"error"`
			} `json:"results"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(resp.Results) != 2 {
			t.Fatalf("results = %+v, want 2", resp.Results)
		}
		if resp.Results[0].Status != "created" || resp.Results[0].IOCID == "" {
			t.Fatalf("results[0] = %+v, want created with an ioc_id", resp.Results[0])
		}
		if resp.Results[1].Status != "error" {
			t.Fatalf("results[1] = %+v, want error", resp.Results[1])
		}
	})
}
