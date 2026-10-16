package sentinelone

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQueryThreats_ReturnsNormalizedThreats_WithinWindow(t *testing.T) {
	created := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"id": "threat-1", "agentId": "agent-1", "computerName": "HOST1",
					"incidentStatus": "unresolved", "mitigationStatus": "not_mitigated",
					"classificationName": "malware", "createdAt": created.Format(time.RFC3339),
				},
			},
			"pagination": map[string]any{"nextCursor": "", "totalItems": 1},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	threats, err := c.QueryThreats(context.Background(), created.Add(-time.Hour), created.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryThreats: %v", err)
	}
	if len(threats) != 1 {
		t.Fatalf("threats = %+v, want 1", threats)
	}
	th := threats[0]
	if th.ID != "threat-1" || th.AgentID != "agent-1" || th.ComputerName != "HOST1" ||
		th.IncidentStatus != "unresolved" || th.MitigationStatus != "not_mitigated" ||
		th.ClassificationName != "malware" {
		t.Fatalf("threat = %+v, missing or wrong field(s)", th)
	}
	if !th.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", th.CreatedAt, created)
	}
}

// TestQueryThreats_ClientSideFiltersOutsideWindow proves the window
// bound is enforced by this client even if the server-side filter
// parameter (unconfirmed against any source) is ignored or wrong --
// the only way to be correct regardless of the real filter param name.
func TestQueryThreats_ClientSideFiltersOutsideWindow(t *testing.T) {
	inWindow := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	outsideWindow := inWindow.Add(-24 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "threat-1", "computerName": "HOST1", "createdAt": inWindow.Format(time.RFC3339)},
				{"id": "threat-2", "computerName": "HOST1", "createdAt": outsideWindow.Format(time.RFC3339)},
			},
			"pagination": map[string]any{"nextCursor": "", "totalItems": 2},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	threats, err := c.QueryThreats(context.Background(), inWindow.Add(-time.Hour), inWindow.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryThreats: %v", err)
	}
	if len(threats) != 1 || threats[0].ID != "threat-1" {
		t.Fatalf("threats = %+v, want only threat-1 (threat-2 is outside the window)", threats)
	}
}

func TestQueryThreats_FollowsCursorPagination(t *testing.T) {
	ts := time.Now().UTC()
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc("/web/api/v2.1/threats", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("cursor") == "" {
			json.NewEncoder(w).Encode(map[string]any{
				"data":       []map[string]any{{"id": "threat-1", "computerName": "HOST1", "createdAt": ts.Format(time.RFC3339)}},
				"pagination": map[string]any{"nextCursor": "p2", "totalItems": 2},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data":       []map[string]any{{"id": "threat-2", "computerName": "HOST1", "createdAt": ts.Format(time.RFC3339)}},
			"pagination": map[string]any{"nextCursor": "", "totalItems": 2},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	threats, err := c.QueryThreats(context.Background(), ts.Add(-time.Hour), ts.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryThreats: %v", err)
	}
	if len(threats) != 2 || calls != 2 {
		t.Fatalf("threats = %+v, calls = %d, want 2 threats and 2 calls", threats, calls)
	}
}

func TestQueryThreats_Forbidden_ReturnsClassifiedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	_, err := c.QueryThreats(context.Background(), time.Now().Add(-time.Hour), time.Now())
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Kind != ErrKindForbidden {
		t.Fatalf("err = %v, want a *ClassifiedError with Kind ErrKindForbidden", err)
	}
}
