package sentinelone

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	return New(Config{BaseURL: baseURL, APIToken: "tok123"})
}

func TestListAgents_ReturnsNormalizedAgents_AndSendsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]any{
			"data":       []map[string]any{{"id": "agent-1", "computerName": "HOST1"}},
			"pagination": map[string]any{"nextCursor": "", "totalItems": 1},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	agents, err := c.ListAgents(context.Background())
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if gotAuth != "ApiToken tok123" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "ApiToken tok123")
	}
	if len(agents) != 1 || agents[0].ID != "agent-1" || agents[0].ComputerName != "HOST1" {
		t.Fatalf("agents = %+v, want one agent-1/HOST1", agents)
	}
}

func TestListAgents_FollowsCursorPagination(t *testing.T) {
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc("/web/api/v2.1/agents", func(w http.ResponseWriter, r *http.Request) {
		calls++
		cursor := r.URL.Query().Get("cursor")
		if cursor == "" {
			json.NewEncoder(w).Encode(map[string]any{
				"data":       []map[string]any{{"id": "agent-1", "computerName": "HOST1"}},
				"pagination": map[string]any{"nextCursor": "page2", "totalItems": 2},
			})
			return
		}
		if cursor != "page2" {
			t.Errorf("cursor = %q, want %q", cursor, "page2")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data":       []map[string]any{{"id": "agent-2", "computerName": "HOST2"}},
			"pagination": map[string]any{"nextCursor": "", "totalItems": 2},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	agents, err := c.ListAgents(context.Background())
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("agents = %+v, want 2", agents)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestListAgents_Forbidden_ReturnsClassifiedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.ListAgents(context.Background())
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Kind != ErrKindForbidden {
		t.Fatalf("err = %v, want a *ClassifiedError with Kind ErrKindForbidden", err)
	}
}

func TestListAgents_MalformedPayload_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.ListAgents(context.Background()); err == nil {
		t.Fatal("expected an error for a malformed response body")
	}
}

func TestResolveDevice_FindsByComputerName_CaseInsensitive_AndCaches(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{
			"data":       []map[string]any{{"id": "agent-1", "computerName": "Host1.Contoso.Com"}},
			"pagination": map[string]any{"nextCursor": "", "totalItems": 1},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	id, err := c.ResolveDevice(context.Background(), "host1.contoso.com")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if id != "agent-1" {
		t.Fatalf("id = %q, want agent-1", id)
	}
	if _, err := c.ResolveDevice(context.Background(), "host1.contoso.com"); err != nil {
		t.Fatalf("ResolveDevice (cached): %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (second call should reuse the cache)", calls)
	}
}

func TestResolveDevice_NoMatch_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data":       []map[string]any{},
			"pagination": map[string]any{"nextCursor": "", "totalItems": 0},
		})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.ResolveDevice(context.Background(), "NOHOST"); err == nil {
		t.Fatal("expected an error when no agent matches the hostname")
	}
}
