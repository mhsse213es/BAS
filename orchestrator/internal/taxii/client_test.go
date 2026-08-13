package taxii

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockTAXIIServer is a spec-compliant TAXII 2.1 test double, not a fake
// FS-ISAC -- fixtures represent realistic ISAC content, but the server
// itself only implements the generic TAXII 2.1 surface (discovery, API
// root, collections, paginated objects). See spec's Testing section.
func mockTAXIIServer(t *testing.T, requireBasicAuth bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/taxii2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		json.NewEncoder(w).Encode(map[string]any{
			"title": "Mock TAXII Server", "default": "http://" + r.Host + "/api1", "api_roots": []string{"http://" + r.Host + "/api1"},
		})
	})
	mux.HandleFunc("/api1/collections/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		json.NewEncoder(w).Encode(map[string]any{
			"collections": []map[string]any{{"id": "col-1", "title": "Indicators"}},
		})
	})
	mux.HandleFunc("/api1/collections/col-1/objects/", func(w http.ResponseWriter, r *http.Request) {
		if requireBasicAuth {
			u, p, ok := r.BasicAuth()
			if !ok || u != "user1" || p != "secret1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		if r.URL.Query().Get("next") == "page2" {
			json.NewEncoder(w).Encode(map[string]any{
				"more": false, "next": "",
				"objects": []map[string]any{{"id": "indicator--2", "type": "indicator", "modified": "2026-01-02T00:00:00Z", "pattern": "[domain-name:value = 'evil2.example.com']", "pattern_type": "stix"}},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"more": true, "next": "page2",
			"objects": []map[string]any{{"id": "indicator--1", "type": "indicator", "modified": "2026-01-01T00:00:00Z", "pattern": "[ipv4-addr:value = '203.0.113.9']", "pattern_type": "stix"}},
		})
	})
	return httptest.NewServer(mux)
}

func TestDiscover_ReturnsDefaultAPIRoot(t *testing.T) {
	srv := mockTAXIIServer(t, false)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	d, err := c.Discover(t.Context())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if d.DefaultAPIRoot == "" {
		t.Fatal("expected a non-empty DefaultAPIRoot")
	}
}

func TestListCollections_ReturnsCollections(t *testing.T) {
	srv := mockTAXIIServer(t, false)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	cols, err := c.ListCollections(t.Context(), srv.URL+"/api1")
	if err != nil {
		t.Fatalf("ListCollections: %v", err)
	}
	if len(cols) != 1 || cols[0].ID != "col-1" {
		t.Fatalf("ListCollections() = %+v", cols)
	}
}

func TestPollObjects_PaginatesAcrossTwoPages(t *testing.T) {
	srv := mockTAXIIServer(t, false)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	page1, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, "")
	if err != nil {
		t.Fatalf("PollObjects page1: %v", err)
	}
	if len(page1.Objects) != 1 || !page1.More || page1.Next != "page2" {
		t.Fatalf("page1 = %+v", page1)
	}
	page2, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, page1.Next)
	if err != nil {
		t.Fatalf("PollObjects page2: %v", err)
	}
	if len(page2.Objects) != 1 || page2.More {
		t.Fatalf("page2 = %+v", page2)
	}
}

func TestPollObjects_BasicAuthSucceeds(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "basic", Username: "user1", Password: "secret1"})
	page, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, "")
	if err != nil {
		t.Fatalf("PollObjects with correct basic auth: %v", err)
	}
	if len(page.Objects) != 1 {
		t.Fatalf("page = %+v", page)
	}
}

func TestPollObjects_AuthFailureReturnsErrAuthFailed(t *testing.T) {
	srv := mockTAXIIServer(t, true)
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "basic", Username: "wrong", Password: "wrong"})
	_, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, "")
	var authErr *ErrAuthFailed
	if err == nil {
		t.Fatal("expected an error for bad credentials")
	}
	if ae, ok := err.(*ErrAuthFailed); !ok {
		t.Fatalf("err = %T (%v), want *ErrAuthFailed", err, err)
	} else {
		authErr = ae
	}
	if authErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", authErr.StatusCode)
	}
}

func TestPollObjects_HTTPErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	_, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", nil, "")
	if err == nil {
		t.Fatal("expected an error for HTTP 500")
	}
}

func TestPollObjects_AddedAfterSentAsQueryParam(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		json.NewEncoder(w).Encode(map[string]any{"more": false, "next": "", "objects": []map[string]any{}})
	}))
	defer srv.Close()
	c := NewClient(ConnectorConfig{ServerURL: srv.URL, AuthType: "none"})
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.PollObjects(t.Context(), srv.URL+"/api1", "col-1", &when, ""); err != nil {
		t.Fatalf("PollObjects: %v", err)
	}
	if gotQuery == "" {
		t.Fatal("expected added_after to be sent as a query param")
	}
}
