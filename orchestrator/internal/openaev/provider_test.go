package openaev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRESTProvider_List_ParsesScenarios(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization header = %q, want Bearer test-token", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/scenarios" {
			t.Errorf("path = %q, want /api/scenarios", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"scenario_id": "sc-1", "scenario_name": "One", "scenario_updated_at": "2026-07-10T12:00:00Z"},
			{"scenario_id": "sc-2", "scenario_name": "Two", "scenario_updated_at": "2026-07-11T12:00:00Z"}
		]`))
	}))
	defer srv.Close()

	p := NewRESTProvider(srv.URL, "test-token")
	refs, err := p.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want 2", len(refs))
	}
	if refs[0].ID != "sc-1" || refs[0].Name != "One" {
		t.Errorf("refs[0] = %+v", refs[0])
	}
}

func TestRESTProvider_List_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewRESTProvider(srv.URL, "bad-token")
	if _, err := p.List(context.Background()); err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}

func TestRESTProvider_Fetch_ReturnsBundleBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/scenarios/sc-1/export" {
			t.Errorf("path = %q, want /api/scenarios/sc-1/export", r.URL.Path)
		}
		w.Write([]byte("fake-zip-bytes"))
	}))
	defer srv.Close()

	p := NewRESTProvider(srv.URL, "test-token")
	data, err := p.Fetch(context.Background(), "sc-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(data) != "fake-zip-bytes" {
		t.Errorf("data = %q", data)
	}
}

func TestBundleProvider_ListAndFetch(t *testing.T) {
	p := NewBundleProvider("sc-uploaded", []byte("zip-content"))
	refs, err := p.List(context.Background())
	if err != nil || len(refs) != 1 || refs[0].ID != "sc-uploaded" {
		t.Fatalf("List = %+v, err = %v", refs, err)
	}
	data, err := p.Fetch(context.Background(), "sc-uploaded")
	if err != nil || string(data) != "zip-content" {
		t.Fatalf("Fetch = %q, err = %v", data, err)
	}
}
