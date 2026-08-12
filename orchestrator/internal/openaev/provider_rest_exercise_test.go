package openaev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExerciseRESTProvider_List_PrefixesIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization header = %q, want Bearer test-token", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/exercises" {
			t.Errorf("path = %q, want /api/exercises", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"exercise_id": "ex-1", "exercise_name": "Drill One", "exercise_updated_at": "2026-08-01T09:00:00Z"}
		]`))
	}))
	defer srv.Close()

	p := NewExerciseRESTProvider(srv.URL, "test-token")
	refs, err := p.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("refs = %d, want 1", len(refs))
	}
	if refs[0].ID != "exercise:ex-1" {
		t.Errorf("refs[0].ID = %q, want exercise:ex-1", refs[0].ID)
	}
	if refs[0].Name != "Drill One" {
		t.Errorf("refs[0].Name = %q, want Drill One", refs[0].Name)
	}
}

func TestExerciseRESTProvider_Fetch_StripsPrefixForExportRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/exercises/ex-1/export" {
			t.Errorf("path = %q, want /api/exercises/ex-1/export (prefix must be stripped)", r.URL.Path)
		}
		w.Write(buildFixtureExerciseZip(t, fixtureExerciseJSON))
	}))
	defer srv.Close()

	p := NewExerciseRESTProvider(srv.URL, "test-token")
	data, err := p.Fetch(context.Background(), "exercise:ex-1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	parsed, err := ParseBundle(data) // Fetch's output must already be ParseBundle-compatible
	if err != nil {
		t.Fatalf("ParseBundle(Fetch output): %v", err)
	}
	if parsed.Scenario.ID != "exercise:ex-1" {
		t.Errorf("parsed.Scenario.ID = %q, want exercise:ex-1 (full prefixed ID re-stamped)", parsed.Scenario.ID)
	}
	if parsed.Scenario.Name != "Live Fire Drill" {
		t.Errorf("parsed.Scenario.Name = %q", parsed.Scenario.Name)
	}
	if parsed.SourceType != "exercise" {
		t.Errorf("parsed.SourceType = %q, want exercise", parsed.SourceType)
	}
}

func TestExerciseRESTProvider_List_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewExerciseRESTProvider(srv.URL, "bad-token")
	if _, err := p.List(context.Background()); err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}
