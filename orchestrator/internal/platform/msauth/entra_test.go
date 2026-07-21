package msauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEntraTokenSource_FetchesAndCaches(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", r.FormValue("grant_type"))
		}
		if r.FormValue("scope") != "https://api.loganalytics.io/.default" {
			t.Errorf("scope = %q", r.FormValue("scope"))
		}
		w.Write([]byte(`{"access_token":"tok-1","expires_in":3600}`))
	}))
	defer srv.Close()

	ts := NewEntraTokenSource("tenant-1", "client-1", "secret-1", "https://api.loganalytics.io/.default")
	ts.TokenURL = srv.URL

	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("token = %q, want tok-1", tok)
	}

	tok2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if tok2 != "tok-1" {
		t.Fatalf("cached token = %q, want tok-1", tok2)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (the second Token() call should reuse the cache)", calls)
	}
}

func TestEntraTokenSource_HTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	ts := NewEntraTokenSource("tenant-1", "client-1", "bad-secret", "scope")
	ts.TokenURL = srv.URL

	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected an error from a 401 token response")
	}
}
