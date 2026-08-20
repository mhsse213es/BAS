package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRunHealthcheck_OKResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path = %q, want /health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setHTTPPortFromURL(t, srv.URL)

	if got := runHealthcheck(); got != 0 {
		t.Errorf("runHealthcheck() = %d, want 0", got)
	}
}

func TestRunHealthcheck_NonOKResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	setHTTPPortFromURL(t, srv.URL)

	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck() = %d, want 1", got)
	}
}

func TestRunHealthcheck_NothingListening(t *testing.T) {
	// Port 1 is reserved (tcpmux) -- nothing listens there, so the request
	// fails to connect, mirroring the exact failure mode this replaces the
	// shell-based "wget || exit 1" check for.
	t.Setenv("HTTP_PORT", "1")

	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck() = %d, want 1", got)
	}
}

func setHTTPPortFromURL(t *testing.T, rawURL string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	t.Setenv("HTTP_PORT", u.Port())
}
