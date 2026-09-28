package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// These three tests were updated for the deployment-topology fix:
// runHealthcheck() now probes HTTP_PORT_ENROLL over HTTPS (9443 requires a
// client certificate this in-process self-check has no way to present),
// not HTTP_PORT over plain HTTP. See TestRunHealthcheck_ProbesEnrollPortOverHTTPS
// for the test that specifically pins "probes the ENROLL port, not HTTP_PORT".
func TestRunHealthcheck_OKResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path = %q, want /health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setEnrollPortFromURL(t, srv.URL)

	if got := runHealthcheck(); got != 0 {
		t.Errorf("runHealthcheck() = %d, want 0", got)
	}
}

func TestRunHealthcheck_NonOKResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	setEnrollPortFromURL(t, srv.URL)

	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck() = %d, want 1", got)
	}
}

func TestRunHealthcheck_NothingListening(t *testing.T) {
	// Port 1 is reserved (tcpmux) -- nothing listens there, so the request
	// fails to connect, mirroring the exact failure mode this replaces the
	// shell-based "wget || exit 1" check for.
	t.Setenv("HTTP_PORT_ENROLL", "1")

	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck() = %d, want 1", got)
	}
}

// TestRunHealthcheck_ProbesEnrollPortOverHTTPS pins the actual design
// property this task changes: a real /health responder on HTTP_PORT_ENROLL
// makes the healthcheck pass even when HTTP_PORT points at nothing at all
// -- proving it's HTTP_PORT_ENROLL being probed, not HTTP_PORT (which is
// now the mTLS listener and would always fail this in-process check anyway).
func TestRunHealthcheck_ProbesEnrollPortOverHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	setEnrollPortFromURL(t, srv.URL)
	t.Setenv("HTTP_PORT", "1") // deliberately nothing listening here -- proves this is NOT what's being probed

	if got := runHealthcheck(); got != 0 {
		t.Errorf("runHealthcheck() = %d, want 0 (healthy) when HTTP_PORT_ENROLL points at a real /health responder", got)
	}
}

func setEnrollPortFromURL(t *testing.T, rawURL string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	t.Setenv("HTTP_PORT_ENROLL", u.Port())
}
