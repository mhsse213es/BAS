package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const testCARootPEM = "-----BEGIN CERTIFICATE-----\nMIIBdummyTestOnlyCertificateBodyNotParsedHere==\n-----END CERTIFICATE-----\n"

// fetchDeploymentCARoot must derive the dashboard listener URL from the
// configured mTLS server URL (BAS_DASHBOARD_PORT overriding the 9543 default,
// never the :9443 server port, which requires a client cert), GET
// /api/config/ca-root over a deliberately unverified TLS connection, and
// return the PEM body.
func TestFetchDeploymentCARoot_FetchesFromDashboardPort(t *testing.T) {
	var gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		io.WriteString(w, testCARootPEM)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	// The test server listens on a random port; point the dashboard-port
	// override at it and give fetchDeploymentCARoot an mTLS-style :9443 URL
	// for the same host, exactly as a real install would.
	t.Setenv("BAS_DASHBOARD_PORT", u.Port())

	got, err := fetchDeploymentCARoot("https://" + u.Hostname() + ":9443")
	if err != nil {
		t.Fatalf("fetchDeploymentCARoot: %v", err)
	}
	if string(got) != testCARootPEM {
		t.Errorf("fetched PEM = %q, want %q", got, testCARootPEM)
	}
	if gotPath != "/api/config/ca-root" {
		t.Errorf("requested path = %q, want /api/config/ca-root", gotPath)
	}
}

// A response that is not a PEM certificate (e.g. an HTML error page returned
// by a misconfigured reverse proxy) must be rejected rather than written to
// disk as a bogus trust anchor.
func TestFetchDeploymentCARoot_RejectsNonPEM(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "<html><body>not a certificate</body></html>")
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	t.Setenv("BAS_DASHBOARD_PORT", u.Port())

	if _, err := fetchDeploymentCARoot("https://" + u.Hostname() + ":9443"); err == nil {
		t.Error("expected an error for a non-PEM ca-root response, got nil")
	}
}

// A non-200 status must surface as an error, not a silently-saved empty root.
func TestFetchDeploymentCARoot_RejectsNon200(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	t.Setenv("BAS_DASHBOARD_PORT", u.Port())

	if _, err := fetchDeploymentCARoot("https://" + u.Hostname() + ":9443"); err == nil {
		t.Error("expected an error for a non-200 ca-root response, got nil")
	}
}
