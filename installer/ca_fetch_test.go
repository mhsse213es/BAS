//go:build windows

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testCAPEM = "-----BEGIN CERTIFICATE-----\nMIIBdummytestcertdata\n-----END CERTIFICATE-----\n"

// The bootstrap client must accept the self-signed deployment cert — that is
// the whole reason it exists. A verifying client cannot, since the CA it would
// need is the very root we are fetching. httptest.NewTLSServer serves a
// self-signed cert, so it models the default BAS_TLS=false deployment exactly.
func TestBootstrapHTTPClient_AcceptsSelfSignedWhereVerifyingClientFails(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	if _, err := (&http.Client{Timeout: 5 * time.Second}).Get(ts.URL); err == nil {
		t.Fatal("expected a verifying client to reject the self-signed cert, got nil error")
	}
	resp, err := bootstrapHTTPClient().Get(ts.URL)
	if err != nil {
		t.Fatalf("bootstrap client should accept the self-signed cert: %v", err)
	}
	resp.Body.Close()
}

func TestFetchDeploymentCA_WritesPEM(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config/ca-root" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(testCAPEM))
	}))
	defer ts.Close()

	dir := t.TempDir()
	caPath, err := fetchDeploymentCA(ts.URL, dir)
	if err != nil {
		t.Fatalf("fetchDeploymentCA: %v", err)
	}
	want := filepath.Join(dir, "deployment-ca.pem")
	if caPath != want {
		t.Fatalf("caPath = %q, want %q", caPath, want)
	}
	got, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read written CA: %v", err)
	}
	if string(got) != testCAPEM {
		t.Fatalf("written CA = %q, want %q", got, testCAPEM)
	}
}

func TestFetchDeploymentCA_RejectsNonPEM(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not a certificate"))
	}))
	defer ts.Close()

	if _, err := fetchDeploymentCA(ts.URL, t.TempDir()); err == nil {
		t.Fatal("expected error for a non-PEM response, got nil")
	}
}

func TestFetchDeploymentCA_RejectsHTTPError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	if _, err := fetchDeploymentCA(ts.URL, t.TempDir()); err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestFetchDeploymentCA_TrimsTrailingSlash(t *testing.T) {
	var gotPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(testCAPEM))
	}))
	defer ts.Close()

	if _, err := fetchDeploymentCA(ts.URL+"/", t.TempDir()); err != nil {
		t.Fatalf("fetchDeploymentCA: %v", err)
	}
	if gotPath != "/api/config/ca-root" {
		t.Fatalf("requested path = %q, want /api/config/ca-root (no double slash)", gotPath)
	}
}
