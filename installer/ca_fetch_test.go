package main

import (
	"crypto/x509"
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

func TestValidateEnrollment_HealthyServerAcceptedToken(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/ws/agent":
			if r.Header.Get("X-Agent-Token") != "right-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	if err := validateEnrollment(ts.URL, "right-secret", nil); err != nil {
		t.Fatalf("validateEnrollment: %v", err)
	}
}

func TestValidateEnrollment_WrongSecret_Returns401Error(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/ws/agent":
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer ts.Close()

	if err := validateEnrollment(ts.URL, "wrong-secret", nil); err == nil {
		t.Fatal("expected an error for a rejected secret, got nil")
	}
}

func TestValidateEnrollment_UnhealthyServer_ReturnsError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	if err := validateEnrollment(ts.URL, "any-secret", nil); err == nil {
		t.Fatal("expected an error for an unhealthy server, got nil")
	}
}

func TestValidateEnrollment_UnreachableServer_ReturnsError(t *testing.T) {
	if err := validateEnrollment("https://127.0.0.1:1", "any-secret", nil); err == nil {
		t.Fatal("expected an error for an unreachable server, got nil")
	}
}

// TestValidateEnrollment_WithCAPool_RejectsServerNotSignedByIt is the
// actual trust-chain protection this whole mechanism exists for: once an
// embedded CA pool is available, validateEnrollment must verify against
// it instead of skipping verification -- so a serverURL that was somehow
// redirected to a host NOT trusted by that pool (the rogue-collector
// scenario) is rejected before the agent secret is ever sent to it.
func TestValidateEnrollment_WithCAPool_RejectsServerNotSignedByIt(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// An empty pool trusts nothing, including this server's own self-signed
	// cert -- models a caPool that came from the REAL deployment while ts
	// models a ROGUE server the request got redirected to.
	emptyPool := x509.NewCertPool()
	err := validateEnrollment(ts.URL, "any-secret", emptyPool)
	if err == nil {
		t.Fatal("expected an error: a caPool must verify the chain, not skip verification")
	}
}

// TestValidateEnrollment_WithCAPool_AcceptsServerSignedByIt is the
// matching positive case: the real deployment's own server, whose cert
// IS trusted by the pool, must still work once verification is enforced.
func TestValidateEnrollment_WithCAPool_AcceptsServerSignedByIt(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/ws/agent":
			if r.Header.Get("X-Agent-Token") != "right-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	if err := validateEnrollment(ts.URL, "right-secret", pool); err != nil {
		t.Fatalf("validateEnrollment with the server's own cert trusted: %v", err)
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
