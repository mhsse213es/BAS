package main

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"audspect/agent/preflight"
)

const cliSecret = "cli-s3cr3t-DO-NOT-LEAK"

func fakeEnrollmentServer(t *testing.T) (srv *httptest.Server, caFile, port string) {
	t.Helper()
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/ws/agent":
			if r.Header.Get("X-Agent-Token") != cliSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	return srv, caFile, u.Port()
}

func runCLI(t *testing.T, a preflightCLIArgs, stdin string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := runPreflightCLI(a, strings.NewReader(stdin), &out)
	if strings.Contains(out.String(), cliSecret) || (a.SecretArg != "" && strings.Contains(out.String(), a.SecretArg)) {
		t.Fatalf("output leaks a secret: %q", out.String())
	}
	return code, out.String()
}

func TestPreflightCLISuccess(t *testing.T) {
	srv, ca, port := fakeEnrollmentServer(t)
	code, out := runCLI(t, preflightCLIArgs{Server: srv.URL, EnrollPort: port, CARootPath: ca, SecretStdin: true}, cliSecret+"\r\n")
	if code != preflight.CodeOK {
		t.Fatalf("exit %d, output %q", code, out)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatal("expected a one-line message")
	}
}

func TestPreflightCLIWrongSecretExitsWithSecretRejected(t *testing.T) {
	srv, ca, port := fakeEnrollmentServer(t)
	code, _ := runCLI(t, preflightCLIArgs{Server: srv.URL, EnrollPort: port, CARootPath: ca, SecretStdin: true}, "some-other-secret\n")
	if code != preflight.CodeSecretRejected {
		t.Fatalf("exit %d, want %d", code, preflight.CodeSecretRejected)
	}
}

func TestPreflightCLIRefusesSecretOnCommandLine(t *testing.T) {
	srv, ca, port := fakeEnrollmentServer(t)
	code, out := runCLI(t, preflightCLIArgs{Server: srv.URL, EnrollPort: port, CARootPath: ca, SecretArg: "typed-on-cmdline", SecretStdin: true}, cliSecret+"\n")
	if code != preflight.CodeInvalidInput {
		t.Fatalf("exit %d, want %d", code, preflight.CodeInvalidInput)
	}
	if !strings.Contains(out, "--secret-stdin") {
		t.Fatalf("message should point at --secret-stdin: %q", out)
	}
}

func TestPreflightCLIRequiresSecretStdin(t *testing.T) {
	srv, ca, port := fakeEnrollmentServer(t)
	code, _ := runCLI(t, preflightCLIArgs{Server: srv.URL, EnrollPort: port, CARootPath: ca}, cliSecret+"\n")
	if code != preflight.CodeInvalidInput {
		t.Fatalf("exit %d, want %d", code, preflight.CodeInvalidInput)
	}
}

func TestPreflightCLIMalformedStdin(t *testing.T) {
	srv, ca, port := fakeEnrollmentServer(t)
	for name, in := range map[string]string{"empty": "", "two lines": "a\nb\n", "control char": "a\x00b\n"} {
		t.Run(name, func(t *testing.T) {
			code, _ := runCLI(t, preflightCLIArgs{Server: srv.URL, EnrollPort: port, CARootPath: ca, SecretStdin: true}, in)
			if code != preflight.CodeInvalidInput {
				t.Fatalf("exit %d, want %d", code, preflight.CodeInvalidInput)
			}
		})
	}
}

func TestPreflightCLIMissingCAFileIsInvalidCA(t *testing.T) {
	srv, _, port := fakeEnrollmentServer(t)
	code, _ := runCLI(t, preflightCLIArgs{Server: srv.URL, EnrollPort: port, CARootPath: filepath.Join(t.TempDir(), "nope.pem"), SecretStdin: true}, cliSecret+"\n")
	if code != preflight.CodeInvalidCA {
		t.Fatalf("exit %d, want %d", code, preflight.CodeInvalidCA)
	}
}

func TestPreflightCLIWritesNothingToDisk(t *testing.T) {
	srv, ca, port := fakeEnrollmentServer(t)
	dir := t.TempDir()
	t.Setenv("TEMP", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TMPDIR", dir)
	runCLI(t, preflightCLIArgs{Server: srv.URL, EnrollPort: port, CARootPath: ca, SecretStdin: true}, cliSecret+"\n")
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("preflight wrote %d file(s) to the temp dir", len(left))
	}
}
