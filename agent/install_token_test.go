package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"audspect/agent/preflight"
)

func TestResolveEnrollmentToken_FromStdin(t *testing.T) {
	tok, err := resolveEnrollmentToken("", true, false, strings.NewReader("bas_enr_abc\n"))
	if err != nil || tok != "bas_enr_abc" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	if _, err := resolveEnrollmentToken("", true, false, strings.NewReader("one\ntwo\n")); err == nil {
		t.Error("more than one line on stdin must be rejected")
	}
	if _, err := resolveEnrollmentToken("", true, false, strings.NewReader("")); err == nil {
		t.Error("empty stdin must be rejected")
	}
}

// Only one thing can own stdin.
func TestResolveEnrollmentToken_RefusesToShareStdinWithTheSecret(t *testing.T) {
	if _, err := resolveEnrollmentToken("", true, true, strings.NewReader("bas_enr_abc\n")); err == nil {
		t.Error("--enrollment-token-stdin together with --secret-stdin must be rejected")
	}
}

// A token read from a file is single use, so the file is removed once it has been read.
func TestResolveEnrollmentToken_FileIsReadAndRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(path, []byte("bas_enr_fromfile\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tok, err := resolveEnrollmentToken(path, false, false, strings.NewReader(""))
	if err != nil || tok != "bas_enr_fromfile" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the token file must be removed after it is read")
	}
	if _, err := resolveEnrollmentToken(path, false, false, strings.NewReader("")); err == nil {
		t.Error("a missing token file must be an error")
	}
}

func TestResolveEnrollmentToken_FileAndStdinTogetherIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(path, []byte("bas_enr_x\n"), 0600)
	if _, err := resolveEnrollmentToken(path, true, false, strings.NewReader("bas_enr_y\n")); err == nil {
		t.Error("two token sources must be rejected, not silently resolved")
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("a rejected request must not consume the file")
	}
}

func TestResolveEnrollmentToken_EnvFallbackIsClearedAfterReading(t *testing.T) {
	t.Setenv("BAS_ENROLLMENT_TOKEN", "bas_enr_fromenv")
	tok, err := resolveEnrollmentToken("", false, false, strings.NewReader(""))
	if err != nil || tok != "bas_enr_fromenv" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	if os.Getenv("BAS_ENROLLMENT_TOKEN") != "" {
		t.Error("the token must be removed from the environment once read")
	}
	if tok, _ := resolveEnrollmentToken("", false, false, strings.NewReader("")); tok != "" {
		t.Errorf("no source must yield no token, got %q", tok)
	}
}

func TestResolveEnrollmentToken_ErrorsNeverContainTheToken(t *testing.T) {
	_, err := resolveEnrollmentToken("", true, false, strings.NewReader("bas_enr_SECRETVALUE\nsecond\n"))
	if err == nil || strings.Contains(err.Error(), "SECRETVALUE") {
		t.Errorf("error must exist and not echo the token: %v", err)
	}
}

// A refused token and an unreachable server are different problems and must be told apart.
func TestEnrollAtInstall_DistinguishesRefusalFromConnectionFailure(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   int
	}{
		{"unauthorized", http.StatusUnauthorized, preflight.CodeEnrollmentRejected},
		{"forbidden", http.StatusForbidden, preflight.CodeEnrollmentRejected},
		{"host already enrolled", http.StatusConflict, preflight.CodeAlreadyEnrolled},
		{"server error", http.StatusInternalServerError, preflight.CodeServerUnreachable},
		{"not found", http.StatusNotFound, preflight.CodeServerUnreachable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("BAS_CERT_DIR", dir)
			ca := newTestCA(t)
			seedDeploymentCA(t, dir, ca)
			srv := newMockOrchestrator(t, ca, tls.NoClientCert, c.status, &csrRecord{})
			cfg := Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "s", EnrollmentToken: "bas_enr_TOKENVALUE"}
			err := enrollAtInstall(context.Background(), cfg, portOf(t, srv.URL), installTestAgentID)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := installExitCode(err); got != c.want {
				t.Errorf("exit code = %d, want %d (%v)", got, c.want, err)
			}
			if strings.Contains(err.Error(), "TOKENVALUE") {
				t.Error("the error must not contain the token")
			}
		})
	}
}

func TestEnrollAtInstall_UnreachableServerIsAConnectionFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	seedDeploymentCA(t, dir, newTestCA(t))
	cfg := Config{ServerURL: "https://127.0.0.1:9443", AgentSecret: "s", EnrollmentToken: "bas_enr_x"}
	err := enrollAtInstall(context.Background(), cfg, "1", installTestAgentID) // nothing listens on port 1
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := installExitCode(err); got != preflight.CodeServerUnreachable {
		t.Errorf("exit code = %d, want %d (%v)", got, preflight.CodeServerUnreachable, err)
	}
	var ie *installEnrollError
	if !errors.As(err, &ie) {
		t.Error("the error should be an installEnrollError so callers can classify it")
	}
}
