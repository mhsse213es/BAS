// orchestrator/internal/api/agent_install_script_test.go
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The install command downloads this script with no session, so it must be served as-is
// with no auth, and it must be the installer that handles the CA fetch and identity reset.
func TestGetAgentInstallScript_ServesInstaller(t *testing.T) {
	h := New(nil, nil, nil, "")
	rec := httptest.NewRecorder()
	h.GetAgentInstallScript(rec, httptest.NewRequest(http.MethodGet, "/api/agent/install-script", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "#!/bin/bash") {
		t.Fatalf("body does not start with a bash shebang")
	}
	for _, want := range []string{"/api/config/ca-root", "clear_stale_identity", "BAS_SERVER_HOST"} {
		if !strings.Contains(body, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Fatalf("Content-Type = %q", ct)
	}
}

// The installer must never put the agent secret or an enrolment token on a command line, where any local
// user can read it from the process list (audit F-03).
func TestInstallScript_KeepsCredentialsOffCommandLines(t *testing.T) {
	s := string(installAgentLinuxScript)
	if strings.Contains(s, `-secret "$SECRET"`) || strings.Contains(s, "-secret $SECRET") {
		t.Error("the agent secret must not be passed with -secret on the command line")
	}
	for _, want := range []string{"--secret-stdin", "--enrollment-token-file", "BAS_ENROLLMENT_TOKEN", "umask 077"} {
		if !strings.Contains(s, want) {
			t.Errorf("install script missing %q", want)
		}
	}
	if strings.Contains(s, "-enrollment-token ") || strings.Contains(s, "--enrollment-token ") {
		t.Error("a token must not be accepted as a command-line value")
	}
}

// A refused token and an unreachable server are reported differently, from the agent's exit codes.
func TestInstallScript_ReportsRefusalAndConnectionFailureSeparately(t *testing.T) {
	s := string(installAgentLinuxScript)
	for _, want := range []string{"26)", "27)", "refused the enrolment token", "could not reach the server"} {
		if !strings.Contains(s, want) {
			t.Errorf("install script missing %q", want)
		}
	}
}

// The generic setup file is the same for everyone: it embeds no token.
func TestLinuxSetupScript_EmbedsNoCredentials(t *testing.T) {
	script, err := buildLinuxSetupScript("192.168.10.78", 9445, 9443, 9543)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"bas_enr_", "BAS_ENROLLMENT_TOKEN=", "--secret"} {
		if strings.Contains(string(script), bad) {
			t.Errorf("the generic setup header must not contain %q", bad)
		}
	}
}
