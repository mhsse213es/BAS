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
