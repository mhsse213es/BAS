// orchestrator/internal/api/ca_root_handler_test.go
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/pki"
	"github.com/audspect/bas/internal/ws"
)

// TestGetCARoot_ServesPEM covers the gap that stranded a real agent on
// legacy transport: the generated install commands had no way to fetch the
// deployment CA root, so every fresh enrollment silently skipped mTLS and
// never received the command-signing trust cert. This is the unauthenticated
// endpoint those install commands now curl/Invoke-WebRequest before
// --install, so it must serve the exact PEM the CA holds with no auth
// required -- the target machine has no browser session to present.
func TestGetCARoot_ServesPEM(t *testing.T) {
	ca, err := pki.LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	h := New(nil, ws.NewHub(), nil, "").WithPKI(ca)

	rec := httptest.NewRecorder()
	h.GetCARoot(rec, httptest.NewRequest(http.MethodGet, "/api/config/ca-root", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := rec.Body.String()
	want := string(ca.RootCertPEM())
	if got != want {
		t.Fatalf("body = %q, want the CA's own RootCertPEM %q", got, want)
	}
	if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("body does not look like a PEM certificate: %q", got)
	}
}

// TestGetCARoot_NoPKI_404s covers a server with no PKI configured -- the
// agent's own error message for this case ("read deployment CA root ...")
// should never be misattributed to a network problem when the server simply
// never set one up.
func TestGetCARoot_NoPKI_404s(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")

	rec := httptest.NewRecorder()
	h.GetCARoot(rec, httptest.NewRequest(http.MethodGet, "/api/config/ca-root", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
