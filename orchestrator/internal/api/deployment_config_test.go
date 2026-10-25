package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/cmdsigning"
	"github.com/audspect/bas/internal/deployconfig"
)

func newDeployHandler(t *testing.T) (*Handler, *cmdsigning.SigningKey) {
	t.Helper()
	sk, err := cmdsigning.LoadOrGenerateSigningKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return (&Handler{}).WithAdvertisedPorts(9443, 9444).WithCommandSigningKey(sk), sk
}

func TestGetDeploymentConfig_SignedAndFingerprintMatches(t *testing.T) {
	h, sk := newDeployHandler(t)
	req := httptest.NewRequest(http.MethodGet, "https://bas.example.com:8443/api/config/deployment-config", nil)
	rec := httptest.NewRecorder()
	h.GetDeploymentConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "deployment.json") {
		t.Fatalf("missing attachment name: %q", rec.Header().Get("Content-Disposition"))
	}
	var env struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || env.Config == "" {
		t.Fatalf("not an envelope: %v", err)
	}
	if strings.Contains(rec.Body.String(), h.agentSecret) && h.agentSecret != "" {
		t.Fatal("the agent secret must never be in deployment.json")
	}
	fp, _ := deployconfig.Fingerprint(sk.CertPEM())
	conn := httptest.NewRecorder()
	h.GetConnectionConfig(conn, httptest.NewRequest(http.MethodGet, "/api/config/connection", nil))
	var resp map[string]string
	_ = json.Unmarshal(conn.Body.Bytes(), &resp)
	if resp["deploymentSigningFingerprint"] != fp {
		t.Fatalf("connection config fingerprint %q, want %q", resp["deploymentSigningFingerprint"], fp)
	}
}

func TestGetDeploymentConfig_UsesAdvertisedPortsAndRequestHost(t *testing.T) {
	h, _ := newDeployHandler(t)
	rec := httptest.NewRecorder()
	h.GetDeploymentConfig(rec, httptest.NewRequest(http.MethodGet, "https://bas.example.com:8443/x", nil))
	var env struct{ Config string }
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	b, _ := decodeB64(env.Config)
	if !strings.Contains(string(b), `"serverURL":"https://bas.example.com:9443"`) || !strings.Contains(string(b), `"enrollPort":"9444"`) {
		t.Fatalf("unexpected body %s", b)
	}
}

func TestGetDeploymentConfig_NoSigningKey(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	h.GetDeploymentConfig(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	conn := httptest.NewRecorder()
	h.GetConnectionConfig(conn, httptest.NewRequest(http.MethodGet, "/x", nil))
	if strings.Contains(conn.Body.String(), "deploymentSigningFingerprint") {
		t.Fatal("fingerprint must be omitted without a signing key")
	}
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
