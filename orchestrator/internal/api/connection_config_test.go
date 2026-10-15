package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetConnectionConfig_AdvertisesHostPorts proves the connection-config
// endpoint reports the advertised host ports, so the dashboard can build an
// agent-install command that targets the real (possibly remapped) ports
// rather than whatever port the admin's browser happens to be on.
func TestGetConnectionConfig_AdvertisesHostPorts(t *testing.T) {
	h := (&Handler{}).WithAdvertisedPorts(9443, 9445)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config/connection", nil)

	h.GetConnectionConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp["mtlsPort"] != "9443" {
		t.Errorf("mtlsPort = %q, want 9443", resp["mtlsPort"])
	}
	if resp["enrollPort"] != "9445" {
		t.Errorf("enrollPort = %q, want 9445", resp["enrollPort"])
	}
}

// TestGetConnectionConfig_OmitsUnsetPorts: a handler with no advertised ports
// wired must not emit a misleading "0" port the install command would use.
func TestGetConnectionConfig_OmitsUnsetPorts(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config/connection", nil)

	h.GetConnectionConfig(rec, req)

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if v, ok := resp["mtlsPort"]; ok {
		t.Errorf("mtlsPort should be omitted when unset, got %q", v)
	}
	if v, ok := resp["enrollPort"]; ok {
		t.Errorf("enrollPort should be omitted when unset, got %q", v)
	}
}
