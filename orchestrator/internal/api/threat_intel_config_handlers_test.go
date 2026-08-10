package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/connector"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func threatIntelConfigReq(method, connector string, body map[string]any) *http.Request {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "/x", bytes.NewReader(b))
	return withURLParam(req, "connector", connector)
}

func TestGetThreatIntelConfig_UnknownConnector_BadRequest(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.GetThreatIntelConfig(rec, threatIntelConfigReq(http.MethodGet, "mandiant", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown connector)", rec.Code)
	}
}

func TestPutThreatIntelConfig_NeverReturnsApiKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		putRec := httptest.NewRecorder()
		h.PutThreatIntelConfig(putRec, threatIntelConfigReq(http.MethodPut, "misp", map[string]any{
			"baseUrl": "https://misp.example.com", "apiKey": "secret-key-1", "enabled": true,
		}))
		if putRec.Code != http.StatusOK {
			t.Fatalf("put status = %d, body = %s", putRec.Code, putRec.Body.String())
		}

		getRec := httptest.NewRecorder()
		h.GetThreatIntelConfig(getRec, threatIntelConfigReq(http.MethodGet, "misp", nil))
		var resp map[string]any
		json.Unmarshal(getRec.Body.Bytes(), &resp)
		if _, present := resp["apiKey"]; present {
			t.Errorf("GET response contains apiKey field, must never return the stored secret: %v", resp)
		}
		if resp["baseUrl"] != "https://misp.example.com" {
			t.Errorf("baseUrl = %v, want https://misp.example.com", resp["baseUrl"])
		}
	})
}

func TestPutThreatIntelConfig_EmptyApiKeyKeepsExisting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		h.PutThreatIntelConfig(httptest.NewRecorder(), threatIntelConfigReq(http.MethodPut, "otx", map[string]any{
			"apiKey": "first-key", "enabled": true,
		}))
		// Second PUT with an empty apiKey must not wipe out "first-key".
		h.PutThreatIntelConfig(httptest.NewRecorder(), threatIntelConfigReq(http.MethodPut, "otx", map[string]any{
			"apiKey": "", "enabled": true,
		}))
		var apiKey string
		if err := pool.QueryRow(context.Background(),
			`SELECT api_key FROM threat_intel_config WHERE connector='otx'`,
		).Scan(&apiKey); err != nil {
			t.Fatalf("query: %v", err)
		}
		if apiKey != "first-key" {
			t.Errorf("api_key = %q, want unchanged %q", apiKey, "first-key")
		}
	})
}

func TestPutThreatIntelConfig_MispReconfiguresScheduler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sched := connector.NewScheduler(nil, nil, nil, 24, nil, nil)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithScheduler(sched)
		rec := httptest.NewRecorder()
		h.PutThreatIntelConfig(rec, threatIntelConfigReq(http.MethodPut, "misp", map[string]any{
			"baseUrl": "https://misp.example.com", "apiKey": "misp-key", "enabled": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		st := sched.Status()
		if !st.MISPEnabled {
			t.Error("scheduler status shows MISPEnabled=false after enabling MISP via config save — Reconfigure was not called correctly")
		}
	})
}

func TestTestThreatIntelConfig_UnreachableURL_ReturnsOkFalse(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.TestThreatIntelConfig(rec, threatIntelConfigReq(http.MethodPost, "misp", map[string]any{
		"baseUrl": "http://127.0.0.1:1", "apiKey": "whatever",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (test failures are reported as ok:false in the body, not an HTTP error)", rec.Code)
	}
	var resp struct {
		OK bool `json:"ok"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.OK {
		t.Error("ok = true for an unreachable URL, want false")
	}
}
