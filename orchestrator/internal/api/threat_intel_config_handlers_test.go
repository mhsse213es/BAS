package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// TestGetThreatIntelConfig_ConfiguredFlagDistinguishesFirstTimeFromUpdate
// proves the GET response tells the frontend whether this connector has
// ever been saved before -- the confirm-diff "you're about to overwrite an
// existing value" modal makes no sense on a genuine first-time setup, only
// once real values are already in place and someone is changing them.
func TestGetThreatIntelConfig_ConfiguredFlagDistinguishesFirstTimeFromUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		preRec := httptest.NewRecorder()
		h.GetThreatIntelConfig(preRec, threatIntelConfigReq(http.MethodGet, "opencti", nil))
		var pre map[string]any
		json.Unmarshal(preRec.Body.Bytes(), &pre)
		if pre["configured"] != false {
			t.Errorf("configured = %v before any save, want false", pre["configured"])
		}

		h.PutThreatIntelConfig(httptest.NewRecorder(), threatIntelConfigReq(http.MethodPut, "opencti", map[string]any{
			"baseUrl": "https://opencti.example.com", "apiKey": "secret-key-1", "enabled": true,
		}))

		postRec := httptest.NewRecorder()
		h.GetThreatIntelConfig(postRec, threatIntelConfigReq(http.MethodGet, "opencti", nil))
		var post map[string]any
		json.Unmarshal(postRec.Body.Bytes(), &post)
		if post["configured"] != true {
			t.Errorf("configured = %v after a save, want true", post["configured"])
		}
	})
}

func TestDeleteThreatIntelConfig_UnknownConnector_BadRequest(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.DeleteThreatIntelConfig(rec, threatIntelConfigReq(http.MethodDelete, "mandiant", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown connector)", rec.Code)
	}
}

// TestDeleteThreatIntelConfig_RemovesStoredCredentials proves DELETE
// actually clears the row -- unlike enabled=false via PUT, which stops
// syncing but leaves the base URL/API key stored, GET must report
// configured=false again afterward.
func TestDeleteThreatIntelConfig_RemovesStoredCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		h.PutThreatIntelConfig(httptest.NewRecorder(), threatIntelConfigReq(http.MethodPut, "misp", map[string]any{
			"baseUrl": "https://misp.example.com", "apiKey": "secret-key-2", "enabled": true,
		}))
		preRec := httptest.NewRecorder()
		h.GetThreatIntelConfig(preRec, threatIntelConfigReq(http.MethodGet, "misp", nil))
		var pre map[string]any
		json.Unmarshal(preRec.Body.Bytes(), &pre)
		if pre["configured"] != true {
			t.Fatalf("configured = %v after save, want true", pre["configured"])
		}

		delRec := httptest.NewRecorder()
		h.DeleteThreatIntelConfig(delRec, threatIntelConfigReq(http.MethodDelete, "misp", nil))
		if delRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", delRec.Code, delRec.Body.String())
		}

		postRec := httptest.NewRecorder()
		h.GetThreatIntelConfig(postRec, threatIntelConfigReq(http.MethodGet, "misp", nil))
		var post map[string]any
		json.Unmarshal(postRec.Body.Bytes(), &post)
		if post["configured"] != false {
			t.Errorf("configured = %v after delete, want false", post["configured"])
		}
		if post["baseUrl"] != "" {
			t.Errorf("baseUrl = %q after delete, want empty", post["baseUrl"])
		}
	})
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

// TestPutThreatIntelConfig_SecondConnectorAlsoTriggersImmediateSync guards
// against Reconfigure's own auto-sync only firing the very first time it
// starts the scheduler from cold. Without the explicit TriggerSync call in
// PutThreatIntelConfig, saving a second connector after the scheduler is
// already running (from the first save) would silently update the source
// list without ever fetching it until the next periodic poll.
func TestPutThreatIntelConfig_SecondConnectorAlsoTriggersImmediateSync(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sched := connector.NewScheduler(nil, nil, nil, 24, nil, nil)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithScheduler(sched)

		// First save: cold start, MISP pointed at an unreachable host --
		// Reconfigure's own internal shouldStart path handles this one.
		h.PutThreatIntelConfig(httptest.NewRecorder(), threatIntelConfigReq(http.MethodPut, "misp", map[string]any{
			"baseUrl": "https://misp.example.com", "apiKey": "misp-key", "enabled": true,
		}))

		deadline := time.Now().Add(5 * time.Second)
		var firstSyncAt time.Time
		for time.Now().Before(deadline) {
			firstSyncAt = sched.Status().LastSyncAt
			if !firstSyncAt.IsZero() {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if firstSyncAt.IsZero() {
			t.Fatal("first save never triggered a sync (LastSyncAt still zero) -- test setup broken")
		}

		// Second save: scheduler is already running -- this is the case
		// Reconfigure's own auto-sync does NOT cover.
		rec := httptest.NewRecorder()
		h.PutThreatIntelConfig(rec, threatIntelConfigReq(http.MethodPut, "opencti", map[string]any{
			"baseUrl": "https://opencti.example.com", "apiKey": "opencti-key", "enabled": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		deadline = time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if sched.Status().LastSyncAt.After(firstSyncAt) {
				return // pass -- a second sync ran after the second save
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("saving a second connector after the scheduler was already running did not trigger an immediate sync")
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
