package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func siemHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func siemConfigReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/siem/configs", bytes.NewReader(b))
}

func TestListSIEMConfigs_EmptyAndPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := siemHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListSIEMConfigs(rec, httptest.NewRequest(http.MethodGet, "/api/siem/configs", nil))
		var empty []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 configs, got %d", len(empty))
		}

		createRec := httptest.NewRecorder()
		h.CreateSIEMConfig(createRec, siemConfigReq(map[string]any{
			"name": "Prod QRadar", "provider": "qradar", "consoleUrl": "https://qradar.corp",
		}))
		if createRec.Code != http.StatusOK {
			t.Fatalf("create: status = %d, want 200, body = %s", createRec.Code, createRec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.ListSIEMConfigs(listRec, httptest.NewRequest(http.MethodGet, "/api/siem/configs", nil))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "Prod QRadar" || out[0]["provider"] != "qradar" {
			t.Fatalf("out = %+v, want 1 entry named Prod QRadar/qradar", out)
		}
	})
}

func TestCreateSIEMConfig_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := siemHandler(t, pool)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"missing name", map[string]any{"provider": "qradar"}},
			{"missing provider", map[string]any{"name": "x"}},
			{"invalid provider", map[string]any{"name": "x", "provider": "bogus"}},
			// This correlator only has a working client for qradar (see
			// queryAlerts/TestConnectivity in siem/correlator.go) -- splunk,
			// wazuh and sentinel must never validate as creatable here, or a
			// config silently fails later at query/test time instead of at
			// creation. Splunk/Sentinel detection validation is available
			// today via the separate Detection Validation connectors.
			{"splunk not implemented in this correlator", map[string]any{"name": "x", "provider": "splunk"}},
			{"wazuh not implemented in this correlator", map[string]any{"name": "x", "provider": "wazuh"}},
			{"sentinel not implemented in this correlator", map[string]any{"name": "x", "provider": "sentinel"}},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.CreateSIEMConfig(rec, siemConfigReq(c.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestUpdateSIEMConfig_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := siemHandler(t, pool)
		b, _ := json.Marshal(map[string]any{"name": "x"})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", "nope")
		rec := httptest.NewRecorder()
		h.UpdateSIEMConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestUpdateSIEMConfig_PreservesMaskedSecrets pins the "***" sentinel
// contract: the UI redisplays existing secrets as "***"; submitting that
// back unchanged must NOT overwrite the real stored value.
func TestUpdateSIEMConfig_PreservesMaskedSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := siemHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateSIEMConfig(createRec, siemConfigReq(map[string]any{
			"name": "x", "provider": "qradar", "token": "real-secret-token",
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		b, _ := json.Marshal(map[string]any{"name": "x-renamed", "token": "***"})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", created.ID)
		rec := httptest.NewRecorder()
		h.UpdateSIEMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var name, token string
		if err := pool.QueryRow(context.Background(),
			`SELECT name, token FROM siem_configs WHERE id=$1`, created.ID,
		).Scan(&name, &token); err != nil {
			t.Fatalf("query: %v", err)
		}
		if name != "x-renamed" {
			t.Errorf("name = %q, want x-renamed", name)
		}
		if token != "real-secret-token" {
			t.Errorf("token = %q, want the original secret preserved (masked update)", token)
		}
	})
}

func TestDeleteSIEMConfig_NotFoundAndSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := siemHandler(t, pool)
		notFoundRec := httptest.NewRecorder()
		h.DeleteSIEMConfig(notFoundRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if notFoundRec.Code != http.StatusNotFound {
			t.Fatalf("not found: status = %d, want 404", notFoundRec.Code)
		}

		createRec := httptest.NewRecorder()
		h.CreateSIEMConfig(createRec, siemConfigReq(map[string]any{"name": "x", "provider": "qradar"}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeleteSIEMConfig(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200", delRec.Code)
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM siem_configs WHERE id=$1`, created.ID).Scan(&n)
		if n != 0 {
			t.Fatalf("expected the config to be gone, found %d rows", n)
		}
	})
}

func TestTestSIEMConfig_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := siemHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TestSIEMConfig(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// Note: there is deliberately no "test an unsupported-provider config" case
// here. Non-qradar providers are now rejected at creation (see
// CreateSIEMConfig and TestCreateSIEMConfig_ValidationErrors), so a config
// that TestSIEMConfig could run against is always qradar -- there is no
// reachable unsupported-provider state left to exercise at test time.

func TestTestSIEMConfig_QRadarSuccessAndAuthFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mock := newQRadarMock(t, nil, false)
		defer mock.Close()
		h := siemHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateSIEMConfig(createRec, siemConfigReq(map[string]any{
			"name": "x", "provider": "qradar", "consoleUrl": mock.URL, "token": "good-token",
		}))
		var ok struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &ok)

		rec := httptest.NewRecorder()
		h.TestSIEMConfig(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", ok.ID))
		var out struct {
			OK bool `json:"ok"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if !out.OK {
			t.Fatalf("expected ok:true against the mock QRadar server, body = %s", rec.Body.String())
		}

		authFailMock := newQRadarMock(t, nil, true)
		defer authFailMock.Close()
		createRec2 := httptest.NewRecorder()
		h.CreateSIEMConfig(createRec2, siemConfigReq(map[string]any{
			"name": "bad", "provider": "qradar", "consoleUrl": authFailMock.URL, "token": "bad-token",
		}))
		var bad struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec2.Body.Bytes(), &bad)

		rec2 := httptest.NewRecorder()
		h.TestSIEMConfig(rec2, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", bad.ID))
		var out2 struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		json.Unmarshal(rec2.Body.Bytes(), &out2)
		if out2.OK || out2.Error == "" {
			t.Fatalf("expected ok:false against the auth-failing mock, got %+v", out2)
		}
	})
}
