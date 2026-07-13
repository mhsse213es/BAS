package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ticketing"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ticketingHandler builds a Handler with no ticketing manager attached — the
// baseline for the many handlers that gracefully degrade when ticketing
// isn't configured.
func ticketingHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

// ticketingHandlerWithManager builds a Handler with a real, DB-backed
// ticketing.Manager attached (WithTicketing) — used by every test that
// exercises the configured/connected path.
func ticketingHandlerWithManager(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	mgr := ticketing.NewManager(pool)
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithTicketing(mgr)
}

func ticketingConfigReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/ticketing/configs", bytes.NewReader(b))
}

func TestListTicketingConfigs_NilTicketingReturnsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListTicketingConfigs(rec, httptest.NewRequest(http.MethodGet, "/api/ticketing/configs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Fatalf("expected 0 configs (nil ticketing), got %d", len(out))
		}
	})
}

func TestCreateTicketingConfig_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"invalid provider", map[string]any{"name": "x", "provider": "bogus"}},
			{"invalid autoCreate", map[string]any{"name": "x", "provider": "webhook", "autoCreate": "bogus"}},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.CreateTicketingConfig(rec, ticketingConfigReq(c.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestCreateTicketingConfig_DefaultsAutoCreateToOff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		rec := httptest.NewRecorder()
		h.CreateTicketingConfig(rec, ticketingConfigReq(map[string]any{
			"name": "x", "provider": "webhook", "enabled": true,
			"settings": map[string]string{"url": "http://example.invalid"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			ID string `json:"id"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		var autoCreate string
		pool.QueryRow(context.Background(), `SELECT auto_create FROM ticketing_configs WHERE id=$1`, out.ID).Scan(&autoCreate)
		if autoCreate != "off" {
			t.Errorf("auto_create = %q, want off (default)", autoCreate)
		}
	})
}

func TestListTicketingConfigs_ReflectsCreatedAndReloadsManager(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		h.CreateTicketingConfig(httptest.NewRecorder(), ticketingConfigReq(map[string]any{
			"name": "Webhook A", "provider": "webhook", "enabled": true,
			"settings": map[string]string{"url": "http://example.invalid"},
		}))

		rec := httptest.NewRecorder()
		h.ListTicketingConfigs(rec, httptest.NewRequest(http.MethodGet, "/api/ticketing/configs", nil))
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "Webhook A" {
			t.Fatalf("out = %+v, want 1 entry named Webhook A (Manager.Reload picked up the new config)", out)
		}
	})
}

func TestUpdateTicketingConfig_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		b, _ := json.Marshal(map[string]any{"name": "x"})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", "nope")
		rec := httptest.NewRecorder()
		h.UpdateTicketingConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestUpdateTicketingConfig_PreservesMaskedSettings pins the per-key "***"
// sentinel: only masked keys fall back to their stored value, unmasked keys
// (and new keys) are applied as given.
func TestUpdateTicketingConfig_PreservesMaskedSettings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateTicketingConfig(createRec, ticketingConfigReq(map[string]any{
			"name": "x", "provider": "webhook", "enabled": true,
			"settings": map[string]string{"url": "http://example.invalid", "secret": "s3cr3t"},
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		b, _ := json.Marshal(map[string]any{
			"name": "x-renamed",
			"settings": map[string]string{
				"url":    "http://updated.invalid", // unmasked — applied
				"secret": "***",                    // masked — preserved
			},
		})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", created.ID)
		rec := httptest.NewRecorder()
		h.UpdateTicketingConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var settingsRaw []byte
		pool.QueryRow(context.Background(), `SELECT settings FROM ticketing_configs WHERE id=$1`, created.ID).Scan(&settingsRaw)
		var settings map[string]string
		json.Unmarshal(settingsRaw, &settings)
		if settings["url"] != "http://updated.invalid" {
			t.Errorf("url = %q, want the new value applied", settings["url"])
		}
		if settings["secret"] != "s3cr3t" {
			t.Errorf("secret = %q, want the original preserved (masked update)", settings["secret"])
		}
	})
}

func TestDeleteTicketingConfig_NotFoundAndSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		notFoundRec := httptest.NewRecorder()
		h.DeleteTicketingConfig(notFoundRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if notFoundRec.Code != http.StatusNotFound {
			t.Fatalf("not found: status = %d, want 404", notFoundRec.Code)
		}

		createRec := httptest.NewRecorder()
		h.CreateTicketingConfig(createRec, ticketingConfigReq(map[string]any{"name": "x", "provider": "webhook"}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeleteTicketingConfig(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200", delRec.Code)
		}
	})
}

func TestTestTicketingConfig_NilTicketing503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TestTicketingConfig(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "x"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

// TestTestTicketingConfig_WebhookSuccessAndFailure exercises the real
// connector round trip against a mock webhook receiver: a reachable URL
// succeeds, a config pointing nowhere fails cleanly (not a 5xx).
func TestTestTicketingConfig_WebhookSuccessAndFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mock := newWebhookMock(t, http.StatusOK, `{}`)
		defer mock.Close()
		h := ticketingHandlerWithManager(t, pool)

		okRec := httptest.NewRecorder()
		h.CreateTicketingConfig(okRec, ticketingConfigReq(map[string]any{
			"name": "ok", "provider": "webhook", "enabled": true,
			"settings": map[string]string{"url": mock.URL},
		}))
		var ok struct {
			ID string `json:"id"`
		}
		json.Unmarshal(okRec.Body.Bytes(), &ok)

		rec := httptest.NewRecorder()
		h.TestTicketingConfig(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", ok.ID))
		var out struct {
			OK bool `json:"ok"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if !out.OK {
			t.Fatalf("expected ok:true against a live mock, body = %s", rec.Body.String())
		}

		failMock := newWebhookMock(t, http.StatusInternalServerError, `boom`)
		defer failMock.Close()
		failRec := httptest.NewRecorder()
		h.CreateTicketingConfig(failRec, ticketingConfigReq(map[string]any{
			"name": "fail", "provider": "webhook", "enabled": true,
			"settings": map[string]string{"url": failMock.URL},
		}))
		var bad struct {
			ID string `json:"id"`
		}
		json.Unmarshal(failRec.Body.Bytes(), &bad)

		rec2 := httptest.NewRecorder()
		h.TestTicketingConfig(rec2, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", bad.ID))
		var out2 struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		json.Unmarshal(rec2.Body.Bytes(), &out2)
		if out2.OK || out2.Error == "" {
			t.Fatalf("expected ok:false against a failing mock, got %+v", out2)
		}
	})
}

func TestProbeTicketingConfig_NilTicketing503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ProbeTicketingConfig(rec, ticketingConfigReq(map[string]any{"provider": "webhook"}))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestProbeTicketingConfig_MissingProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		rec := httptest.NewRecorder()
		h.ProbeTicketingConfig(rec, ticketingConfigReq(map[string]any{}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestProbeTicketingConfig_TestsInlineSettingsWithoutSaving pins that Probe
// works from unsaved settings — no ticketing_configs row is created.
func TestProbeTicketingConfig_TestsInlineSettingsWithoutSaving(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mock := newWebhookMock(t, http.StatusOK, `{}`)
		defer mock.Close()
		h := ticketingHandlerWithManager(t, pool)

		rec := httptest.NewRecorder()
		h.ProbeTicketingConfig(rec, ticketingConfigReq(map[string]any{
			"provider": "webhook", "settings": map[string]string{"url": mock.URL},
		}))
		var out struct {
			OK bool `json:"ok"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if !out.OK {
			t.Fatalf("expected ok:true, body = %s", rec.Body.String())
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM ticketing_configs`).Scan(&n)
		if n != 0 {
			t.Fatalf("probe should not persist a config row, found %d", n)
		}
	})
}

func TestProbeListProjects_UnsupportedProviderForWebhook(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		rec := httptest.NewRecorder()
		h.ProbeListProjects(rec, ticketingConfigReq(map[string]any{
			"provider": "webhook", "settings": map[string]string{},
		}))
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.OK {
			t.Fatalf("project listing is Jira-only — expected ok:false for webhook, got %+v", out)
		}
	})
}
