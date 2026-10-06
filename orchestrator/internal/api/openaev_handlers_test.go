package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/openaev"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fixtureBundleForHandlerTest builds a minimal OpenAEV export ZIP the same
// way openaev.buildFixtureZip does — duplicated here (not imported) since
// that helper is unexported in another package.
func fixtureBundleForHandlerTest(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "Handler Test Scenario.json", Method: zip.Deflate}
	hdr.Comment = "Scenario"
	w, _ := zw.CreateHeader(hdr)
	w.Write([]byte(`{"export_version":1,"scenario_information":{"scenario_id":"sc-handler-test","scenario_name":"Handler Test Scenario","scenario_updated_at":"2026-07-10T00:00:00Z"}}`))
	zw.Close()
	return buf.Bytes()
}

func TestGetOpenAEVConfig_RedactsToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		pool.Exec(context.Background(),
			`INSERT INTO openaev_config (id, base_url, bearer_token, enabled) VALUES (1, 'https://openaev.local', 'super-secret', true)
			 ON CONFLICT (id) DO UPDATE SET base_url = EXCLUDED.base_url, bearer_token = EXCLUDED.bearer_token, enabled = EXCLUDED.enabled`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetOpenAEVConfig(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/config", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["baseUrl"] != "https://openaev.local" {
			t.Errorf("baseUrl = %v", out["baseUrl"])
		}
		if _, present := out["bearerToken"]; present {
			t.Error("bearerToken must never be present in the response")
		}
	})
}

// TestGetOpenAEVConfig_ConfiguredFlagDistinguishesFirstTimeFromUpdate proves
// the GET response tells the frontend whether OpenAEV has ever been saved
// before -- the confirm-diff "you're about to overwrite an existing value"
// modal makes no sense on a genuine first-time setup, only once real values
// are already in place and someone is changing them. Same fix as
// GetThreatIntelConfig's own configured flag for MISP/OpenCTI/OTX.
func TestGetOpenAEVConfig_ConfiguredFlagDistinguishesFirstTimeFromUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		preRec := httptest.NewRecorder()
		h.GetOpenAEVConfig(preRec, httptest.NewRequest(http.MethodGet, "/api/openaev/config", nil))
		var pre map[string]any
		json.Unmarshal(preRec.Body.Bytes(), &pre)
		if pre["configured"] != false {
			t.Errorf("configured = %v before any save, want false", pre["configured"])
		}

		pool.Exec(context.Background(),
			`INSERT INTO openaev_config (id, base_url, bearer_token, enabled) VALUES (1, 'https://openaev.local', 'super-secret', true)
			 ON CONFLICT (id) DO UPDATE SET base_url = EXCLUDED.base_url, bearer_token = EXCLUDED.bearer_token, enabled = EXCLUDED.enabled`)

		postRec := httptest.NewRecorder()
		h.GetOpenAEVConfig(postRec, httptest.NewRequest(http.MethodGet, "/api/openaev/config", nil))
		var post map[string]any
		json.Unmarshal(postRec.Body.Bytes(), &post)
		if post["configured"] != true {
			t.Errorf("configured = %v after a save, want true", post["configured"])
		}
	})
}

// TestDeleteOpenAEVConfig_RemovesStoredCredentials proves DELETE actually
// clears the row -- unlike enabled=false via PUT, which stops syncing but
// leaves the base URL/bearer token stored, GET must report
// configured=false again afterward. Mirrors
// TestDeleteThreatIntelConfig_RemovesStoredCredentials.
func TestDeleteOpenAEVConfig_RemovesStoredCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		h.PutOpenAEVConfig(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/api/openaev/config",
			bytes.NewReader([]byte(`{"baseUrl":"https://openaev.example.com","bearerToken":"secret-token","enabled":true}`))))

		preRec := httptest.NewRecorder()
		h.GetOpenAEVConfig(preRec, httptest.NewRequest(http.MethodGet, "/api/openaev/config", nil))
		var pre map[string]any
		json.Unmarshal(preRec.Body.Bytes(), &pre)
		if pre["configured"] != true {
			t.Fatalf("configured = %v after save, want true", pre["configured"])
		}

		delRec := httptest.NewRecorder()
		h.DeleteOpenAEVConfig(delRec, httptest.NewRequest(http.MethodDelete, "/api/openaev/config", nil))
		if delRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", delRec.Code)
		}

		postRec := httptest.NewRecorder()
		h.GetOpenAEVConfig(postRec, httptest.NewRequest(http.MethodGet, "/api/openaev/config", nil))
		var post map[string]any
		json.Unmarshal(postRec.Body.Bytes(), &post)
		if post["configured"] != false {
			t.Errorf("configured = %v after delete, want false", post["configured"])
		}
	})
}

func TestGetOpenAEVStatus_ReturnsSyncCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		pool.Exec(context.Background(),
			`INSERT INTO openaev_config (id, enabled, last_sync_status, last_sync_created, last_sync_updated, last_sync_skipped, last_sync_errored)
			 VALUES (1, true, 'ok', 3, 2, 5, 1)
			 ON CONFLICT (id) DO UPDATE SET last_sync_status = EXCLUDED.last_sync_status,
			   last_sync_created = EXCLUDED.last_sync_created, last_sync_updated = EXCLUDED.last_sync_updated,
			   last_sync_skipped = EXCLUDED.last_sync_skipped, last_sync_errored = EXCLUDED.last_sync_errored`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetOpenAEVStatus(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/status", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if int(out["lastSyncCreated"].(float64)) != 3 {
			t.Errorf("lastSyncCreated = %v, want 3", out["lastSyncCreated"])
		}
		if int(out["lastSyncSkipped"].(float64)) != 5 {
			t.Errorf("lastSyncSkipped = %v, want 5", out["lastSyncSkipped"])
		}
	})
}

func TestGetOpenAEVConfig_ReturnsSyncCountsDefaultZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetOpenAEVConfig(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/config", nil))

		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["lastSyncCreated"] != float64(0) {
			t.Errorf("lastSyncCreated = %v, want 0 (never synced)", out["lastSyncCreated"])
		}
	})
}

func TestListOpenAEVScenarios_EmptyByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListOpenAEVScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/scenarios", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out []any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Errorf("expected empty list, got %d entries", len(out))
		}
	})
}

func TestListOpenAEVScenarios_DefaultsToScenarioType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := openaev.NewSQLStore(pool)
		store.Upsert(context.Background(), openaev.Scenario{OpenAEVScenarioID: "sc-filter-1", Name: "Scn", SourceType: "scenario"}, openaev.Detail{}, "h1", 10, 1)
		store.Upsert(context.Background(), openaev.Scenario{OpenAEVScenarioID: "sc-filter-2", Name: "Exc", SourceType: "exercise"}, openaev.Detail{}, "h2", 10, 1)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListOpenAEVScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/scenarios", nil))

		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		for _, sc := range out {
			if sc["OpenAEVScenarioID"] == "sc-filter-2" {
				t.Error("default (no ?type=) must not include an exercise-sourced row")
			}
		}
	})
}

func TestListOpenAEVScenarios_TypeExercise_FiltersToExercises(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := openaev.NewSQLStore(pool)
		store.Upsert(context.Background(), openaev.Scenario{OpenAEVScenarioID: "sc-filter-3", Name: "Scn", SourceType: "scenario"}, openaev.Detail{}, "h3", 10, 1)
		store.Upsert(context.Background(), openaev.Scenario{OpenAEVScenarioID: "sc-filter-4", Name: "Exc", SourceType: "exercise"}, openaev.Detail{}, "h4", 10, 1)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListOpenAEVScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/openaev/scenarios?type=exercise", nil))

		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		found := false
		for _, sc := range out {
			if sc["OpenAEVScenarioID"] == "sc-filter-4" {
				found = true
			}
			if sc["OpenAEVScenarioID"] == "sc-filter-3" {
				t.Error("?type=exercise must not include a scenario-sourced row")
			}
		}
		if !found {
			t.Error("?type=exercise must include the exercise-sourced row")
		}
	})
}

func TestImportOpenAEVBundle_ParsesAndStores(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("file", "scenario.zip")
		fw.Write(fixtureBundleForHandlerTest(t))
		mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/api/openaev/import", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		h.ImportOpenAEVBundle(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var scenarioCount int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM openaev_scenarios`).Scan(&scenarioCount)
		if scenarioCount != 1 {
			t.Errorf("openaev_scenarios rows = %d, want 1", scenarioCount)
		}
	})
}
