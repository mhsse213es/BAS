package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The source guard on both UpdateScenario and DeleteScenario is a single
// `if source != "custom"` branch. intel is the sole non-custom vehicle used
// here — constructing a genuinely-signed builtin fixture would require the
// offline release-signing private key, which is not available to tests or
// CI (see the spec's "Note" under the DeleteScenario matrix).

func TestUpdateScenario_SourceGuardRejectsIntel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedIntelScenario(t, dir, e, minimalScenario("intel-guard-sc"))
		filePath := filepath.Join(dir, "intel", "intel-guard-sc.yaml")
		before := readScenarioFile(t, filePath)

		h := New(pool, ws.NewHub(), e, "")
		updated := minimalScenario("intel-guard-sc")
		updated.Name = "Should Never Persist"
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/api/scenarios/intel-guard-sc", scenarioJSON(t, updated)), "id", "intel-guard-sc")
		rec := httptest.NewRecorder()
		h.UpdateScenario(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}

		after := readScenarioFile(t, filePath)
		if string(before) != string(after) {
			t.Fatalf("intel file mutated despite source guard:\nbefore:\n%s\nafter:\n%s", before, after)
		}
		got, ok := e.Get("intel-guard-sc")
		if !ok || got.Name == "Should Never Persist" {
			t.Fatalf("in-memory scenario mutated despite source guard: %+v", got)
		}
	})
}

func TestDeleteScenario_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, e := newFileEngine(t)
		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/scenarios/missing-sc", nil), "id", "missing-sc")
		rec := httptest.NewRecorder()
		h.DeleteScenario(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestDeleteScenario_SourceGuardRejectsIntel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedIntelScenario(t, dir, e, minimalScenario("intel-delete-guard-sc"))
		filePath := filepath.Join(dir, "intel", "intel-delete-guard-sc.yaml")
		before := readScenarioFile(t, filePath)

		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/scenarios/intel-delete-guard-sc", nil), "id", "intel-delete-guard-sc")
		rec := httptest.NewRecorder()
		h.DeleteScenario(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}

		after := readScenarioFile(t, filePath)
		if string(before) != string(after) {
			t.Fatalf("intel file removed/mutated despite source guard")
		}
		if _, ok := e.Get("intel-delete-guard-sc"); !ok {
			t.Fatalf("scenario removed from memory despite source guard")
		}
	})
}

func TestDeleteScenario_ValidDeleteOfCustom(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir, e := newFileEngine(t)
		seedCustomScenario(t, e, minimalScenario("delete-me-sc"))
		filePath := filepath.Join(dir, "custom", "delete-me-sc.yaml")
		if _, err := os.Stat(filePath); err != nil {
			t.Fatalf("fixture file missing before delete: %v", err)
		}

		h := New(pool, ws.NewHub(), e, "")
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/scenarios/delete-me-sc", nil), "id", "delete-me-sc")
		rec := httptest.NewRecorder()
		h.DeleteScenario(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
		}

		if _, ok := e.Get("delete-me-sc"); ok {
			t.Fatalf("scenario still present in memory after delete")
		}
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Fatalf("file still present on disk after delete: err = %v", err)
		}

		listReq := httptest.NewRequest(http.MethodGet, "/api/scenarios", nil)
		listRec := httptest.NewRecorder()
		h.ListScenarios(listRec, listReq)
		var out []*scenario.Scenario
		if err := json.Unmarshal(listRec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		for _, sc := range out {
			if sc.ID == "delete-me-sc" {
				t.Fatalf("deleted scenario still present in list")
			}
		}
	})
}
