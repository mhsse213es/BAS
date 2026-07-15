package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetExposureAssets_NoData_ReturnsEmptyList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetExposureAssets(rec, httptest.NewRequest(http.MethodGet, "/api/exposure/assets", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("expected empty asset list with no agents/collections, got %d", len(out))
		}
	})
}

func TestGetExposureAsset_ManagedAgent_Returns200WithManagedTrue(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			 VALUES ('exp-h-agent', 'EXPHOST01', '10.0.0.5', 'Windows 11', 'idle', 'active', NOW())`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/exposure/assets/EXPHOST01", nil), "hostKey", "EXPHOST01")
		h.GetExposureAsset(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		asset, _ := out["asset"].(map[string]any)
		if asset["managed"] != true {
			t.Fatalf("expected asset.managed=true, got %v", out["asset"])
		}
	})
}

func TestGetExposureAsset_UnknownHost_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/exposure/assets/NOPE", nil), "hostKey", "NOPE")
		h.GetExposureAsset(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
