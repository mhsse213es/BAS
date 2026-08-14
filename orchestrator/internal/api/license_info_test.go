package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetLicenseInfo_ReturnsRealStateAndGraceFields(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		licPath := filepath.Join(t.TempDir(), "bas.lic")
		data, _ := json.Marshal(license.License{
			Customer:   "Acme Corp",
			CustomerID: "acme-1",
			IssuedAt:   "2026-01-01",
			ExpiresAt:  "2026-08-14",
		})
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithLicensePath(licPath)

		license.SetInitial(license.Info{
			State:         license.StateGrace,
			DaysRemaining: 3,
			LockoutAt:     time.Date(2026, 8, 19, 23, 59, 59, 0, time.UTC),
		})
		defer license.SetInitial(license.Info{})

		req := httptest.NewRequest(http.MethodGet, "/api/license", nil)
		rec := httptest.NewRecorder()
		h.GetLicenseInfo(rec, req)

		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if body["status"] != "grace" {
			t.Errorf("status = %v, want %q", body["status"], "grace")
		}
		if body["daysRemaining"] != float64(3) {
			t.Errorf("daysRemaining = %v, want 3", body["daysRemaining"])
		}
		if body["lockoutAt"] == nil {
			t.Error("lockoutAt missing from response")
		}
	})
}
