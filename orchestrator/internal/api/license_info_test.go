package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetLicenseInfo_ReturnsRealStateAndGraceFields(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		priv, pubPEM := license.GenerateTestKeypair()
		origKey := license.PublicKeyPEM
		license.PublicKeyPEM = pubPEM
		defer func() { license.PublicKeyPEM = origKey }()

		licPath := filepath.Join(t.TempDir(), "bas.lic")
		lic := license.SignForTest(priv, license.License{
			Customer:   "Acme Corp",
			CustomerID: "acme-1",
			IssuedAt:   "2026-01-01",
			ExpiresAt:  "2026-08-14",
		})
		data, _ := json.Marshal(lic)
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithLicensePath(licPath)

		license.SetInitial(license.Info{
			State:         license.StateGrace,
			DaysRemaining: 3,
			LockoutAt:     time.Date(2026, 8, 19, 23, 59, 59, 0, time.UTC),
		})
		defer license.SetInitial(license.Info{State: license.StateValid, Tier: license.TierEnterprise})

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

// TestGetLicenseInfo_TamperedFile_ReportsVerificationFailure_NeverDisplaysForgedFields
// is the Settings -> License panel side of the signature-verification
// fix: it must never show a tampered file's fields (customer, expiry,
// features) as if they were authentic, even if license.Current()'s
// cached state has not yet caught up with the tampering (e.g. the monitor
// hasn't ticked yet) -- GetLicenseInfo does its own fresh VerifiedRead on
// every call, independent of the monitor's cadence.
func TestGetLicenseInfo_TamperedFile_ReportsVerificationFailure_NeverDisplaysForgedFields(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		priv, pubPEM := license.GenerateTestKeypair()
		origKey := license.PublicKeyPEM
		license.PublicKeyPEM = pubPEM
		defer func() { license.PublicKeyPEM = origKey }()

		licPath := filepath.Join(t.TempDir(), "bas.lic")
		lic := license.SignForTest(priv, license.License{
			Customer:   "Acme Corp",
			CustomerID: "acme-1",
			IssuedAt:   "2026-01-01",
			ExpiresAt:  "2026-08-14",
		})
		data, _ := json.Marshal(lic)

		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		raw["expires_at"] = "2099-12-31" // tampered, signature untouched
		tampered, _ := json.Marshal(raw)
		if err := os.WriteFile(licPath, tampered, 0644); err != nil {
			t.Fatalf("write tampered license: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithLicensePath(licPath)

		// Deliberately stale cached state -- Valid, as if the monitor
		// has not ticked since the file was tampered with. GetLicenseInfo
		// must not rely on this being accurate.
		license.SetInitial(license.Info{State: license.StateValid})
		defer license.SetInitial(license.Info{State: license.StateValid, Tier: license.TierEnterprise})

		req := httptest.NewRequest(http.MethodGet, "/api/license", nil)
		rec := httptest.NewRecorder()
		h.GetLicenseInfo(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatalf("GetLicenseInfo returned 200 for a tampered license file, want an error status")
		}
		if !strings.Contains(rec.Body.String(), "verification failed") {
			t.Errorf("response body = %q, want it to explicitly report verification failure", rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "2099-12-31") {
			t.Error("response body echoes the tampered expires_at — a forged field must never be displayed as authentic")
		}
	})
}

// The licence endpoint reports the tier and product lines of the verified (signed) licence. A Core
// licence says Core, lists the Core lines, and does not list an Advanced one.
func TestGetLicenseInfo_ReportsSignedTier(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		priv, pubPEM := license.GenerateTestKeypair()
		origKey := license.PublicKeyPEM
		license.PublicKeyPEM = pubPEM
		defer func() { license.PublicKeyPEM = origKey }()

		licPath := filepath.Join(t.TempDir(), "bas.lic")
		lic := license.SignForTest(priv, license.License{
			Customer:   "Acme Corp",
			CustomerID: "acme-core",
			IssuedAt:   "2026-01-01",
			ExpiresAt:  "2099-01-01",
			Features:   []string{"Core"},
			Tier:       string(license.TierCore),
		})
		data, _ := json.Marshal(lic)
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithLicensePath(licPath)
		license.SetInitial(license.Info{State: license.StateValid, Tier: license.TierCore})
		defer license.SetInitial(license.Info{State: license.StateValid, Tier: license.TierEnterprise})

		rec := httptest.NewRecorder()
		h.GetLicenseInfo(rec, httptest.NewRequest(http.MethodGet, "/api/license", nil))
		var body struct {
			Tier         string   `json:"tier"`
			ProductLines []string `json:"productLines"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if body.Tier != "Core" {
			t.Fatalf("tier = %q, want Core", body.Tier)
		}
		has := map[string]bool{}
		for _, p := range body.ProductLines {
			has[p] = true
		}
		if !has["av"] || !has["common"] || has["dlp"] || has["apibas"] {
			t.Fatalf("product lines = %v: Core lines expected, Advanced lines not", body.ProductLines)
		}
	})
}

// The licence info lists licensed add-ons under the "special" category, from the verified licence.
func TestGetLicenseInfo_ListsSpecialAddons(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		priv, pubPEM := license.GenerateTestKeypair()
		origKey := license.PublicKeyPEM
		license.PublicKeyPEM = pubPEM
		defer func() { license.PublicKeyPEM = origKey }()
		licPath := filepath.Join(t.TempDir(), "bas.lic")
		lic := license.SignForTest(priv, license.License{Customer: "Acme", CustomerID: "acme-1", IssuedAt: "2026-01-01",
			ExpiresAt: "2999-01-01", Features: []string{"full", "addon:aleef"}, Tier: "Core"})
		data, _ := json.Marshal(lic)
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithLicensePath(licPath)
		rec := httptest.NewRecorder()
		h.GetLicenseInfo(rec, httptest.NewRequest(http.MethodGet, "/api/license", nil))
		var body struct {
			SpecialAddons []map[string]string `json:"specialAddons"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.SpecialAddons) != 1 || body.SpecialAddons[0]["name"] != "aleef" || body.SpecialAddons[0]["category"] != "special" {
			t.Fatalf("specialAddons = %v", body.SpecialAddons)
		}
	})
}
