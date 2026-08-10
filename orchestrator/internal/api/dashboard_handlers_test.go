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

func dashboardHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func TestGetDashboardCurrent_EmptyFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := dashboardHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetDashboardCurrent(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/current", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var snap struct {
			AvgRiskScore      int  `json:"avgRiskScore"`
			ExposureScore     int  `json:"exposureScore"`
			DetectionCoverage int  `json:"detectionCoverage"`
			AssetCount        int  `json:"assetCount"`
			HasAttackPathData bool `json:"hasAttackPathData"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if snap.AssetCount != 0 || snap.AvgRiskScore != 0 {
			t.Errorf("snap = %+v, want AssetCount=0 and AvgRiskScore=0 on an empty fleet", snap)
		}
		if snap.HasAttackPathData {
			t.Errorf("snap.HasAttackPathData = true on an empty fleet with zero attackpath_collections, want false")
		}
	})
}

func TestGetDashboardTrends_EmptyHistoryReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := dashboardHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetDashboardTrends(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/trends", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if body != "[]\n" && body != "[]" {
			t.Errorf("body = %q, want an empty JSON array, not null or an error", body)
		}
	})
}

func TestGetDashboardTrends_DayRangeFilteringAndClamping(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `
			INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count)
			VALUES
				(CURRENT_DATE, 50, 60, 70, 5),
				(CURRENT_DATE - INTERVAL '10 days', 40, 55, 65, 4),
				(CURRENT_DATE - INTERVAL '400 days', 10, 10, 10, 1)`)

		h := dashboardHandler(t, pool)

		// days=30 should include today and the 10-day-old row, exclude the 400-day-old one.
		rec := httptest.NewRecorder()
		h.GetDashboardTrends(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/trends?days=30", nil))
		var rows []struct {
			AvgRiskScore int `json:"avgRiskScore"`
		}
		json.Unmarshal(rec.Body.Bytes(), &rows)
		if len(rows) != 2 {
			t.Fatalf("days=30: got %d rows, want 2", len(rows))
		}

		// days=99999 clamps to 365 — still excludes the 400-day-old row.
		rec2 := httptest.NewRecorder()
		h.GetDashboardTrends(rec2, httptest.NewRequest(http.MethodGet, "/api/dashboard/trends?days=99999", nil))
		var rows2 []struct {
			AvgRiskScore int `json:"avgRiskScore"`
		}
		json.Unmarshal(rec2.Body.Bytes(), &rows2)
		if len(rows2) != 2 {
			t.Fatalf("days=99999 (clamped to 365): got %d rows, want 2 (400-day-old row still excluded)", len(rows2))
		}
	})
}

func mustExecAPI(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func mustExecAPIReturning(t *testing.T, pool *pgxpool.Pool, dest *string, sql string, args ...any) {
	t.Helper()
	if err := pool.QueryRow(t.Context(), sql, args...).Scan(dest); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
}
