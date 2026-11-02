package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Measurement validity per daily point: legacy rows (written before validity was tracked) report null, so a
// consumer can tell them apart from a measured point (true) and from "nothing was measurable that day" (false).
func TestGetDashboardTrends_ReportsMeasurementValidityPerPoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// Legacy row: no validity columns written.
		mustExecAPI(t, pool, `
			INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count)
			VALUES (CURRENT_DATE - INTERVAL '3 days', 40, 100, 100, 4)`)
		// Day with nothing measurable: placeholders stored, flagged false.
		mustExecAPI(t, pool, `
			INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count,
				exposure_measurable, detection_measurable, exposure_measured_assets, risk_measurable)
			VALUES (CURRENT_DATE - INTERVAL '2 days', 41, 0, 100, 4, false, false, 0, false)`)
		// Measured day, including a genuine zero detection coverage.
		mustExecAPI(t, pool, `
			INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count,
				exposure_measurable, detection_measurable, exposure_measured_assets, risk_measurable)
			VALUES (CURRENT_DATE - INTERVAL '1 days', 42, 70, 0, 4, true, true, 3, true)`)

		h := dashboardHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetDashboardTrends(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/trends?days=30", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var pts []struct {
			DetectionCoverage      int   `json:"detectionCoverage"`
			ExposureMeasurable     *bool `json:"exposureMeasurable"`
			DetectionMeasurable    *bool `json:"detectionMeasurable"`
			ExposureMeasuredAssets *int  `json:"exposureMeasuredAssets"`
			RiskMeasurable         *bool `json:"riskMeasurable"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &pts); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(pts) != 3 {
			t.Fatalf("points = %d, want 3", len(pts))
		}
		if pts[0].RiskMeasurable != nil || pts[1].RiskMeasurable == nil || *pts[1].RiskMeasurable || pts[2].RiskMeasurable == nil || !*pts[2].RiskMeasurable {
			t.Errorf("risk validity must be null/false/true for legacy/unmeasured/measured, got %v %v %v", pts[0].RiskMeasurable, pts[1].RiskMeasurable, pts[2].RiskMeasurable)
		}
		if pts[0].ExposureMeasurable != nil || pts[0].DetectionMeasurable != nil || pts[0].ExposureMeasuredAssets != nil {
			t.Errorf("legacy row must report null validity, got %+v", pts[0])
		}
		if pts[1].ExposureMeasurable == nil || *pts[1].ExposureMeasurable || pts[1].DetectionMeasurable == nil || *pts[1].DetectionMeasurable {
			t.Errorf("unmeasurable day must report false, got %+v", pts[1])
		}
		if pts[2].ExposureMeasurable == nil || !*pts[2].ExposureMeasurable || pts[2].DetectionMeasurable == nil || !*pts[2].DetectionMeasurable {
			t.Errorf("measured day must report true, got %+v", pts[2])
		}
		if pts[2].DetectionCoverage != 0 || pts[2].ExposureMeasuredAssets == nil || *pts[2].ExposureMeasuredAssets != 3 {
			t.Errorf("a genuine 0 stays 0 and carries its asset count, got %+v", pts[2])
		}
	})
}

// The daily scheduler records validity on every row it writes, and upgrades a legacy same-day row.
func TestSnapshotAndPrune_RecordsMeasurementValidity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// A legacy row for today (validity NULL) must be overwritten with a validity-stamped one.
		mustExecAPI(t, pool, `
			INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count)
			VALUES (CURRENT_DATE, 0, 100, 100, 0)`)

		snapshotAndPrune(ctx, pool)

		var expM, detM *bool
		var measured *int
		var n int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM dashboard_snapshots WHERE snapshot_date = CURRENT_DATE`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("today rows = %d (err %v), want exactly 1 (upsert, not a second row)", n, err)
		}
		if err := pool.QueryRow(ctx, `
			SELECT exposure_measurable, detection_measurable, exposure_measured_assets
			FROM dashboard_snapshots WHERE snapshot_date = CURRENT_DATE`).Scan(&expM, &detM, &measured); err != nil {
			t.Fatalf("select: %v", err)
		}
		if expM == nil || detM == nil || measured == nil {
			t.Fatalf("validity must be recorded, got exposure=%v detection=%v measured=%v", expM, detM, measured)
		}
		// An empty fleet has nothing to measure: recorded as not measurable, never as a trusted 100.
		var riskM *bool
		if err := pool.QueryRow(ctx, `SELECT risk_measurable FROM dashboard_snapshots WHERE snapshot_date = CURRENT_DATE`).Scan(&riskM); err != nil || riskM == nil || *riskM {
			t.Errorf("empty fleet must record risk_measurable=false (err %v, got %v)", err, riskM)
		}
		if *expM || *detM || *measured != 0 {
			t.Errorf("empty fleet recorded exposure=%v detection=%v measured=%d, want false/false/0", *expM, *detM, *measured)
		}
	})
}
