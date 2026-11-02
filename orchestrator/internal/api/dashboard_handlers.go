package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/dashboard"
)

// GetDashboardCurrent returns today's fleet-wide posture, computed live
// (not read from dashboard_snapshots) so it never waits for the next
// scheduled tick. Read-only (Viewer+).
// GET /api/dashboard/current
func (h *Handler) GetDashboardCurrent(w http.ResponseWriter, r *http.Request) {
	snap, err := dashboard.Compute(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, snap)
}

// DashboardTrendPoint is one day's stored snapshot.
type DashboardTrendPoint struct {
	Date              string `json:"date"`
	AvgRiskScore      int    `json:"avgRiskScore"`
	ExposureScore     int    `json:"exposureScore"`
	DetectionCoverage int    `json:"detectionCoverage"`
	AssetCount        int    `json:"assetCount"`
	// Measurement validity of this day's point. nil (JSON null) marks a legacy row recorded before validity was
	// tracked: its exposure and detection figures cannot be trusted and must not be trended. false means nothing
	// was measurable that day. true means the figure was measured.
	ExposureMeasurable     *bool `json:"exposureMeasurable"`
	DetectionMeasurable    *bool `json:"detectionMeasurable"`
	ExposureMeasuredAssets *int  `json:"exposureMeasuredAssets"`
	// RiskMeasurable: false = no scored run that day (AvgRiskScore is a bare 0); null = legacy row.
	RiskMeasurable *bool `json:"riskMeasurable"`
}

// GetDashboardTrends returns stored daily snapshots for the requested range.
// Query params: days (default 90, clamped to [1, 365]). Read-only (Viewer+).
// GET /api/dashboard/trends?days=90
func (h *Handler) GetDashboardTrends(w http.ResponseWriter, r *http.Request) {
	days := 90
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 365 {
			days = n
		}
	}
	rows, err := h.db.Query(r.Context(), `
		SELECT snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count,
		       exposure_measurable, detection_measurable, exposure_measured_assets, risk_measurable
		FROM dashboard_snapshots
		WHERE snapshot_date >= CURRENT_DATE - $1::int
		ORDER BY snapshot_date ASC`, days)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []DashboardTrendPoint{}
	for rows.Next() {
		var p DashboardTrendPoint
		var d time.Time
		if rows.Scan(&d, &p.AvgRiskScore, &p.ExposureScore, &p.DetectionCoverage, &p.AssetCount,
			&p.ExposureMeasurable, &p.DetectionMeasurable, &p.ExposureMeasuredAssets, &p.RiskMeasurable) != nil {
			continue
		}
		p.Date = d.Format("2006-01-02")
		out = append(out, p)
	}
	respond(w, out)
}
