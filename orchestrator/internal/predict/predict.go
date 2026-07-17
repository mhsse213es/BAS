package predict

import (
	"context"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// exposureThresholdDays is the age past which an open finding counts as
	// overdue. Fixed for this slice (not yet configurable).
	exposureThresholdDays = 30
	// exposureWorstN is how many of the oldest open findings we surface.
	exposureWorstN = 10
)

// Prediction bundles the trend forecast and the measured exposure windows.
type Prediction struct {
	Forecast Forecast        `json:"forecast"`
	Exposure ExposureWindows `json:"exposure"`
}

// ExposureWindows is a measured (not modeled) view of open-finding staleness.
type ExposureWindows struct {
	OpenCount      int            `json:"openCount"`
	WorstDaysOpen  int            `json:"worstDaysOpen"`
	MedianDaysOpen int            `json:"medianDaysOpen"`
	OverThreshold  int            `json:"overThreshold"`
	ThresholdDays  int            `json:"thresholdDays"`
	Worst          []ExposureItem `json:"worst"`
	HasData        bool           `json:"hasData"`
}

type ExposureItem struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	Severity      string `json:"severity"`
	DaysOpen      int    `json:"daysOpen"`
	FirstSeen     string `json:"firstSeen"`
	ReopenedCount int    `json:"reopenedCount"`
}

// Build composes a trend forecast (from dashboard_snapshots) and exposure
// windows (from open findings). Nil-safe: an empty/young fleet returns a
// Prediction whose sub-structs report their own insufficiency, never an error.
func Build(ctx context.Context, pool *pgxpool.Pool) (Prediction, error) {
	fc, err := buildForecast(ctx, pool)
	if err != nil {
		return Prediction{}, err
	}
	exp, err := buildExposure(ctx, pool)
	if err != nil {
		return Prediction{}, err
	}
	return Prediction{Forecast: fc, Exposure: exp}, nil
}

func buildForecast(ctx context.Context, pool *pgxpool.Pool) (Forecast, error) {
	rows, err := pool.Query(ctx, `
		SELECT to_char(snapshot_date, 'YYYY-MM-DD'), avg_risk_score
		FROM dashboard_snapshots
		ORDER BY snapshot_date ASC`)
	if err != nil {
		return Forecast{}, err
	}
	defer rows.Close()
	var dates []string
	var scores []float64
	for rows.Next() {
		var d string
		var v int
		if rows.Scan(&d, &v) != nil {
			continue
		}
		dates = append(dates, d)
		scores = append(scores, float64(v))
	}
	if err := rows.Err(); err != nil {
		return Forecast{}, err
	}
	return forecastSeries("avg_risk_score", dates, scores, forecastHorizon), nil
}

func buildExposure(ctx context.Context, pool *pgxpool.Pool) (ExposureWindows, error) {
	exp := ExposureWindows{ThresholdDays: exposureThresholdDays, Worst: []ExposureItem{}}
	rows, err := pool.Query(ctx, `
		SELECT technique_id, technique_name, severity, reopened_count,
		       to_char(first_seen, 'YYYY-MM-DD'),
		       FLOOR(EXTRACT(EPOCH FROM (NOW() - first_seen)) / 86400)::int
		FROM findings
		WHERE status = 'open'
		ORDER BY first_seen ASC`)
	if err != nil {
		return exp, err
	}
	defer rows.Close()

	var days []int
	for rows.Next() {
		var it ExposureItem
		if rows.Scan(&it.TechniqueID, &it.TechniqueName, &it.Severity,
			&it.ReopenedCount, &it.FirstSeen, &it.DaysOpen) != nil {
			continue
		}
		days = append(days, it.DaysOpen)
		if it.DaysOpen > exposureThresholdDays {
			exp.OverThreshold++
		}
		if len(exp.Worst) < exposureWorstN {
			exp.Worst = append(exp.Worst, it)
		}
	}
	if err := rows.Err(); err != nil {
		return exp, err
	}

	exp.OpenCount = len(days)
	if exp.OpenCount == 0 {
		return exp, nil
	}
	exp.HasData = true
	// first_seen ASC => oldest first => days[0] is the worst.
	exp.WorstDaysOpen = days[0]
	exp.MedianDaysOpen = medianInt(days)
	return exp, nil
}

// medianInt returns the floored median of the values. Copies before sorting so
// the caller's ordering (oldest-first) is preserved.
func medianInt(vals []int) int {
	s := make([]int, len(vals))
	copy(s, vals)
	sort.Ints(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
