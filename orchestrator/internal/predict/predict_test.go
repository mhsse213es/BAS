package predict

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// seedFinding inserts one finding whose first_seen is daysAgo days in the past.
func seedFinding(t *testing.T, pool *pgxpool.Pool, id, tech, name, sev, status string, daysAgo, reopened int) {
	t.Helper()
	mustExec(t, pool, `
		INSERT INTO findings (id, agent_id, technique_id, control_class, technique_name,
			tactic, severity, status, reopened_count, first_seen, last_seen)
		VALUES ($1, 'pa-01', $2, 'prevention', $3, 'execution', $4, $5, $6,
			NOW() - make_interval(days => $7), NOW())`,
		id, tech, name, sev, status, reopened, daysAgo)
}

func TestBuild_EmptyFleet_NoError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		p, err := Build(context.Background(), pool)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if p.Forecast.Direction != "unknown" {
			t.Errorf("Forecast.Direction = %q, want unknown on 0 snapshots", p.Forecast.Direction)
		}
		if p.Forecast.HasForecast {
			t.Error("HasForecast = true on empty fleet, want false")
		}
		if p.Exposure.HasData {
			t.Error("Exposure.HasData = true on empty fleet, want false")
		}
		if p.Exposure.Worst == nil {
			t.Error("Exposure.Worst must be an empty slice, not nil — the UI iterates it")
		}
	})
}

func TestBuild_ExposureWindows_MeasuresDaysOpen(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedFinding(t, pool, "f-old", "T1059.001", "PowerShell", "High", "open", 90, 2)
		seedFinding(t, pool, "f-mid", "T1078", "Valid Accounts", "Critical", "open", 40, 0)
		seedFinding(t, pool, "f-new", "T1053", "Scheduled Task", "Medium", "open", 5, 0)
		seedFinding(t, pool, "f-done", "T1021", "Remote Services", "High", "resolved", 200, 0)

		p, err := Build(context.Background(), pool)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		exp := p.Exposure
		if !exp.HasData {
			t.Fatal("HasData = false, want true with open findings")
		}
		if exp.OpenCount != 3 {
			t.Errorf("OpenCount = %d, want 3 (resolved excluded)", exp.OpenCount)
		}
		if exp.WorstDaysOpen < 89 || exp.WorstDaysOpen > 91 {
			t.Errorf("WorstDaysOpen = %d, want ~90", exp.WorstDaysOpen)
		}
		if exp.MedianDaysOpen < 39 || exp.MedianDaysOpen > 41 {
			t.Errorf("MedianDaysOpen = %d, want ~40 (median of 3)", exp.MedianDaysOpen)
		}
		if exp.OverThreshold != 2 {
			t.Errorf("OverThreshold = %d, want 2 (>30d: the 90d and 40d)", exp.OverThreshold)
		}
		if len(exp.Worst) == 0 || exp.Worst[0].TechniqueID != "T1059.001" {
			t.Errorf("Worst[0] = %+v, want the 90-day T1059.001 first", exp.Worst)
		}
		if exp.Worst[0].ReopenedCount != 2 {
			t.Errorf("Worst[0].ReopenedCount = %d, want 2", exp.Worst[0].ReopenedCount)
		}
	})
}

func TestBuild_ExposureMedian_EvenCount(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedFinding(t, pool, "e1", "T1", "a", "Low", "open", 10, 0)
		seedFinding(t, pool, "e2", "T2", "b", "Low", "open", 20, 0)
		seedFinding(t, pool, "e3", "T3", "c", "Low", "open", 30, 0)
		seedFinding(t, pool, "e4", "T4", "d", "Low", "open", 40, 0)
		p, err := Build(context.Background(), pool)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		// even count: mean of the two middle (20,30) = 25.
		if p.Exposure.MedianDaysOpen < 24 || p.Exposure.MedianDaysOpen > 26 {
			t.Errorf("MedianDaysOpen = %d, want ~25 (mean of middle two)", p.Exposure.MedianDaysOpen)
		}
	})
}

func TestBuild_Forecast_FromSnapshots(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// 14 consecutive daily snapshots, rising risk score.
		for i := 0; i < 14; i++ {
			mustExec(t, pool, `
				INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage)
				VALUES (CURRENT_DATE - $1::int, $2, 0, 0)`, 13-i, 40+i)
		}
		p, err := Build(context.Background(), pool)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if !p.Forecast.HasForecast {
			t.Error("HasForecast = false with 14 snapshots, want true")
		}
		if p.Forecast.Direction != "worsening" {
			t.Errorf("Direction = %q, want worsening on a rising series", p.Forecast.Direction)
		}
		if p.Forecast.SampleDays != 14 {
			t.Errorf("SampleDays = %d, want 14", p.Forecast.SampleDays)
		}
	})
}
