package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedIOCAnalytics(t *testing.T, pool *pgxpool.Pool, iocType, value string, sightingCount int, verdict, status string, firstSeenExpr string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO iocs (type, value, source, status, sighting_count, first_seen)
		VALUES ($1, $2, 'detection_alert', $3, $4, `+firstSeenExpr+`)
		RETURNING id`, iocType, value, status, sightingCount).Scan(&id); err != nil {
		t.Fatalf("seed ioc %s: %v", value, err)
	}
	if verdict != "" {
		mustExec(t, pool, `INSERT INTO ioc_sightings (ioc_id, detection_verdict) VALUES ($1, $2)`, id, verdict)
	}
	return id
}

func TestIOCAnalytics_MostDetected_OrdersBySightingCountAmongDetectedVerdicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCAnalytics(t, pool, "command_line", "cmd-high-detected", 9, "detected", "detected", "NOW()")
		seedIOCAnalytics(t, pool, "command_line", "cmd-low-detected", 2, "detected", "detected", "NOW()")
		seedIOCAnalytics(t, pool, "command_line", "cmd-undetected", 20, "undetected", "missed", "NOW()")

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		if len(got.MostDetected) != 2 {
			t.Fatalf("MostDetected = %+v, want 2 entries (undetected excluded)", got.MostDetected)
		}
		if got.MostDetected[0].Value != "cmd-high-detected" {
			t.Errorf("MostDetected[0] = %+v, want cmd-high-detected first (highest sighting_count)", got.MostDetected[0])
		}
	})
}

func TestIOCAnalytics_HighestBypassRate_OnlyUndetectedVerdicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCAnalytics(t, pool, "command_line", "cmd-bypass", 5, "undetected", "missed", "NOW()")
		seedIOCAnalytics(t, pool, "command_line", "cmd-detected", 5, "detected", "detected", "NOW()")

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		if len(got.HighestBypassRate) != 1 || got.HighestBypassRate[0].Value != "cmd-bypass" {
			t.Errorf("HighestBypassRate = %+v, want exactly [cmd-bypass]", got.HighestBypassRate)
		}
	})
}

func TestIOCAnalytics_FrequentlyReused_OrdersBySightingCountNoVerdictFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCAnalytics(t, pool, "process", "svchost.exe", 15, "", "observed", "NOW()")
		seedIOCAnalytics(t, pool, "process", "cmd.exe", 3, "", "observed", "NOW()")

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		if len(got.FrequentlyReused) != 2 || got.FrequentlyReused[0].Value != "svchost.exe" {
			t.Errorf("FrequentlyReused = %+v, want svchost.exe first", got.FrequentlyReused)
		}
	})
}

func TestIOCAnalytics_LongestSurviving_ExcludesArchivedAndExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOCAnalytics(t, pool, "command_line", "cmd-oldest", 1, "", "observed", "'2020-01-01T00:00:00Z'")
		seedIOCAnalytics(t, pool, "command_line", "cmd-newer", 1, "", "observed", "'2025-01-01T00:00:00Z'")
		seedIOCAnalytics(t, pool, "command_line", "cmd-archived-but-oldest", 1, "", "archived", "'2010-01-01T00:00:00Z'")

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		if len(got.LongestSurviving) != 2 {
			t.Fatalf("LongestSurviving = %+v, want 2 entries (archived excluded)", got.LongestSurviving)
		}
		if got.LongestSurviving[0].Value != "cmd-oldest" {
			t.Errorf("LongestSurviving[0] = %+v, want cmd-oldest first (earliest first_seen)", got.LongestSurviving[0])
		}
	})
}

func TestIOCAnalytics_HighestBypassRate_ExcludesSuppressedButFrequentlyReusedIncludesIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		id := seedIOCAnalytics(t, pool, "command_line", "cmd-suppressed-bypass", 7, "undetected", "missed", "NOW()")
		mustExec(t, pool, `UPDATE iocs SET suppressed = true, suppression_reason = 'known lab tool' WHERE id = $1`, id)

		got, err := IOCAnalytics(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("IOCAnalytics: %v", err)
		}
		for _, e := range got.HighestBypassRate {
			if e.Value == "cmd-suppressed-bypass" {
				t.Errorf("HighestBypassRate = %+v, want the suppressed IOC excluded", got.HighestBypassRate)
			}
		}
		found := false
		for _, e := range got.FrequentlyReused {
			if e.Value == "cmd-suppressed-bypass" {
				found = true
			}
		}
		if !found {
			t.Errorf("FrequentlyReused = %+v, want the suppressed IOC still included (only bypass-rate excludes suppressed)", got.FrequentlyReused)
		}
	})
}
