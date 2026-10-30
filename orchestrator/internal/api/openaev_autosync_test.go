package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setOpenAEVConfig writes the singleton config row the sync reads.
func setOpenAEVConfig(t *testing.T, pool *pgxpool.Pool, baseURL string, enabled bool, hours int, lastSync *time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO openaev_config (id, base_url, bearer_token, enabled, poll_interval_hours, last_sync_at)
		VALUES (1, $1, 'token', $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET base_url = EXCLUDED.base_url, bearer_token = EXCLUDED.bearer_token,
		  enabled = EXCLUDED.enabled, poll_interval_hours = EXCLUDED.poll_interval_hours, last_sync_at = EXCLUDED.last_sync_at`,
		baseURL, enabled, hours, lastSync); err != nil {
		t.Fatalf("set openaev config: %v", err)
	}
}

func TestOpenAEVSyncDue_RespectsConfiguredInterval(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		hoursAgo := func(h float64) *time.Time { v := time.Now().Add(-time.Duration(h * float64(time.Hour))); return &v }
		cases := []struct {
			name    string
			enabled bool
			hours   int
			last    *time.Time
			want    bool
		}{
			{"disabled is never due", false, 24, nil, false},
			{"enabled and never synced is due", true, 24, nil, true},
			{"synced 1h ago, 24h interval, not due", true, 24, hoursAgo(1), false},
			{"synced 25h ago, 24h interval, due", true, 24, hoursAgo(25), true},
			{"synced 2h ago, 1h interval, due", true, 1, hoursAgo(2), true},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				setOpenAEVConfig(t, pool, "http://127.0.0.1:1", c.enabled, c.hours, c.last)
				got, err := openAEVSyncDue(ctx, pool)
				if err != nil {
					t.Fatalf("openAEVSyncDue: %v", err)
				}
				if got != c.want {
					t.Errorf("due = %v, want %v", got, c.want)
				}
			})
		}
	})
}

// A failing automatic sync is recorded on the config row, so the status page shows it.
// Nothing is swallowed.
func TestRunOpenAEVSync_FailureRecordedOnConfig(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		setOpenAEVConfig(t, pool, "http://127.0.0.1:1", true, 24, nil)
		_, err := runOpenAEVSync(ctx, pool)
		if err == nil {
			t.Fatalf("a sync to an unreachable server reported success")
		}
		var status, lastErr string
		if err := pool.QueryRow(ctx,
			`SELECT last_sync_status, last_error FROM openaev_config WHERE id = 1`).Scan(&status, &lastErr); err != nil {
			t.Fatalf("read status: %v", err)
		}
		if status != "error" || lastErr == "" {
			t.Errorf("config row says status=%q lastError=%q, want error with a message", status, lastErr)
		}
	})
}
