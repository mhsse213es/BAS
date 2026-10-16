package db_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwrun"
)

func TestEmailGWMetricsSnapshotSchema_Idempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if err := db.EnsureEmailGWMetricsSnapshotSchema(ctx, pool); err != nil {
				t.Fatalf("ensure #%d: %v", i+1, err)
			}
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name='email_gw_metrics_snapshots'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("email_gw_metrics_snapshots table missing (n=%d err=%v)", n, err)
		}
	})
}

func TestEmailGWMetricsSnapshotSchema_EnvironmentCheckConstraint(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		cases := []struct {
			environment string
			legal       bool
		}{
			{"lab", true},
			{"customer", true},
			{"bogus", false},
		}
		for i, c := range cases {
			date := time.Now().UTC().AddDate(0, 0, -i)
			_, err := pool.Exec(ctx, `INSERT INTO email_gw_metrics_snapshots (snapshot_date, environment, metric_definition_version, metrics) VALUES ($1, $2, 1, '{}')`, date, c.environment)
			if got := err == nil; got != c.legal {
				t.Errorf("environment=%q: accepted=%v want %v (err=%v)", c.environment, got, c.legal, err)
			}
		}
	})
}

func TestUpsertEmailGWMetricsSnapshot_SameDateAndEnvironment_UpdatesInPlace(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		date := time.Now().UTC()

		if err := db.UpsertEmailGWMetricsSnapshot(ctx, pool, date, emailgwrun.EnvironmentLab, 1, true, json.RawMessage(`{"runsConsidered":1}`)); err != nil {
			t.Fatalf("first upsert: %v", err)
		}
		if err := db.UpsertEmailGWMetricsSnapshot(ctx, pool, date, emailgwrun.EnvironmentLab, 1, true, json.RawMessage(`{"runsConsidered":5}`)); err != nil {
			t.Fatalf("second upsert: %v", err)
		}

		rows, err := db.ListEmailGWMetricsSnapshots(ctx, pool, emailgwrun.EnvironmentLab, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("got %d rows, want exactly 1 (the upsert must update in place, not duplicate)", len(rows))
		}
		var decoded struct {
			RunsConsidered int `json:"runsConsidered"`
		}
		if err := json.Unmarshal(rows[0].Metrics, &decoded); err != nil {
			t.Fatalf("decode metrics: %v", err)
		}
		if decoded.RunsConsidered != 5 {
			t.Errorf("metrics.runsConsidered = %d, want 5 (the second upsert's value)", decoded.RunsConsidered)
		}
	})
}

func TestListEmailGWMetricsSnapshots_FiltersByEnvironment_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		older := time.Now().UTC().AddDate(0, 0, -2)
		newer := time.Now().UTC().AddDate(0, 0, -1)

		for _, d := range []time.Time{older, newer} {
			if err := db.UpsertEmailGWMetricsSnapshot(ctx, pool, d, emailgwrun.EnvironmentLab, 1, true, json.RawMessage(`{}`)); err != nil {
				t.Fatalf("upsert lab %v: %v", d, err)
			}
		}
		if err := db.UpsertEmailGWMetricsSnapshot(ctx, pool, newer, emailgwrun.EnvironmentCustomer, 1, false, json.RawMessage(`{}`)); err != nil {
			t.Fatalf("upsert customer: %v", err)
		}

		lab, err := db.ListEmailGWMetricsSnapshots(ctx, pool, emailgwrun.EnvironmentLab, 10)
		if err != nil {
			t.Fatalf("list lab: %v", err)
		}
		if len(lab) != 2 {
			t.Fatalf("lab rows = %d, want 2", len(lab))
		}
		if !lab[0].SnapshotDate.After(lab[1].SnapshotDate) {
			t.Errorf("lab rows not newest-first: %v then %v", lab[0].SnapshotDate, lab[1].SnapshotDate)
		}

		customer, err := db.ListEmailGWMetricsSnapshots(ctx, pool, emailgwrun.EnvironmentCustomer, 10)
		if err != nil {
			t.Fatalf("list customer: %v", err)
		}
		if len(customer) != 1 {
			t.Fatalf("customer rows = %d, want 1 (lab rows must never leak into a customer listing)", len(customer))
		}
		if customer[0].HasData {
			t.Errorf("customer row HasData = true, want false (as upserted)")
		}
	})
}

func TestPruneEmailGWMetricsSnapshotsOlderThan_OnlyDeletesOldRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		old := time.Now().UTC().AddDate(-2, 0, 0)
		recent := time.Now().UTC()

		if err := db.UpsertEmailGWMetricsSnapshot(ctx, pool, old, emailgwrun.EnvironmentLab, 1, true, json.RawMessage(`{}`)); err != nil {
			t.Fatalf("upsert old: %v", err)
		}
		if err := db.UpsertEmailGWMetricsSnapshot(ctx, pool, recent, emailgwrun.EnvironmentLab, 1, true, json.RawMessage(`{}`)); err != nil {
			t.Fatalf("upsert recent: %v", err)
		}

		cutoff := time.Now().UTC().AddDate(-1, 0, 0)
		n, err := db.PruneEmailGWMetricsSnapshotsOlderThan(ctx, pool, cutoff)
		if err != nil {
			t.Fatalf("prune: %v", err)
		}
		if n != 1 {
			t.Fatalf("pruned %d rows, want exactly 1 (the old one)", n)
		}

		rows, err := db.ListEmailGWMetricsSnapshots(ctx, pool, emailgwrun.EnvironmentLab, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rows) != 1 || !rows[0].SnapshotDate.Equal(recent.Truncate(24*time.Hour)) {
			t.Errorf("remaining rows = %+v, want exactly the recent one", rows)
		}
	})
}
