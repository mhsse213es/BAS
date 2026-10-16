package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestSnapshotEmailGWMetricsAndPrune_PersistsBothEnvironmentsWithCorrectHasData(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		now := time.Now().UTC()

		result := emailgwefficacy.EfficacyResult{DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure}}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		insertTerminalRun(t, ctx, pool, "scheduler-lab-run-1", "EG-002.known-bad", emailgwrun.StatusCompleted, raw)

		snapshotEmailGWMetricsAndPrune(ctx, pool, now)

		lab, err := db.ListEmailGWMetricsSnapshots(ctx, pool, emailgwrun.EnvironmentLab, 1)
		if err != nil {
			t.Fatalf("list lab: %v", err)
		}
		if len(lab) != 1 {
			t.Fatalf("lab rows = %d, want 1", len(lab))
		}
		if !lab[0].HasData {
			t.Errorf("lab HasData = false, want true -- a real run was just inserted")
		}
		if lab[0].MetricDefinitionVersion != EmailGWMetricDefinitionVersion {
			t.Errorf("MetricDefinitionVersion = %d, want %d", lab[0].MetricDefinitionVersion, EmailGWMetricDefinitionVersion)
		}

		customer, err := db.ListEmailGWMetricsSnapshots(ctx, pool, emailgwrun.EnvironmentCustomer, 1)
		if err != nil {
			t.Fatalf("list customer: %v", err)
		}
		if len(customer) != 1 {
			t.Fatalf("customer rows = %d, want 1 (an empty-but-real snapshot must still be persisted)", len(customer))
		}
		if customer[0].HasData {
			t.Errorf("customer HasData = true, want false -- no customer runs exist")
		}
	})
}

func TestSnapshotEmailGWMetricsAndPrune_SameDayCalledTwice_UpdatesInPlace(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		now := time.Now().UTC()

		snapshotEmailGWMetricsAndPrune(ctx, pool, now)
		snapshotEmailGWMetricsAndPrune(ctx, pool, now)

		lab, err := db.ListEmailGWMetricsSnapshots(ctx, pool, emailgwrun.EnvironmentLab, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(lab) != 1 {
			t.Fatalf("lab rows = %d, want exactly 1 -- same-day restart must refresh, never duplicate", len(lab))
		}
	})
}

func TestSnapshotEmailGWMetricsAndPrune_PrunesSnapshotsOlderThanRetention(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		now := time.Now().UTC()
		longAgo := now.Add(-2 * emailGWMetricsSnapshotRetention)

		if err := db.UpsertEmailGWMetricsSnapshot(ctx, pool, longAgo, emailgwrun.EnvironmentLab, EmailGWMetricDefinitionVersion, false, json.RawMessage(`{}`)); err != nil {
			t.Fatalf("seed old snapshot: %v", err)
		}

		snapshotEmailGWMetricsAndPrune(ctx, pool, now)

		lab, err := db.ListEmailGWMetricsSnapshots(ctx, pool, emailgwrun.EnvironmentLab, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, row := range lab {
			if row.SnapshotDate.Before(longAgo.Add(time.Hour)) {
				t.Errorf("found a snapshot from %v, want it pruned (older than retention)", row.SnapshotDate)
			}
		}
	})
}

func TestGetEmailGWMetricsHistory_DefaultsToLabAndReturnsPersistedRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		now := time.Now().UTC()
		snapshotEmailGWMetricsAndPrune(ctx, pool, now)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/emailgw/metrics/history", nil, auth.RoleAnalyst, "any-authenticated-user")
		rec := callAuthed(h.GetEmailGWMetricsHistory, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var rows []*db.EmailGWMetricsSnapshotRow
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(rows) < 1 {
			t.Fatalf("got %d rows, want at least 1", len(rows))
		}
		if rows[0].Environment != emailgwrun.EnvironmentLab {
			t.Errorf("Environment = %q, want %q (the default)", rows[0].Environment, emailgwrun.EnvironmentLab)
		}
	})
}
