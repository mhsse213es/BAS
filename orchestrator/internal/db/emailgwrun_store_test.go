package db_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwrun"
)

func TestEmailGWRunSchema_Idempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if err := db.EnsureEmailGWRunSchema(ctx, pool); err != nil {
				t.Fatalf("ensure #%d: %v", i+1, err)
			}
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name='email_gw_runs'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("email_gw_runs table missing (n=%d err=%v)", n, err)
		}
	})
}

func TestEmailGWRunSchema_StatusCheckConstraint(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		cases := []struct {
			status string
			legal  bool
		}{
			{"pending", true},
			{"running", true},
			{"completed", true},
			{"failed", true},
			{"partial", true},
			{"bogus", false},
			{"", false},
		}
		for i, c := range cases {
			id := fmt.Sprintf("status-case-%d", i)
			_, err := pool.Exec(ctx, `INSERT INTO email_gw_runs (id, scenario_id, status) VALUES ($1, 'EG-002.known-bad', $2)`, id, c.status)
			if got := err == nil; got != c.legal {
				t.Errorf("status=%q: accepted=%v want %v (err=%v)", c.status, got, c.legal, err)
			}
		}
	})
}

func TestInsertGetEmailGWRun_RoundTrips(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &emailgwrun.EmailGWRun{
			ID:           "run-roundtrip-1",
			ScenarioID:   "EG-002.known-bad",
			MessageClass: "executive-impersonation",
			Status:       emailgwrun.StatusPending,
			InitiatedBy:  "tester",
			StartedAt:    time.Now().UTC().Truncate(time.Second),
		}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.ScenarioID != run.ScenarioID || got.MessageClass != run.MessageClass || got.Status != run.Status || got.InitiatedBy != run.InitiatedBy {
			t.Errorf("got %+v, want fields matching %+v", got, run)
		}
		if got.InjectedAt != nil || got.WindowStart != nil || got.WindowEnd != nil || got.VerifiedAt != nil {
			t.Errorf("got timing fields set before injection: %+v", got)
		}
	})
}

func TestEmailGWRunSchema_EnvironmentCheckConstraint(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		cases := []struct {
			environment string
			legal       bool
		}{
			{"lab", true},
			{"customer", true},
			{"bogus", false},
			{"", false},
		}
		for i, c := range cases {
			id := fmt.Sprintf("environment-case-%d", i)
			_, err := pool.Exec(ctx, `INSERT INTO email_gw_runs (id, scenario_id, environment, status) VALUES ($1, 'EG-002.known-bad', $2, 'pending')`, id, c.environment)
			if got := err == nil; got != c.legal {
				t.Errorf("environment=%q: accepted=%v want %v (err=%v)", c.environment, got, c.legal, err)
			}
		}
	})
}

func TestInsertEmailGWRun_EnvironmentDefaultsToLabWhenUnset(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &emailgwrun.EmailGWRun{
			ID:          "run-env-default",
			ScenarioID:  "EG-002.known-bad",
			Status:      emailgwrun.StatusPending,
			InitiatedBy: "tester",
			StartedAt:   time.Now().UTC().Truncate(time.Second),
			// Environment deliberately left unset.
		}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Environment != emailgwrun.EnvironmentLab {
			t.Errorf("got environment %q, want %q (never leave this unset)", got.Environment, emailgwrun.EnvironmentLab)
		}
	})
}

func TestInsertGetEmailGWRun_EnvironmentCustomer_RoundTrips(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &emailgwrun.EmailGWRun{
			ID:          "run-env-customer",
			ScenarioID:  "EG-002.known-bad",
			Environment: emailgwrun.EnvironmentCustomer,
			Status:      emailgwrun.StatusPending,
			InitiatedBy: "tester",
			StartedAt:   time.Now().UTC().Truncate(time.Second),
		}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Environment != emailgwrun.EnvironmentCustomer {
			t.Errorf("got environment %q, want %q", got.Environment, emailgwrun.EnvironmentCustomer)
		}
	})
}

func TestGetEmailGWRun_NotFound_ReturnsPgxNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetEmailGWRun(context.Background(), pool, "no-such-run")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestUpdateEmailGWRunInjected_TransitionsToRunningAndSetsWindow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &emailgwrun.EmailGWRun{ID: "run-injected-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusPending, StartedAt: time.Now().UTC()}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		injectedAt := time.Now().UTC().Truncate(time.Second)
		windowStart := injectedAt
		windowEnd := injectedAt.Add(5 * time.Minute)
		if err := db.UpdateEmailGWRunInjected(ctx, pool, run.ID, "deadbeef", injectedAt, windowStart, windowEnd); err != nil {
			t.Fatalf("update injected: %v", err)
		}

		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != emailgwrun.StatusRunning {
			t.Errorf("Status = %q, want %q", got.Status, emailgwrun.StatusRunning)
		}
		if got.SenderPayloadHash != "deadbeef" {
			t.Errorf("SenderPayloadHash = %q, want %q", got.SenderPayloadHash, "deadbeef")
		}
		if got.InjectedAt == nil || !got.InjectedAt.Equal(injectedAt) {
			t.Errorf("InjectedAt = %v, want %v", got.InjectedAt, injectedAt)
		}
		if got.WindowEnd == nil || !got.WindowEnd.Equal(windowEnd) {
			t.Errorf("WindowEnd = %v, want %v", got.WindowEnd, windowEnd)
		}
	})
}

func TestUpdateEmailGWRunStatus_TerminalTransitionSetsCompletedAtAndVerifiedAt(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &emailgwrun.EmailGWRun{ID: "run-terminal-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusRunning, StartedAt: time.Now().UTC()}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		result, _ := json.Marshal(map[string]any{"prevention": "confirmed-failure"})
		verifiedAt := time.Now().UTC().Truncate(time.Second)
		if err := db.UpdateEmailGWRunStatus(ctx, pool, run.ID, emailgwrun.StatusCompleted, result, "", verifiedAt); err != nil {
			t.Fatalf("update status: %v", err)
		}

		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != emailgwrun.StatusCompleted {
			t.Errorf("Status = %q, want %q", got.Status, emailgwrun.StatusCompleted)
		}
		if got.CompletedAt == nil {
			t.Error("CompletedAt is nil, want set for a terminal status")
		}
		if got.VerifiedAt == nil || !got.VerifiedAt.Equal(verifiedAt) {
			t.Errorf("VerifiedAt = %v, want %v", got.VerifiedAt, verifiedAt)
		}
		if len(got.Result) == 0 {
			t.Error("Result is empty, want the marshaled EfficacyResult")
		}
	})
}

func TestUpdateEmailGWRunStatus_FailedTransition_LeavesVerifiedAtUnset(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &emailgwrun.EmailGWRun{ID: "run-failed-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusPending, StartedAt: time.Now().UTC()}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		if err := db.UpdateEmailGWRunStatus(ctx, pool, run.ID, emailgwrun.StatusFailed, nil, "smtp dial failed", time.Time{}); err != nil {
			t.Fatalf("update status: %v", err)
		}

		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != emailgwrun.StatusFailed || got.Error != "smtp dial failed" {
			t.Errorf("got status=%q error=%q, want failed/\"smtp dial failed\"", got.Status, got.Error)
		}
		if got.VerifiedAt != nil {
			t.Errorf("VerifiedAt = %v, want nil -- a failed injection was never verified", got.VerifiedAt)
		}
	})
}

func TestListEmailGWRuns_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		base := time.Now().UTC().Add(-time.Hour)
		ids := []string{"list-order-1", "list-order-2", "list-order-3"}
		for i, id := range ids {
			run := &emailgwrun.EmailGWRun{ID: id, ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusPending, StartedAt: base.Add(time.Duration(i) * time.Minute)}
			if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
				t.Fatalf("insert %s: %v", id, err)
			}
		}

		runs, err := db.ListEmailGWRuns(ctx, pool, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		positions := map[string]int{}
		for i, r := range runs {
			positions[r.ID] = i
		}
		if positions["list-order-3"] >= positions["list-order-2"] || positions["list-order-2"] >= positions["list-order-1"] {
			t.Errorf("list is not newest-first: positions = %+v", positions)
		}
	})
}

func TestListRunningEmailGWRuns_OnlyReturnsRunningStatus(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		running := &emailgwrun.EmailGWRun{ID: "recover-running-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusRunning, StartedAt: time.Now().UTC()}
		completed := &emailgwrun.EmailGWRun{ID: "recover-completed-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusCompleted, StartedAt: time.Now().UTC()}
		for _, r := range []*emailgwrun.EmailGWRun{running, completed} {
			if err := db.InsertEmailGWRun(ctx, pool, r); err != nil {
				t.Fatalf("insert %s: %v", r.ID, err)
			}
		}

		runs, err := db.ListRunningEmailGWRuns(ctx, pool)
		if err != nil {
			t.Fatalf("list running: %v", err)
		}
		found := map[string]bool{}
		for _, r := range runs {
			found[r.ID] = true
			if r.Status != emailgwrun.StatusRunning {
				t.Errorf("ListRunningEmailGWRuns returned a %q row (%s)", r.Status, r.ID)
			}
		}
		if !found[running.ID] {
			t.Errorf("ListRunningEmailGWRuns missing the running row %s", running.ID)
		}
		if found[completed.ID] {
			t.Errorf("ListRunningEmailGWRuns incorrectly returned the completed row %s", completed.ID)
		}
	})
}
