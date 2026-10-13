package db_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/db"
)

func TestCloudRunSchema_Idempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if err := db.EnsureCloudRunSchema(ctx, pool); err != nil {
				t.Fatalf("ensure #%d: %v", i+1, err)
			}
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name='cloud_runs'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("cloud_runs table missing (n=%d err=%v)", n, err)
		}
	})
}

func TestCloudRunSchema_StatusCheckConstraint(t *testing.T) {
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
			_, err := pool.Exec(ctx, `INSERT INTO cloud_runs (id, scenario_id, provider, status) VALUES ($1, 'x', 'aws', $2)`, id, c.status)
			if got := err == nil; got != c.legal {
				t.Errorf("status=%q: accepted=%v want %v (err=%v)", c.status, got, c.legal, err)
			}
		}
	})
}

func TestCloudRunSchema_ProviderCheckConstraint(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		cases := []struct {
			provider string
			legal    bool
		}{
			{"aws", true},
			{"azure", true},
			{"gcp", true},
			{"bogus", false},
			{"", false},
		}
		for i, c := range cases {
			id := fmt.Sprintf("provider-case-%d", i)
			_, err := pool.Exec(ctx, `INSERT INTO cloud_runs (id, scenario_id, provider) VALUES ($1, 'x', $2)`, id, c.provider)
			if got := err == nil; got != c.legal {
				t.Errorf("provider=%q: accepted=%v want %v (err=%v)", c.provider, got, c.legal, err)
			}
		}
	})
}

func TestInsertAndGetCloudRun_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		result := json.RawMessage(`{"hops":[{"edge":"role-a","state":"observed"},{"edge":"role-b","state":"policy_supported"}],"overallState":"policy_supported"}`)
		started := time.Now().UTC().Truncate(time.Microsecond)
		run := &cloudrun.CloudRun{
			ID:          "run-1",
			ScenarioID:  "cloud-ransomware-s3",
			Provider:    "aws",
			AccountID:   "111122223333",
			TenantID:    "",
			Region:      "us-east-1",
			Status:      cloudrun.StatusRunning,
			Result:      result,
			Error:       "",
			InitiatedBy: "tausif",
			StartedAt:   started,
			CompletedAt: nil,
		}
		if err := db.InsertCloudRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetCloudRun(ctx, pool, "run-1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.ID != run.ID || got.ScenarioID != run.ScenarioID || got.Provider != run.Provider ||
			got.AccountID != run.AccountID || got.Region != run.Region || got.Status != run.Status ||
			got.InitiatedBy != run.InitiatedBy {
			t.Fatalf("round-trip field mismatch: got %+v, want %+v", got, run)
		}
		var gotJSON, wantJSON any
		if err := json.Unmarshal(got.Result, &gotJSON); err != nil {
			t.Fatalf("unmarshal got.Result: %v", err)
		}
		if err := json.Unmarshal(result, &wantJSON); err != nil {
			t.Fatalf("unmarshal want result: %v", err)
		}
		if !reflect.DeepEqual(gotJSON, wantJSON) {
			t.Fatalf("result mismatch: got %s want %s", got.Result, result)
		}
		if !got.StartedAt.Equal(started) {
			t.Fatalf("startedAt mismatch: got %v want %v", got.StartedAt, started)
		}
		if got.CompletedAt != nil {
			t.Fatalf("completedAt: got %v want nil", got.CompletedAt)
		}
	})
}

func TestInsertCloudRun_NilResultRoundTrips(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &cloudrun.CloudRun{
			ID:         "run-nil-result",
			ScenarioID: "cloud-plan-search",
			Provider:   "azure",
			Status:     cloudrun.StatusPending,
			StartedAt:  time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := db.InsertCloudRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetCloudRun(ctx, pool, "run-nil-result")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Result != nil {
			t.Fatalf("result: got %s want nil", got.Result)
		}
	})
}

func TestGetCloudRun_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, err := db.GetCloudRun(ctx, pool, "does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("want pgx.ErrNoRows, got %v", err)
		}
	})
}
