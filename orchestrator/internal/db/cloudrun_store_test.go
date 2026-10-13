package db_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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
