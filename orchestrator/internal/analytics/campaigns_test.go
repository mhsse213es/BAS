package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCampaigns_EmptyFleet_ReturnsEmptySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := Campaigns(context.Background(), pool)
		if err != nil {
			t.Fatalf("Campaigns: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("Campaigns() = %+v, want empty", got)
		}
	})
}

func TestCampaigns_DelegatesToListWithRollups(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `
			INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode, created_by, targets, skips, tags, started_at)
			VALUES ('camp-analytics-1', 'Analytics Test Campaign', 'scn-1', 'Test Scenario', 'posture', 'tester', '[]', '[]', '[]', NOW())`)

		got, err := Campaigns(ctx, pool)
		if err != nil {
			t.Fatalf("Campaigns: %v", err)
		}
		if len(got) != 1 || got[0].ID != "camp-analytics-1" {
			t.Fatalf("Campaigns() = %+v, want 1 rollup for camp-analytics-1", got)
		}
	})
}
