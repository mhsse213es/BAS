package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/db"
)

func TestListCloudRunsByCampaign_ReturnsOnlyMatchingRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		matching := &cloudrun.CloudRun{
			ID: "campaign-filter-match", ScenarioID: "s", Provider: "aws", AccountID: "1",
			Status: cloudrun.StatusCompleted, CampaignID: "campaign-filter-test",
		}
		other := &cloudrun.CloudRun{
			ID: "campaign-filter-other", ScenarioID: "s", Provider: "aws", AccountID: "2",
			Status: cloudrun.StatusCompleted, CampaignID: "a-different-campaign",
		}
		if err := db.InsertCloudRun(context.Background(), pool, matching); err != nil {
			t.Fatalf("insert matching: %v", err)
		}
		if err := db.InsertCloudRun(context.Background(), pool, other); err != nil {
			t.Fatalf("insert other: %v", err)
		}

		runs, err := db.ListCloudRunsByCampaign(context.Background(), pool, "campaign-filter-test")
		if err != nil {
			t.Fatalf("ListCloudRunsByCampaign: %v", err)
		}
		if len(runs) != 1 || runs[0].ID != "campaign-filter-match" {
			t.Fatalf("got %d runs, want exactly 1 matching campaign-filter-match", len(runs))
		}
	})
}

func TestListCloudRunsByCampaign_NoMatchReturnsNilNotError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runs, err := db.ListCloudRunsByCampaign(context.Background(), pool, "nonexistent-campaign-id")
		if err != nil {
			t.Fatalf("ListCloudRunsByCampaign: %v", err)
		}
		if len(runs) != 0 {
			t.Fatalf("got %d runs, want 0", len(runs))
		}
	})
}
