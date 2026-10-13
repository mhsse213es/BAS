package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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

func TestInsertCloudCampaign_RoundTripsThroughGet(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		c := &db.CloudCampaign{ID: "campaign-roundtrip-1", Name: "Quarterly Check", CreatedBy: "alice"}
		if err := db.InsertCloudCampaign(context.Background(), pool, c); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetCloudCampaign(context.Background(), pool, c.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Name != "Quarterly Check" || got.CreatedBy != "alice" {
			t.Fatalf("got %+v, want Name=Quarterly Check CreatedBy=alice", got)
		}
		if got.CreatedAt.IsZero() {
			t.Fatal("CreatedAt should be populated by the database default")
		}
	})
}

func TestGetCloudCampaign_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetCloudCampaign(context.Background(), pool, "nonexistent-campaign-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListCloudCampaigns_ReturnsNewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		older := &db.CloudCampaign{ID: "campaign-list-older", Name: "Older"}
		if err := db.InsertCloudCampaign(context.Background(), pool, older); err != nil {
			t.Fatalf("insert older: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		newer := &db.CloudCampaign{ID: "campaign-list-newer", Name: "Newer"}
		if err := db.InsertCloudCampaign(context.Background(), pool, newer); err != nil {
			t.Fatalf("insert newer: %v", err)
		}

		list, err := db.ListCloudCampaigns(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		newerIdx, olderIdx := -1, -1
		for i, c := range list {
			if c.ID == "campaign-list-newer" {
				newerIdx = i
			}
			if c.ID == "campaign-list-older" {
				olderIdx = i
			}
		}
		if newerIdx == -1 || olderIdx == -1 {
			t.Fatalf("both campaigns must be in the list, got newerIdx=%d olderIdx=%d", newerIdx, olderIdx)
		}
		if newerIdx >= olderIdx {
			t.Fatalf("newer campaign (idx %d) should sort before older (idx %d)", newerIdx, olderIdx)
		}
	})
}
