package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
)

func TestInsertNetworkDiscoveryRun_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		run := &db.NetworkDiscoveryRun{
			ID: "ndrun-roundtrip-1", VantagePointID: "vp-1", RequestedBy: "alice",
			TargetCount: 2, Status: "completed",
		}
		if err := db.InsertNetworkDiscoveryRun(context.Background(), pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetNetworkDiscoveryRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.VantagePointID != "vp-1" || got.RequestedBy != "alice" || got.TargetCount != 2 || got.Status != "completed" {
			t.Fatalf("got %+v, want VantagePointID=vp-1 RequestedBy=alice TargetCount=2 Status=completed", got)
		}
		if got.StartedAt.IsZero() {
			t.Fatal("StartedAt should be populated by the database default")
		}

		list, err := db.ListNetworkDiscoveryRuns(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		found := false
		for _, r := range list {
			if r.ID == run.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted run should appear in the list")
		}
	})
}

func TestGetNetworkDiscoveryRun_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetNetworkDiscoveryRun(context.Background(), pool, "nonexistent-run-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestInsertNetworkObservations_RoundTripsThroughListNetworkObservationsByRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		run := &db.NetworkDiscoveryRun{ID: "ndrun-obs-1", VantagePointID: "vp-1", TargetCount: 2, Status: "completed"}
		if err := db.InsertNetworkDiscoveryRun(context.Background(), pool, run); err != nil {
			t.Fatalf("insert run: %v", err)
		}

		obs := []networkgraph.NetworkObservation{
			{
				Target: networkgraph.Target{Host: "10.0.0.1", Port: 443, Label: "web"},
				VantagePointID: "vp-1", State: cloudgraph.Observed,
				Provenance: cloudgraph.Provenance{Source: "test-position", Confidence: "high"},
			},
			{
				Target: networkgraph.Target{Host: "10.0.0.2", Port: 22},
				VantagePointID: "vp-1", State: cloudgraph.Blocked, ErrorDetail: "connection refused",
				Provenance: cloudgraph.Provenance{Source: "test-position", Confidence: "high"},
			},
		}
		if err := db.InsertNetworkObservations(context.Background(), pool, run.ID, obs); err != nil {
			t.Fatalf("insert observations: %v", err)
		}

		got, err := db.ListNetworkObservationsByRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("list observations: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d observations, want 2", len(got))
		}
		byHost := map[string]networkgraph.NetworkObservation{}
		for _, o := range got {
			byHost[o.Target.Host] = o
		}
		if byHost["10.0.0.1"].State != cloudgraph.Observed || byHost["10.0.0.1"].Target.Label != "web" {
			t.Fatalf("10.0.0.1 observation = %+v, want State=observed Label=web", byHost["10.0.0.1"])
		}
		if byHost["10.0.0.2"].State != cloudgraph.Blocked || byHost["10.0.0.2"].ErrorDetail != "connection refused" {
			t.Fatalf("10.0.0.2 observation = %+v, want State=blocked ErrorDetail=connection refused", byHost["10.0.0.2"])
		}
	})
}
