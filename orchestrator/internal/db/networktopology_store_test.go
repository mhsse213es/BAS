package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networktopology"
)

func TestInsertNetworkTopologyImport_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &networktopology.TopologyImport{
			ID: "ntimp-roundtrip-1", SourceType: "manual-declared", ImportedBy: "alice", ConfigVersion: "v1",
			Zones:       []networktopology.Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}},
			Edges:       []networktopology.RouteEdge{{FromZone: "dmz", ToZone: "internal"}},
			Limitations: []string{"no NAT interaction modeled"},
		}
		if err := db.InsertNetworkTopologyImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetNetworkTopologyImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.SourceType != "manual-declared" || got.ImportedBy != "alice" || got.ConfigVersion != "v1" {
			t.Fatalf("got %+v, want SourceType=manual-declared ImportedBy=alice ConfigVersion=v1", got)
		}
		if len(got.Zones) != 1 || got.Zones[0].Name != "dmz" {
			t.Fatalf("Zones round-trip mismatch: %+v", got.Zones)
		}
		if len(got.Edges) != 1 || got.Edges[0].FromZone != "dmz" || got.Edges[0].ToZone != "internal" {
			t.Fatalf("Edges round-trip mismatch: %+v", got.Edges)
		}
		if len(got.Limitations) != 1 || got.Limitations[0] != "no NAT interaction modeled" {
			t.Fatalf("Limitations round-trip mismatch: %+v", got.Limitations)
		}
		if got.ImportedAt.IsZero() {
			t.Fatal("ImportedAt should be populated by the database default")
		}

		list, err := db.ListNetworkTopologyImports(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		found := false
		for _, r := range list {
			if r.ID == imp.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted import should appear in the list")
		}
	})
}

func TestGetNetworkTopologyImport_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetNetworkTopologyImport(context.Background(), pool, "nonexistent-topology-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
