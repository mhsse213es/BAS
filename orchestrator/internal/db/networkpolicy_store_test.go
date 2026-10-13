package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkpolicy"
)

func TestInsertNetworkPolicyImport_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &networkpolicy.PolicyImport{
			ID: "npimp-roundtrip-1", SourceType: "manual-normalized", ImportedBy: "alice",
			ConfigVersion: "v1", DefaultPolicy: networkpolicy.DefaultDeny,
			Zones:       []networkpolicy.Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}},
			Rules:       []networkpolicy.Rule{{ID: "r1", Order: 1, SourceZone: "dmz", DestCIDR: "0.0.0.0/0", PortRange: "443", Action: networkpolicy.ActionAllow}},
			Limitations: []string{"hand-translated from a vendor export"},
		}
		if err := db.InsertNetworkPolicyImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetNetworkPolicyImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.SourceType != "manual-normalized" || got.ImportedBy != "alice" || got.ConfigVersion != "v1" || got.DefaultPolicy != networkpolicy.DefaultDeny {
			t.Fatalf("got %+v, want SourceType=manual-normalized ImportedBy=alice ConfigVersion=v1 DefaultPolicy=deny", got)
		}
		if len(got.Zones) != 1 || got.Zones[0].Name != "dmz" || len(got.Zones[0].CIDRs) != 1 || got.Zones[0].CIDRs[0] != "10.0.1.0/24" {
			t.Fatalf("Zones round-trip mismatch: %+v", got.Zones)
		}
		if len(got.Rules) != 1 || got.Rules[0].ID != "r1" || got.Rules[0].Action != networkpolicy.ActionAllow {
			t.Fatalf("Rules round-trip mismatch: %+v", got.Rules)
		}
		if len(got.Limitations) != 1 || got.Limitations[0] != "hand-translated from a vendor export" {
			t.Fatalf("Limitations round-trip mismatch: %+v", got.Limitations)
		}
		if got.ImportedAt.IsZero() {
			t.Fatal("ImportedAt should be populated by the database default")
		}

		list, err := db.ListNetworkPolicyImports(context.Background(), pool, 100)
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

func TestGetNetworkPolicyImport_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetNetworkPolicyImport(context.Background(), pool, "nonexistent-import-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
