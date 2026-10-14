package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkefficacy"
)

func TestInsertNetworkControlExpectationImport_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &networkefficacy.ControlExpectationImport{
			ID: "nceimp-roundtrip-1", SourceType: "manual-declared", ImportedBy: "alice", ConfigVersion: "v1",
			Expectations: []networkefficacy.ControlExpectation{
				{FlowSourceCIDR: "10.0.1.0/24", FlowDestCIDR: "10.0.2.0/24", FlowPort: 443, FlowProtocol: "tcp", ExpectedAction: networkefficacy.ExpectedBlock, ControlProduct: "opnsense"},
			},
			Limitations: []string{"lab-only, no production firewall yet"},
		}
		if err := db.InsertNetworkControlExpectationImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetNetworkControlExpectationImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.SourceType != "manual-declared" || got.ImportedBy != "alice" || got.ConfigVersion != "v1" {
			t.Fatalf("got %+v, want SourceType=manual-declared ImportedBy=alice ConfigVersion=v1", got)
		}
		if len(got.Expectations) != 1 || got.Expectations[0].ExpectedAction != networkefficacy.ExpectedBlock {
			t.Fatalf("Expectations round-trip mismatch: %+v", got.Expectations)
		}
		if len(got.Limitations) != 1 {
			t.Fatalf("Limitations round-trip mismatch: %+v", got.Limitations)
		}
		if got.ImportedAt.IsZero() {
			t.Fatal("ImportedAt should be populated by the database default")
		}

		list, err := db.ListNetworkControlExpectationImports(context.Background(), pool, 100)
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

func TestGetNetworkControlExpectationImport_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetNetworkControlExpectationImport(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
