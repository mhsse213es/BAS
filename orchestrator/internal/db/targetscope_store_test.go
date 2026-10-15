package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/targetscope"
)

func TestInsertAndGetTargetScopeImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &targetscope.TargetScopeImport{
			ID: "ts-roundtrip-1", SourceType: "manual",
			AuthorizedTargets: []targetscope.AuthorizedTarget{
				{CIDR: "10.0.1.0/24", Note: "pentest lab"},
				{Host: "approved.example"},
			},
			Limitations: []string{"not cross-validated against a real network-topology import"},
			ImportedBy:  "user-1",
		}
		if err := db.InsertTargetScopeImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetTargetScopeImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.SourceType != "manual" || got.ImportedBy != "user-1" {
			t.Errorf("round-tripped import mismatch: %+v", got)
		}
		if len(got.AuthorizedTargets) != 2 || got.AuthorizedTargets[0].CIDR != "10.0.1.0/24" || got.AuthorizedTargets[1].Host != "approved.example" {
			t.Errorf("authorized targets did not round-trip: %+v", got.AuthorizedTargets)
		}
	})
}

func TestGetTargetScopeImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetTargetScopeImport(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListTargetScopeImports_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		older := &targetscope.TargetScopeImport{ID: "ts-older", SourceType: "manual", AuthorizedTargets: []targetscope.AuthorizedTarget{{CIDR: "10.0.1.0/24"}}}
		if err := db.InsertTargetScopeImport(context.Background(), pool, older); err != nil {
			t.Fatalf("insert older: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		newer := &targetscope.TargetScopeImport{ID: "ts-newer", SourceType: "manual", AuthorizedTargets: []targetscope.AuthorizedTarget{{CIDR: "10.0.2.0/24"}}}
		if err := db.InsertTargetScopeImport(context.Background(), pool, newer); err != nil {
			t.Fatalf("insert newer: %v", err)
		}

		list, err := db.ListTargetScopeImports(context.Background(), pool, 20)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) < 2 {
			t.Fatalf("got %d imports, want at least 2", len(list))
		}
		if list[0].ID != "ts-newer" {
			t.Errorf("list[0].ID = %q, want %q (newest first)", list[0].ID, "ts-newer")
		}
	})
}
