package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/zoneisolation"
)

func TestInsertAndGetZoneIsolationImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &zoneisolation.IsolationImport{
			ID:         "zi-roundtrip-1",
			SourceType: "manual",
			ZonePairIsolations: []zoneisolation.ZonePairIsolation{
				{CanonicalID: "zp-1", ZoneA: "guest", ZoneB: "clinical", Note: "guest wifi must never reach clinical"},
			},
			Limitations: []string{"zone names are not cross-validated against a real network-topology import"},
		}
		if err := db.InsertZoneIsolationImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetZoneIsolationImport(context.Background(), pool, "zi-roundtrip-1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.ZonePairIsolations) != 1 || got.ZonePairIsolations[0].ZoneA != "guest" {
			t.Fatalf("got %+v, want one zonePairIsolation with zoneA=guest", got.ZonePairIsolations)
		}
	})
}

func TestGetZoneIsolationImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetZoneIsolationImport(context.Background(), pool, "zi-does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListZoneIsolationImports_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		first := &zoneisolation.IsolationImport{ID: "zi-list-1", SourceType: "manual"}
		if err := db.InsertZoneIsolationImport(context.Background(), pool, first); err != nil {
			t.Fatalf("insert first: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		second := &zoneisolation.IsolationImport{ID: "zi-list-2", SourceType: "manual"}
		if err := db.InsertZoneIsolationImport(context.Background(), pool, second); err != nil {
			t.Fatalf("insert second: %v", err)
		}
		list, err := db.ListZoneIsolationImports(context.Background(), pool, 20)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) < 2 {
			t.Fatalf("got %d imports, want at least 2", len(list))
		}
		if list[0].ID != second.ID {
			t.Fatalf("list[0].ID = %q, want %q (newest first)", list[0].ID, second.ID)
		}
	})
}
