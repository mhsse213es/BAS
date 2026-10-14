package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/otsafety"
)

func TestInsertAndGetOTSafetyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &otsafety.OTSafetyImport{
			ID:         "ot-roundtrip-1",
			SourceType: "manual",
			SensitiveZones: []otsafety.SensitiveZone{
				{ZoneName: "ot", Tier: otsafety.TierOT, Note: "engineering workstation zone"},
			},
			RequiredTransits: []otsafety.RequiredTransit{
				{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
			},
			Limitations: []string{"zone names are not cross-validated against a real network-topology import"},
		}
		if err := db.InsertOTSafetyImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := db.GetOTSafetyImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.SensitiveZones) != 1 || got.SensitiveZones[0].ZoneName != "ot" {
			t.Fatalf("SensitiveZones = %v, want 1 entry for zone \"ot\"", got.SensitiveZones)
		}
		if len(got.RequiredTransits) != 1 || got.RequiredTransits[0].CanonicalID != "rt-1" {
			t.Fatalf("RequiredTransits = %v, want 1 entry \"rt-1\"", got.RequiredTransits)
		}
	})
}

func TestGetOTSafetyImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetOTSafetyImport(context.Background(), pool, "does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListOTSafetyImports_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		first := &otsafety.OTSafetyImport{ID: "ot-list-1", SourceType: "manual"}
		if err := db.InsertOTSafetyImport(context.Background(), pool, first); err != nil {
			t.Fatalf("insert first: %v", err)
		}
		second := &otsafety.OTSafetyImport{ID: "ot-list-2", SourceType: "manual"}
		if err := db.InsertOTSafetyImport(context.Background(), pool, second); err != nil {
			t.Fatalf("insert second: %v", err)
		}
		list, err := db.ListOTSafetyImports(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) < 2 {
			t.Fatalf("list = %v, want at least 2 entries", list)
		}
	})
}
