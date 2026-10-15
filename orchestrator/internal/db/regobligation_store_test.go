package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/regobligation"
)

func TestInsertAndGetRegulatoryObligation_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ob := &regobligation.Obligation{
			ID: "ob-roundtrip-1", Jurisdiction: "India", Regulator: "RBI", Sector: "Banking",
			EntityType: "Regulated Financial Institution", Title: "Network segmentation for critical payment/banking systems",
			ObligationType: regobligation.ObligationMandatory, SourceReference: "RBI Cyber Security Framework for Banks",
			EffectiveDate: time.Date(2016, 6, 2, 0, 0, 0, 0, time.UTC), Version: "RBI CSF 2016 (as amended)",
			ControlMappings: []regobligation.ControlMapping{
				{CanonicalID: "cm-1", ControlName: "Segmentation", CapabilityName: "zoneisolation.isolation-check"},
			},
			CreatedBy: "user-1",
		}
		if err := db.InsertRegulatoryObligation(context.Background(), pool, ob); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetRegulatoryObligation(context.Background(), pool, ob.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Jurisdiction != "India" || got.Regulator != "RBI" || got.Title != ob.Title {
			t.Errorf("round-tripped obligation mismatch: %+v", got)
		}
		if len(got.ControlMappings) != 1 || got.ControlMappings[0].CapabilityName != "zoneisolation.isolation-check" {
			t.Errorf("control mappings did not round-trip: %+v", got.ControlMappings)
		}
	})
}

func TestGetRegulatoryObligation_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetRegulatoryObligation(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListRegulatoryObligations_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cm := []regobligation.ControlMapping{{CanonicalID: "cm-1", ControlName: "c", CapabilityName: "x"}}
		older := &regobligation.Obligation{
			ID: "ob-older", Jurisdiction: "India", Regulator: "RBI", Title: "Older",
			ObligationType: regobligation.ObligationMandatory, SourceReference: "ref", Version: "v1",
			EffectiveDate: time.Now().UTC(), ControlMappings: cm,
		}
		if err := db.InsertRegulatoryObligation(context.Background(), pool, older); err != nil {
			t.Fatalf("insert older: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		newer := &regobligation.Obligation{
			ID: "ob-newer", Jurisdiction: "UAE", Regulator: "UAE Central Bank", Title: "Newer",
			ObligationType: regobligation.ObligationMandatory, SourceReference: "ref", Version: "v1",
			EffectiveDate: time.Now().UTC(), ControlMappings: cm,
		}
		if err := db.InsertRegulatoryObligation(context.Background(), pool, newer); err != nil {
			t.Fatalf("insert newer: %v", err)
		}

		list, err := db.ListRegulatoryObligations(context.Background(), pool, 20)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) < 2 {
			t.Fatalf("got %d obligations, want at least 2", len(list))
		}
		if list[0].ID != "ob-newer" {
			t.Errorf("list[0].ID = %q, want %q (newest first)", list[0].ID, "ob-newer")
		}
	})
}
