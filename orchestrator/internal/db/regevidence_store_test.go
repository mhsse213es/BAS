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

func TestInsertAndGetEvidenceSnapshot_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		es := &regobligation.EvidenceSnapshot{
			ID: "es-roundtrip-1", SchemaVersion: regobligation.CurrentSnapshotSchemaVersion,
			ObligationID: "ob-1", ControlMappingID: "cm-1", ObligationVersion: "v1",
			CapabilityName:   "zoneisolation.isolation-check",
			ImportReferences: map[string]string{"topologyImportId": "topo-1", "isolationImportId": "iso-1"},
			CapturedOutcome:  "no-violation-found", Status: regobligation.SnapshotCaptured,
			CapturedBy: "user-1", CapturedAt: time.Now().UTC(),
		}
		if err := db.InsertEvidenceSnapshot(context.Background(), pool, es); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetEvidenceSnapshot(context.Background(), pool, es.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.ObligationID != "ob-1" || got.ControlMappingID != "cm-1" || got.CapturedOutcome != "no-violation-found" {
			t.Errorf("round-tripped snapshot mismatch: %+v", got)
		}
		if got.ImportReferences["topologyImportId"] != "topo-1" {
			t.Errorf("import references did not round-trip: %+v", got.ImportReferences)
		}
	})
}

func TestGetEvidenceSnapshot_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetEvidenceSnapshot(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListEvidenceSnapshotsByObligation_NewestFirstAndScopedToObligation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		forOtherObligation := &regobligation.EvidenceSnapshot{
			ID: "es-other", ObligationID: "ob-other", ControlMappingID: "cm-1",
			CapabilityName: "x", CapturedOutcome: "no-violation-found",
			Status: regobligation.SnapshotCaptured, CapturedAt: time.Now().UTC(),
		}
		if err := db.InsertEvidenceSnapshot(context.Background(), pool, forOtherObligation); err != nil {
			t.Fatalf("insert forOtherObligation: %v", err)
		}
		older := &regobligation.EvidenceSnapshot{
			ID: "es-older", ObligationID: "ob-target", ControlMappingID: "cm-1",
			CapabilityName: "x", CapturedOutcome: "no-violation-found",
			Status: regobligation.SnapshotCaptured, CapturedAt: time.Now().UTC(),
		}
		if err := db.InsertEvidenceSnapshot(context.Background(), pool, older); err != nil {
			t.Fatalf("insert older: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		newer := &regobligation.EvidenceSnapshot{
			ID: "es-newer", ObligationID: "ob-target", ControlMappingID: "cm-1",
			CapabilityName: "x", CapturedOutcome: "confirmed-violation",
			Status: regobligation.SnapshotCaptured, CapturedAt: time.Now().UTC(),
		}
		if err := db.InsertEvidenceSnapshot(context.Background(), pool, newer); err != nil {
			t.Fatalf("insert newer: %v", err)
		}

		list, err := db.ListEvidenceSnapshotsByObligation(context.Background(), pool, "ob-target")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("got %d snapshots scoped to ob-target, want exactly 2", len(list))
		}
		if list[0].ID != "es-newer" {
			t.Errorf("list[0].ID = %q, want %q (newest first)", list[0].ID, "es-newer")
		}
	})
}
