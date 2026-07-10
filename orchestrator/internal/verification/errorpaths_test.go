package verification

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestStore_ClosedPool_AllMethodsReturnError pins down connection-failure
// behavior: every store method must propagate the pool error, never panic
// and never mask it as a "not found" result.
func TestStore_ClosedPool_AllMethodsReturnError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, sharedDB.Pool.Config().ConnString())
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	pool.Close()
	store := NewStore(pool)

	if _, err := store.CurrentForRun(ctx, "r"); err == nil {
		t.Error("CurrentForRun: want error on closed pool")
	}
	if _, err := store.History(ctx, "r", "e"); err == nil {
		t.Error("History: want error on closed pool")
	}
	if _, _, err := store.Get(ctx, "id"); err == nil {
		t.Error("Get: want error on closed pool, not ok=false")
	}
	if _, err := store.Attest(ctx, AttestInput{RunID: "r", ExpectationID: "e", VerifiedBy: "x"}); err == nil {
		t.Error("Attest: want error on closed pool")
	}
	if _, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: "v", OriginalFilename: "a", UploadedBy: "x", Bytes: []byte("b")}); err == nil {
		t.Error("AddEvidence: want error on closed pool")
	}
	if _, err := store.ListEvidence(ctx, "v"); err == nil {
		t.Error("ListEvidence: want error on closed pool")
	}
	if _, _, err := store.EvidenceByID(ctx, "id"); err == nil {
		t.Error("EvidenceByID: want error on closed pool, not ok=false")
	}
	if _, err := store.EvidenceBytes(ctx, Evidence{StorageType: StorageDatabase, StorageKey: "k"}); err == nil {
		t.Error("EvidenceBytes: want error on closed pool")
	}
	if _, err := store.EvidenceCountsForRun(ctx, "r"); err == nil {
		t.Error("EvidenceCountsForRun: want error on closed pool")
	}
}

func TestEvidenceBytes_MissingBlobRowIsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, err := store.EvidenceBytes(context.Background(), Evidence{
			StorageType: StorageDatabase, StorageKey: "no-such-blob",
		})
		if err == nil {
			t.Fatal("expected error for dangling blob storage key")
		}
	})
}

func TestAddEvidence_NilBytesRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		// nil bytes encode as SQL NULL, which the NOT NULL blob column rejects
		// inside the transaction — no orphan metadata row may be committed.
		_, err := store.AddEvidence(context.Background(), EvidenceInput{
			VerificationID: "v-nil", OriginalFilename: "empty", UploadedBy: "x", Bytes: nil,
		})
		if err == nil {
			t.Fatal("expected error for nil evidence bytes")
		}
		list, err := store.ListEvidence(context.Background(), "v-nil")
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		if len(list) != 0 {
			t.Fatalf("expected no metadata rows after failed AddEvidence, got %d", len(list))
		}
	})
}
