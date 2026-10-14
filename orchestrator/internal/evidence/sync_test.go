package evidence

import (
	"context"
	"testing"
	"time"
)

func TestRecordSync_CompleteSnapshotIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "misp-sync-test-1"
	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	_, authoritative, err := store.RecordSync(ctx, id, ModeSnapshot, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	if !authoritative {
		t.Fatal("complete snapshot sync must be authoritative")
	}
}

func TestRecordSync_PartialSnapshotIsNotAuthoritative(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "misp-sync-test-2"
	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	_, authoritative, err := store.RecordSync(ctx, id, ModeSnapshot, time.Now(), "succeeded", Partial, "one event detail fetch failed")
	if err != nil {
		t.Fatal(err)
	}
	if authoritative {
		t.Fatal("partial snapshot sync must not be authoritative")
	}
}

func TestRecordSync_ActivityWindowNeverAuthoritative(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "otx-sync-test-1"
	if err := store.EnsureSourceInstance(ctx, id, "otx", "Test", ModeActivityWindow, TrustUntrusted); err != nil {
		t.Fatal(err)
	}
	_, authoritative, err := store.RecordSync(ctx, id, ModeActivityWindow, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	if authoritative {
		t.Fatal("activity_window source must never be authoritative, even if it reports complete")
	}
}

func TestRecordSync_FailedSyncForcesFailedCompleteness(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "misp-sync-test-3"
	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, authoritative, err := store.RecordSync(ctx, id, ModeSnapshot, time.Now(), "failed", Complete, "network error")
	if err != nil {
		t.Fatal(err)
	}
	if authoritative {
		t.Fatal("a failed sync must never be authoritative, regardless of the completeness argument passed")
	}
	var storedCompleteness string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT completeness FROM source_syncs WHERE id = $1`, syncID).Scan(&storedCompleteness); err != nil {
		t.Fatal(err)
	}
	if storedCompleteness != "failed" {
		t.Fatalf("stored completeness = %q, want failed", storedCompleteness)
	}
}
