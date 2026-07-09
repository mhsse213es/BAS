package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAddEvidence_HashesBytesAndDefaultsDisplayFilename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e1", ExpectationID: "exp-e1", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}

		payload := []byte("evidence bytes")
		ev, err := store.AddEvidence(ctx, EvidenceInput{
			VerificationID:   rec.ID,
			OriginalFilename: "screenshot.png",
			MIME:             "image/png",
			UploadedBy:       "alice",
			Bytes:            payload,
		})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}

		sum := sha256.Sum256(payload)
		want := hex.EncodeToString(sum[:])
		if ev.ContentHash != want {
			t.Fatalf("ContentHash = %q, want %q", ev.ContentHash, want)
		}
		if ev.HashAlgorithm != HashSHA256 {
			t.Fatalf("HashAlgorithm = %q, want %q", ev.HashAlgorithm, HashSHA256)
		}
		if ev.DisplayFilename != "screenshot.png" {
			t.Fatalf("DisplayFilename = %q, want defaulted to OriginalFilename", ev.DisplayFilename)
		}

		gotBytes, err := store.EvidenceBytes(ctx, ev)
		if err != nil {
			t.Fatalf("EvidenceBytes: %v", err)
		}
		if !bytes.Equal(gotBytes, payload) {
			t.Fatalf("EvidenceBytes = %q, want %q", gotBytes, payload)
		}
	})
}

func TestAddEvidence_ExplicitDisplayFilenameNotOverridden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e2", ExpectationID: "exp-e2", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}

		ev, err := store.AddEvidence(ctx, EvidenceInput{
			VerificationID:   rec.ID,
			OriginalFilename: "raw-name.png",
			DisplayFilename:  "Nice Display Name.png",
			UploadedBy:       "alice",
			Bytes:            []byte("x"),
		})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		if ev.DisplayFilename != "Nice Display Name.png" {
			t.Fatalf("DisplayFilename = %q, want explicit value preserved", ev.DisplayFilename)
		}
	})
}

func TestListEvidence_ExcludesSoftDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e3", ExpectationID: "exp-e3", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}

		ev1, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "a.png", UploadedBy: "alice", Bytes: []byte("a")})
		if err != nil {
			t.Fatalf("AddEvidence 1: %v", err)
		}
		ev2, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "b.png", UploadedBy: "alice", Bytes: []byte("b")})
		if err != nil {
			t.Fatalf("AddEvidence 2: %v", err)
		}

		if err := store.SoftDeleteEvidence(ctx, ev1.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		list, err := store.ListEvidence(ctx, rec.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		if len(list) != 1 || list[0].ID != ev2.ID {
			t.Fatalf("ListEvidence = %+v, want only ev2", list)
		}
	})
}

func TestEvidenceByID_FoundIncludingDeletedAndMissing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e4", ExpectationID: "exp-e4", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		ev, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "a.png", UploadedBy: "alice", Bytes: []byte("a")})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		if err := store.SoftDeleteEvidence(ctx, ev.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		got, ok, err := store.EvidenceByID(ctx, ev.ID)
		if err != nil || !ok {
			t.Fatalf("EvidenceByID: ok=%v err=%v", ok, err)
		}
		if !got.Deleted {
			t.Fatal("expected Deleted=true to be visible via EvidenceByID")
		}

		_, ok, err = store.EvidenceByID(ctx, "does-not-exist")
		if err != nil {
			t.Fatalf("EvidenceByID missing: %v", err)
		}
		if ok {
			t.Fatal("expected ok=false for missing evidence id")
		}
	})
}

func TestEvidenceBytes_ErrorsForNonDatabaseStorage(t *testing.T) {
	store := NewStore(nil)
	ev := Evidence{StorageType: StorageFilesystem}
	if _, err := store.EvidenceBytes(context.Background(), ev); err == nil {
		t.Fatal("expected error for non-database storage type")
	}
}

func TestSoftDeleteEvidence_IdempotentSecondCallNoError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e5", ExpectationID: "exp-e5", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		ev, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "a.png", UploadedBy: "alice", Bytes: []byte("a")})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}

		if err := store.SoftDeleteEvidence(ctx, ev.ID, "alice"); err != nil {
			t.Fatalf("first SoftDeleteEvidence: %v", err)
		}
		if err := store.SoftDeleteEvidence(ctx, ev.ID, "bob"); err != nil {
			t.Fatalf("second SoftDeleteEvidence should not error: %v", err)
		}

		got, ok, err := store.EvidenceByID(ctx, ev.ID)
		if err != nil || !ok {
			t.Fatalf("EvidenceByID: ok=%v err=%v", ok, err)
		}
		if got.DeletedBy != "alice" {
			t.Fatalf("DeletedBy = %q, want %q (first delete wins, second is a no-op)", got.DeletedBy, "alice")
		}
	})
}

func TestEvidenceCountsForRun_OnlyActiveAndNonDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e6", ExpectationID: "exp-e6", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if _, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "a.png", UploadedBy: "alice", Bytes: []byte("a")}); err != nil {
			t.Fatalf("AddEvidence 1: %v", err)
		}
		ev2, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "b.png", UploadedBy: "alice", Bytes: []byte("b")})
		if err != nil {
			t.Fatalf("AddEvidence 2: %v", err)
		}
		if err := store.SoftDeleteEvidence(ctx, ev2.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		counts, err := store.EvidenceCountsForRun(ctx, "run-e6")
		if err != nil {
			t.Fatalf("EvidenceCountsForRun: %v", err)
		}
		if counts[rec.ID] != 1 {
			t.Fatalf("counts[rec.ID] = %d, want 1 (soft-deleted excluded)", counts[rec.ID])
		}
	})
}
