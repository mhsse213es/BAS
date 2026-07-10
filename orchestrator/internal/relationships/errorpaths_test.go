package relationships

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCreate_ForeignKeyViolationIsNotErrDuplicate pins down that only a
// unique-constraint violation maps to ErrDuplicate — an FK violation for an
// unknown technique or CVE must surface as a raw error so callers don't tell
// the user "relationship already exists" when the real problem is bad input.
func TestCreate_ForeignKeyViolationIsNotErrDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, err := store.Create(context.Background(), CreateInput{
			TechniqueID: "T-UNSEEDED", CVEID: "CVE-0000-0000",
			RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err == nil {
			t.Fatal("expected FK violation error for unseeded technique/CVE")
		}
		if errors.Is(err, ErrDuplicate) {
			t.Fatalf("FK violation must not be reported as ErrDuplicate, got %v", err)
		}
	})
}

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

	if _, err := store.ForTechnique(ctx, "T1059"); err == nil {
		t.Error("ForTechnique: want error on closed pool")
	}
	if _, _, err := store.Get(ctx, "id"); err == nil {
		t.Error("Get: want error on closed pool, not ok=false")
	}
	if _, err := store.Update(ctx, "id", UpdateInput{RelationshipType: TypeDirectExploitation, ProposedConfidence: ConfidenceMedium, UpdatedBy: "x"}); err == nil {
		t.Error("Update: want error on closed pool")
	}
	if _, err := store.ListEvidence(ctx, "rel"); err == nil {
		t.Error("ListEvidence: want error on closed pool")
	}
	if _, _, err := store.EvidenceByID(ctx, "id"); err == nil {
		t.Error("EvidenceByID: want error on closed pool, not ok=false")
	}
	if _, err := store.EvidenceCounts(ctx, []string{"rel"}); err == nil {
		t.Error("EvidenceCounts: want error on closed pool")
	}
}
