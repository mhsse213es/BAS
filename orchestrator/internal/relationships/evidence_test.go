package relationships

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAddEvidence_Defaults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1001")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-1001", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		ev, err := store.AddEvidence(ctx, EvidenceInput{
			RelationshipID: r.ID, ReferenceValue: "https://example.com/advisory", AddedBy: "alice",
		})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		if ev.Source != SourceAnalyst {
			t.Fatalf("Source = %q, want default %q", ev.Source, SourceAnalyst)
		}
		if ev.ReferenceType != ReferenceURL {
			t.Fatalf("ReferenceType = %q, want default %q", ev.ReferenceType, ReferenceURL)
		}
	})
}

func TestListEvidence_OrderedByPriorityThenAddedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1002")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-1002", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		low, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "low-priority", Priority: 5, AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence low: %v", err)
		}
		high, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "high-priority", Priority: 1, AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence high: %v", err)
		}

		list, err := store.ListEvidence(ctx, r.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		if len(list) != 2 || list[0].ID != high.ID || list[1].ID != low.ID {
			t.Fatalf("ListEvidence order = %+v, want [high, low] by priority ascending", list)
		}
	})
}

func TestListEvidence_ExcludesSoftDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1003")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-1003", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		ev1, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "a", AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence 1: %v", err)
		}
		ev2, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "b", AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence 2: %v", err)
		}

		if err := store.SoftDeleteEvidence(ctx, ev1.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		list, err := store.ListEvidence(ctx, r.ID)
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
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1004")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-1004", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		ev, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "a", AddedBy: "alice"})
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
			t.Fatal("expected Deleted=true visible via EvidenceByID")
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

func TestEvidenceCounts_BatchAndEmptySliceShortCircuit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1005")
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1006")
		store := NewStore(pool)
		ctx := context.Background()

		r1, err := store.Create(ctx, CreateInput{TechniqueID: "T1059", CVEID: "CVE-2024-1005", RelationshipType: TypeDirectExploitation, CreatedBy: "alice"})
		if err != nil {
			t.Fatalf("Create r1: %v", err)
		}
		r2, err := store.Create(ctx, CreateInput{TechniqueID: "T1059", CVEID: "CVE-2024-1006", RelationshipType: TypeDirectExploitation, CreatedBy: "alice"})
		if err != nil {
			t.Fatalf("Create r2: %v", err)
		}
		if _, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r1.ID, ReferenceValue: "a", AddedBy: "alice"}); err != nil {
			t.Fatalf("AddEvidence r1: %v", err)
		}

		counts, err := store.EvidenceCounts(ctx, []string{r1.ID, r2.ID})
		if err != nil {
			t.Fatalf("EvidenceCounts: %v", err)
		}
		if counts[r1.ID] != 1 {
			t.Fatalf("counts[r1.ID] = %d, want 1", counts[r1.ID])
		}
		if _, ok := counts[r2.ID]; ok {
			t.Fatalf("counts[r2.ID] should be absent (no evidence rows), got %d", counts[r2.ID])
		}

		empty, err := store.EvidenceCounts(ctx, nil)
		if err != nil {
			t.Fatalf("EvidenceCounts(nil): %v", err)
		}
		if len(empty) != 0 {
			t.Fatalf("EvidenceCounts(nil) = %+v, want empty map", empty)
		}
	})
}
