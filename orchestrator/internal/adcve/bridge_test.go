package adcve

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/relationships"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func seedTechniqueCVE(t *testing.T, pool *pgxpool.Pool, techniqueID, cveID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO techniques (technique_id) VALUES ($1) ON CONFLICT (technique_id) DO NOTHING`,
		techniqueID); err != nil {
		t.Fatalf("seed technique %s: %v", techniqueID, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO cves (cve_id) VALUES ($1) ON CONFLICT (cve_id) DO NOTHING`,
		cveID); err != nil {
		t.Fatalf("seed cve %s: %v", cveID, err)
	}
}

func TestRelatedCVEs_NoTechniqueIDReturnsFalseWithoutTouchingStore(t *testing.T) {
	// store is nil -- if the implementation touched it before checking
	// TechniqueID, this would panic instead of returning ok=false.
	rels, ok, err := RelatedCVEs(context.Background(), nil, adprimitive.Primitive{ID: "acl-forcechangepassword-abuse"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for a primitive with no TechniqueID")
	}
	if len(rels) != 0 {
		t.Fatalf("expected no relationships, got %+v", rels)
	}
}

func TestRelatedCVEs_TechniqueWithNoRelationshipsReturnsTrueAndEmpty(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := relationships.NewStore(pool)
		p := adprimitive.Primitive{ID: "adcs-esc1", TechniqueID: "T1649-ad-m10-test-unmapped"}

		rels, ok, err := RelatedCVEs(context.Background(), store, p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("expected ok=true: p has a TechniqueID, even with zero relationships recorded")
		}
		if len(rels) != 0 {
			t.Fatalf("expected zero relationships for an unmapped technique, got %+v", rels)
		}
	})
}

func TestRelatedCVEs_ReturnsSeededRelationshipUnchanged(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := relationships.NewStore(pool)
		techniqueID := "T1003.006-ad-m10-test"
		cveID := "CVE-2024-9999"
		seedTechniqueCVE(t, pool, techniqueID, cveID)

		created, err := store.Create(ctx, relationships.CreateInput{
			TechniqueID:      techniqueID,
			CVEID:            cveID,
			RelationshipType: "exploits",
			CreatedBy:        "ad-m10-test",
		})
		if err != nil {
			t.Fatalf("seed relationship: %v", err)
		}

		p := adprimitive.Primitive{ID: "dcsync", TechniqueID: techniqueID}
		rels, ok, err := RelatedCVEs(ctx, store, p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("expected ok=true")
		}
		if len(rels) != 1 || rels[0].ID != created.ID {
			t.Fatalf("expected exactly the seeded relationship %+v, got %+v", created, rels)
		}
	})
}
