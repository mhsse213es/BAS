package relationships

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// seedTechniqueCVE inserts a minimal techniques row and cves row so a
// relationship can be created against them — technique_cve_relationships
// has real foreign keys to both tables. Idempotent: safe to call multiple
// times with the same technique_id or cve_id (e.g. two CVEs for one
// technique).
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

func TestCreate_DefaultsConfidenceAndSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0001")
		store := NewStore(pool)

		r, err := store.Create(context.Background(), CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0001",
			RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if r.ProposedConfidence != ConfidenceMedium {
			t.Fatalf("ProposedConfidence = %q, want %q", r.ProposedConfidence, ConfidenceMedium)
		}
		if r.PrimarySource != SourceAnalyst {
			t.Fatalf("PrimarySource = %q, want %q", r.PrimarySource, SourceAnalyst)
		}
		if r.EffectiveConfidence != r.ProposedConfidence {
			t.Fatalf("EffectiveConfidence = %q, want equal to ProposedConfidence %q", r.EffectiveConfidence, r.ProposedConfidence)
		}
		if r.Status != StatusActive {
			t.Fatalf("Status = %q, want %q", r.Status, StatusActive)
		}
	})
}

func TestCreate_DuplicateTripleRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0002")
		store := NewStore(pool)
		ctx := context.Background()

		in := CreateInput{TechniqueID: "T1059", CVEID: "CVE-2024-0002", RelationshipType: TypeDirectExploitation, CreatedBy: "alice"}
		if _, err := store.Create(ctx, in); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		_, err := store.Create(ctx, in)
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("second Create error = %v, want ErrDuplicate", err)
		}
	})
}

func TestCreate_DifferentTypeSamePairSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0003")
		store := NewStore(pool)
		ctx := context.Background()

		if _, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0003", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		_, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0003", RelationshipType: TypePostExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("second Create with different type should succeed: %v", err)
		}
	})
}

func TestUpdate_ChangesDescriptiveFieldsOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0004")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0004", RelationshipType: TypeDirectExploitation,
			ProposedConfidence: ConfidenceLow, Rationale: "initial hypothesis", CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		if _, err := store.Review(ctx, r.ID, ConfidenceHigh, "reviewer"); err != nil {
			t.Fatalf("Review: %v", err)
		}

		result, err := store.Update(ctx, r.ID, UpdateInput{
			RelationshipType: TypeDirectExploitation, ProposedConfidence: ConfidenceMedium,
			PrimarySource: SourceCISA, Rationale: "confirmed by CISA advisory", UpdatedBy: "bob",
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if result.OldConfidence != ConfidenceLow {
			t.Fatalf("OldConfidence = %q, want %q", result.OldConfidence, ConfidenceLow)
		}
		if result.OldRationale != "initial hypothesis" {
			t.Fatalf("OldRationale = %q, want %q", result.OldRationale, "initial hypothesis")
		}
		if result.Relationship.ProposedConfidence != ConfidenceMedium {
			t.Fatalf("ProposedConfidence = %q, want %q", result.Relationship.ProposedConfidence, ConfidenceMedium)
		}
		if result.Relationship.EffectiveConfidence != ConfidenceHigh {
			t.Fatalf("EffectiveConfidence = %q, want unchanged %q (Update must not touch it)", result.Relationship.EffectiveConfidence, ConfidenceHigh)
		}
		if result.Relationship.Status != StatusActive {
			t.Fatalf("Status = %q, want unchanged %q", result.Relationship.Status, StatusActive)
		}
	})
}

func TestUpdate_MissingID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, err := store.Update(context.Background(), "does-not-exist", UpdateInput{
			RelationshipType: TypeDirectExploitation, ProposedConfidence: ConfidenceMedium, UpdatedBy: "alice",
		})
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("Update missing id error = %v, want pgx.ErrNoRows", err)
		}
	})
}

func TestUpdate_CollidesWithAnotherRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0005")
		store := NewStore(pool)
		ctx := context.Background()

		if _, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0005", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		second, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0005", RelationshipType: TypePostExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("second Create: %v", err)
		}

		_, err = store.Update(ctx, second.ID, UpdateInput{
			RelationshipType: TypeDirectExploitation, ProposedConfidence: ConfidenceMedium, UpdatedBy: "bob",
		})
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("Update collision error = %v, want ErrDuplicate", err)
		}
	})
}

func TestReview_DivergesEffectiveFromProposed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0006")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0006", RelationshipType: TypeDirectExploitation,
			ProposedConfidence: ConfidenceHigh, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		reviewed, err := store.Review(ctx, r.ID, ConfidenceLow, "reviewer-bob")
		if err != nil {
			t.Fatalf("Review: %v", err)
		}
		if reviewed.EffectiveConfidence != ConfidenceLow {
			t.Fatalf("EffectiveConfidence = %q, want %q", reviewed.EffectiveConfidence, ConfidenceLow)
		}
		if reviewed.ProposedConfidence != ConfidenceHigh {
			t.Fatalf("ProposedConfidence = %q, want unchanged %q", reviewed.ProposedConfidence, ConfidenceHigh)
		}
		if reviewed.ReviewedBy != "reviewer-bob" {
			t.Fatalf("ReviewedBy = %q, want %q", reviewed.ReviewedBy, "reviewer-bob")
		}
		if reviewed.LastReviewedAt == nil {
			t.Fatal("expected LastReviewedAt to be set")
		}
	})
}

func TestSetStatus_LifecycleTransitions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0007")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0007", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		for _, status := range []string{StatusDeprecated, StatusDisputed, StatusRetired, StatusActive} {
			updated, err := store.SetStatus(ctx, r.ID, status, "reviewer", "transition to "+status)
			if err != nil {
				t.Fatalf("SetStatus(%s): %v", status, err)
			}
			if updated.Status != status {
				t.Fatalf("Status = %q, want %q", updated.Status, status)
			}
			if updated.StatusChangedBy != "reviewer" {
				t.Fatalf("StatusChangedBy = %q, want %q", updated.StatusChangedBy, "reviewer")
			}
			if updated.StatusChangedAt == nil {
				t.Fatal("expected StatusChangedAt to be set")
			}
			if updated.StatusReason != "transition to "+status {
				t.Fatalf("StatusReason = %q, want %q", updated.StatusReason, "transition to "+status)
			}
		}
	})
}

func TestForTechnique_AllStatusesReturnedNewestFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0008")
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0009")
		store := NewStore(pool)
		ctx := context.Background()

		first, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0008", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("first Create: %v", err)
		}
		second, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0009", RelationshipType: TypeObservedInTheWild, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("second Create: %v", err)
		}
		if _, err := store.SetStatus(ctx, first.ID, StatusRetired, "reviewer", "no longer relevant"); err != nil {
			t.Fatalf("SetStatus: %v", err)
		}

		all, err := store.ForTechnique(ctx, "T1059")
		if err != nil {
			t.Fatalf("ForTechnique: %v", err)
		}
		if len(all) != 2 {
			t.Fatalf("ForTechnique returned %d relationships, want 2 (including retired)", len(all))
		}
		if all[0].ID != second.ID {
			t.Fatalf("ForTechnique[0].ID = %q, want newest (%q) first", all[0].ID, second.ID)
		}
	})
}

func TestGet_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, ok, err := store.Get(context.Background(), "does-not-exist")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if ok {
			t.Fatal("expected ok=false for missing id")
		}
	})
}

func TestIsUniqueViolation(t *testing.T) {
	if isUniqueViolation(errors.New("plain error")) {
		t.Fatal("plain error should not be a unique violation")
	}
	if !isUniqueViolation(fakeSQLStateErr{state: "23505"}) {
		t.Fatal("23505 SQLSTATE should be detected as a unique violation")
	}
	if isUniqueViolation(fakeSQLStateErr{state: "23503"}) {
		t.Fatal("23503 (foreign key violation) should not match unique violation")
	}
}

type fakeSQLStateErr struct{ state string }

func (e fakeSQLStateErr) Error() string    { return "fake: " + e.state }
func (e fakeSQLStateErr) SQLState() string { return e.state }
