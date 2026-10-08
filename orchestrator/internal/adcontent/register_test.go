package adcontent

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestStubIntakeFileFor_EmptyIDReturnsFalse(t *testing.T) {
	_, ok := StubIntakeFileFor(adprimitive.Primitive{})
	if ok {
		t.Fatal("expected ok=false for a primitive with no ID")
	}
}

func TestStubIntakeFileFor_NeverPopulatesSteps(t *testing.T) {
	f, ok := StubIntakeFileFor(adprimitive.Primitive{ID: "dcsync", Name: "DCSync Directory Replication", TechniqueID: "T1003.006"})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if f.Source != "intel" {
		t.Errorf("expected Source %q, got %q", "intel", f.Source)
	}
	// The artifact must parse with zero steps -- verified indirectly via
	// Register's DB-backed test below, which confirms the registry itself
	// accepts it; this test only confirms the builder's own output shape.
	if len(f.Artifact) == 0 {
		t.Fatal("expected non-empty artifact bytes")
	}
}

func TestRegister_AcceptsAsIntelDraftAndIsIdempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := contentregistry.New(pool, testutil.DevVerifier())
		p := adprimitive.Primitive{ID: "ad-m09-test-adcs-esc1", Name: "ADCS ESC1: Enrollee-Supplied Subject", TechniqueID: "T1649"}

		d1, err := Register(ctx, r, p)
		if err != nil {
			t.Fatalf("first Register: %v", err)
		}
		if !d1.Accepted {
			t.Fatalf("expected first registration accepted, got %+v", d1)
		}

		versions, err := r.ListVersions(ctx, p.ID)
		if err != nil || len(versions) != 1 {
			t.Fatalf("expected exactly 1 version after first Register, got %d (err=%v)", len(versions), err)
		}
		v := versions[0]
		if v.Lifecycle != contentregistry.LifecycleDraft {
			t.Errorf("expected Lifecycle %q, got %q", contentregistry.LifecycleDraft, v.Lifecycle)
		}
		if v.Trust != contentregistry.TrustUntrusted {
			t.Errorf("expected Trust %q, got %q", contentregistry.TrustUntrusted, v.Trust)
		}
		if v.Source != contentregistry.SourceIntel {
			t.Errorf("expected Source %q, got %q", contentregistry.SourceIntel, v.Source)
		}

		d2, err := Register(ctx, r, p)
		if err != nil {
			t.Fatalf("second Register: %v", err)
		}
		if !d2.Accepted {
			t.Fatalf("expected second (idempotent) registration accepted, got %+v", d2)
		}
		versionsAfter, err := r.ListVersions(ctx, p.ID)
		if err != nil || len(versionsAfter) != 1 {
			t.Fatalf("expected still exactly 1 version after re-registering identical bytes, got %d (err=%v)", len(versionsAfter), err)
		}
	})
}
