package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/threatidentity"
)

func seedComposeThreat(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	idStore := threatidentity.NewStore(pool)
	resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: name}, threatidentity.ProfileFields{})
	if err != nil {
		t.Fatal(err)
	}
	return resolved.ThreatID
}

func TestCompose_RefusesWhenNoCommonOS(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"linux"}, "test")
		if err != nil {
			t.Fatal(err)
		}

		threatID := seedComposeThreat(t, pool, "APT-compose-noos")
		var countBefore int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countBefore)

		_, _, err = reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected refusal: components share no common supported_os")
		}
		var countAfter int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countAfter)
		if countAfter != countBefore {
			t.Fatalf("expected zero new content_versions rows on refusal, got %d new", countAfter-countBefore)
		}
	})
}

// T1003.002 action_key "hive_save" is confirmed ClassDestructive in
// scenario/execclass.go:86-90 ("reg.exe save of SAM/SYSTEM hives..."). An
// empty action_key defaults to "enumerate" (execclass.go:1088-1095), which
// for most techniques (including this one) resolves NonDestructive -- so
// this test passes a real, non-empty action_key to actually exercise the
// destructive branch.
func TestCompose_RefusesWhenAStepIsDestructive(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1003.002", "destructive", "", "hive_save", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		// Compose requires >=2 components; a second, benign, same-OS
		// component keeps the OS-intersection check from being the thing
		// that refuses this -- this test is about the safety check.
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "benign", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-destructive")

		_, _, err = reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected refusal: a destructive step should fail the safety check")
		}
	})
}

func TestCompose_SucceedsAndRecordsProvenance(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"windows", "linux"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-ok")

		versionID, created, err := reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		if !created {
			t.Fatal("expected created=true for a brand-new composition")
		}

		var origin, lifecycle string
		if err := pool.QueryRow(ctx, `SELECT origin, lifecycle FROM content_versions WHERE id = $1`, versionID).Scan(&origin, &lifecycle); err != nil {
			t.Fatal(err)
		}
		if origin != "LOCAL" || lifecycle != "DRAFT" {
			t.Fatalf("expected origin=LOCAL lifecycle=DRAFT, got origin=%s lifecycle=%s", origin, lifecycle)
		}

		var componentCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_components WHERE content_version_id = $1`, versionID).Scan(&componentCount); err != nil {
			t.Fatal(err)
		}
		if componentCount != 2 {
			t.Fatalf("expected provenance for both components, got %d rows", componentCount)
		}
	})
}

// TestCompose_VisibleViaExistingLoadVersion pins acceptance criterion 5 and
// Review Focus item 5: a composed candidate must be readable through the
// SAME existing registry read path every other content_version uses, with
// no special-casing. LoadVersion (store.go:54) is that existing path.
func TestCompose_VisibleViaExistingLoadVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-visibility")

		versionID, _, err := reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		if _, err := reg.LoadVersion(ctx, versionID); err != nil {
			t.Fatalf("expected composed candidate visible via the existing LoadVersion path, got: %v", err)
		}
	})
}
