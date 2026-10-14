package contentregistry

import (
	"bytes"
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

// TestCompose_RequiresThreatID mirrors RegisterGenerated's guard
// (generated.go:38-40) -- composition must not silently produce an
// unlinked candidate (final review finding #1).
func TestCompose_RequiresThreatID(t *testing.T) {
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

		_, _, err = reg.Compose(ctx, []string{c1, c2}, "", "admin-test")
		if err == nil {
			t.Fatal("expected Compose to refuse an empty threatID")
		}
	})
}

// TestCompose_RefusesDuplicateComponentIDs (final review finding #2): a
// duplicate id violates content_version_components' PK on the SECOND
// provenance insert, which happens AFTER createVersion has already
// committed the DRAFT row -- leaving a half-provisioned candidate behind
// even though Compose returns an error. The fix rejects duplicates before
// anything is created.
func TestCompose_RefusesDuplicateComponentIDs(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-dup")
		var countBefore int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countBefore)

		_, _, err = reg.Compose(ctx, []string{c1, c1}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected Compose to refuse duplicate component ids")
		}
		var countAfter int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countAfter)
		if countAfter != countBefore {
			t.Fatalf("expected zero new content_versions rows when refusing duplicate ids, got %d new", countAfter-countBefore)
		}
	})
}

// TestCompose_MixesInternalAndExternalComponents (final review finding
// #3): the mixed-kind path -- an internal component promoted from a
// previously-published scenario alongside an external ART/Caldera
// reference -- was never exercised by any Compose() call in the diff.
func TestCompose_MixesInternalAndExternalComponents(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		versionID := seedExecutableVersion(t, pool, "intel-compose-mixed-source", "- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n")
		internalID, err := reg.PromoteInternalComponent(ctx, versionID, 0, "admin-test")
		if err != nil {
			t.Fatalf("PromoteInternalComponent: %v", err)
		}
		externalID, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "external", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-mixed")

		composedID, created, err := reg.Compose(ctx, []string{internalID, externalID}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		if !created {
			t.Fatal("expected created=true")
		}

		var artifact []byte
		if err := pool.QueryRow(ctx, `SELECT artifact_bytes FROM content_versions WHERE id = $1`, composedID).Scan(&artifact); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(artifact, []byte("T1059")) || !bytes.Contains(artifact, []byte("T1053")) {
			t.Fatalf("expected the composed artifact to carry both the internal (T1059) and external (T1053) step, got: %s", artifact)
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

// T1562 (defense-evasion) and T1053 (persistence) are both confirmed
// ClassNonDestructive under the default "enumerate" action_key in
// scenario/execclass.go:813-819,204-210 -- so the existing per-step safety
// check does not refuse this pair on its own; any refusal here is proven to
// come from the new combinatorial check.
func TestCompose_RefusesDefenseEvasionPlusPersistence(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1562", "disable-defenses", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "persist", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-combo-flagged")
		var countBefore int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countBefore)

		_, _, err = reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected Compose to refuse a defense-evasion + persistence combination")
		}
		var countAfter int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countAfter)
		if countAfter != countBefore {
			t.Fatalf("expected zero new content_versions rows on combinatorial refusal, got %d new", countAfter-countBefore)
		}
	})
}

func TestCompose_AllowsDefenseEvasionPlusDiscovery(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1562", "disable-defenses", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1087", "discover", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-combo-unflagged")

		_, created, err := reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("expected defense-evasion + discovery to succeed (not a flagged combination), got: %v", err)
		}
		if !created {
			t.Fatal("expected created=true")
		}
	})
}

// Every technique_id in execclass.go's 130-entry catalog is confirmed
// present in attack_enrichment.json (checked directly against both files),
// so no real technique can pass the existing per-step safety check while
// still being unresolvable to attackdata.Lookup -- a Compose-level test
// cannot isolate the new combinatorial check's own unresolvable-technique
// branch from the pre-existing safety-destructive refusal; that isolated
// proof is TestCombinatorialRisk_RefusesUnresolvableTechnique instead. This
// test only confirms the weaker, still-true end-to-end property: Compose
// refuses an unresolvable technique regardless of which layer causes it.
func TestCompose_StillRefusesUnresolvableTechniqueEndToEnd(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T9999.999", "unresolvable", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "execute", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-combo-unresolvable")

		_, _, err = reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected an unresolvable technique_id to refuse the whole composition")
		}
	})
}

func TestCompose_RecordsCombinatorialVerdictOnSuccess(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1562", "disable-defenses", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1087", "discover", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-combo-verdict")

		versionID, _, err := reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'combinatorial'`,
			versionID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("expected exactly 1 combinatorial verdict row, got %d", count)
		}

		var execclassCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'execclass'`,
			versionID).Scan(&execclassCount); err != nil {
			t.Fatal(err)
		}
		if execclassCount != 1 {
			t.Fatalf("expected the existing execclass verdict row to still be written exactly once, got %d", execclassCount)
		}
	})
}
