package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

func tpeCount(t *testing.T, pool *pgxpool.Pool, versionID, eventType string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tcf_pipeline_events WHERE content_version_id=$1 AND event_type=$2`,
		versionID, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A DRAFT->VALIDATING->VALIDATED transition emits one validation_dispatched and
// one validated_coverage for that version (the SLA coverage stop).
func TestValidatedCoverage_WrittenOnceOnValidatedTransition(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, err := pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		if d := mustIntake(t, r, ctx, file("custom", "id: vc\nname: VC\nart_techniques: [T1082]\n")); !d.Accepted {
			t.Fatal("intake not accepted")
		}
		vid := latest(t, r, "vc").ID

		if err := r.Transition(ctx, vid, LifecycleValidating, ActorValidationLab, "claim"); err != nil {
			t.Fatalf("->VALIDATING: %v", err)
		}
		if err := r.Transition(ctx, vid, LifecycleValidated, ActorValidationLab, "pass"); err != nil {
			t.Fatalf("->VALIDATED: %v", err)
		}

		if n := tpeCount(t, pool, vid, "validation_dispatched"); n != 1 {
			t.Fatalf("validation_dispatched = %d, want 1", n)
		}
		if n := tpeCount(t, pool, vid, "validated_coverage"); n != 1 {
			t.Fatalf("validated_coverage = %d, want 1", n)
		}
	})
}

// Acceptance test 5 (emulates-hole fix): a hand-authored LOCAL version taking
// DRAFT->PUBLISHED_LOCAL emits published_executable but NEVER validated_coverage.
func TestPublishedLocal_NoValidatedCoverage(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, err := pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		if d := mustIntake(t, r, ctx, file("custom", "id: pl\nname: PL\nart_techniques: [T1082]\n")); !d.Accepted {
			t.Fatal("intake not accepted")
		}
		vid := latest(t, r, "pl").ID

		if err := r.Transition(ctx, vid, LifecyclePublishedLocal, "user:op", "approve"); err != nil {
			t.Fatalf("->PUBLISHED_LOCAL: %v", err)
		}
		if n := tpeCount(t, pool, vid, "published_executable"); n != 1 {
			t.Fatalf("published_executable = %d, want 1", n)
		}
		if n := tpeCount(t, pool, vid, "validated_coverage"); n != 0 {
			t.Fatalf("validated_coverage = %d, want 0 (never factory-validated)", n)
		}
	})
}

// Acceptance test 6: validating version A must not produce a validated_coverage
// for version B.
func TestValidatedCoverage_VersionScoped(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, err := pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		if d := mustIntake(t, r, ctx, file("custom", "id: va\nname: VA\nart_techniques: [T1082]\n")); !d.Accepted {
			t.Fatal("intake va")
		}
		if d := mustIntake(t, r, ctx, file("custom", "id: vb\nname: VB\nart_techniques: [T1082]\n")); !d.Accepted {
			t.Fatal("intake vb")
		}
		vidA := latest(t, r, "va").ID
		vidB := latest(t, r, "vb").ID

		if err := r.Transition(ctx, vidA, LifecycleValidating, ActorValidationLab, "claim"); err != nil {
			t.Fatal(err)
		}
		if err := r.Transition(ctx, vidA, LifecycleValidated, ActorValidationLab, "pass"); err != nil {
			t.Fatal(err)
		}
		if n := tpeCount(t, pool, vidA, "validated_coverage"); n != 1 {
			t.Fatalf("A validated_coverage = %d, want 1", n)
		}
		if n := tpeCount(t, pool, vidB, "validated_coverage"); n != 0 {
			t.Fatalf("B validated_coverage = %d, want 0 (version-scoped)", n)
		}
	})
}
