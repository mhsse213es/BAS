package validationlab

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
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

// validation_resulted is emitted for a terminal EXECUTION outcome and NOT for
// the in-flight NO_DATA placeholder (spec §5; Review Focus NO_DATA case).
func TestValidationResulted_TerminalOnlyNotPlaceholder(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := newTestRegistry(t, pool)
		vid := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorIntake, "vr", nonDestructiveArtifact("vr"))
		mustInsertAgent(t, pool, "vl-lab-agent-vr")
		runID := mustInsertScenarioRun(t, pool, "vl-lab-agent-vr", "completed")
		o := &Orchestrator{pool: pool}

		o.recordExecutionOutcome(ctx, vid, runID, "NO_DATA", map[string]any{})
		if n := tpeCount(t, pool, vid, "validation_resulted"); n != 0 {
			t.Fatalf("NO_DATA placeholder emitted %d validation_resulted, want 0", n)
		}

		o.recordExecutionOutcome(ctx, vid, runID, "FAIL", map[string]any{})
		if n := tpeCount(t, pool, vid, "validation_resulted"); n != 1 {
			t.Fatalf("FAIL emitted %d validation_resulted, want 1", n)
		}

		// A terminal result never implies coverage; validated_coverage comes
		// only from the ->VALIDATED transition, which a FAIL never triggers.
		if n := tpeCount(t, pool, vid, "validated_coverage"); n != 0 {
			t.Fatalf("FAIL emitted %d validated_coverage, want 0", n)
		}
	})
}
