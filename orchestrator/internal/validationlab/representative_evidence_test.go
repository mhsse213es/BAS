package validationlab

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
)

// A representative validation that passes must record the profile and its
// coverage in the content_validations evidence, so a subset PASS is never
// mistaken for full validation (spec requirement 5).
func TestResolveIfComplete_RecordsProfileAndCoverageOnPass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		draft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-repr-pass", nonDestructiveArtifact("vl-repr-pass"))
		mustInsertAgent(t, pool, "vl-lab-agent-repr-pass")
		runID := mustInsertScenarioRun(t, pool, "vl-lab-agent-repr-pass", "completed")
		// Dispatch would have stamped the run with profile + coverage.
		if _, err := pool.Exec(ctx,
			`UPDATE scenario_runs SET validation_profile = 'representative',
			   validation_coverage = '{"profile":"representative","total_steps":9,"selected_steps":3,"skipped_steps":6,"techniques_total":3,"techniques_selected":3,"truncated":false}'::jsonb
			 WHERE id = $1`, runID); err != nil {
			t.Fatalf("stamp run with profile/coverage: %v", err)
		}

		o := NewOrchestrator(pool, reg, &fakeDispatcher{runID: runID}, "vl-lab-agent-repr-pass", 0)
		if err := o.runOnce(ctx); err != nil {
			t.Fatalf("runOnce: %v", err)
		}

		assertLifecycle(t, reg, draft, contentregistry.LifecycleValidated)

		var outcome string
		var detailRaw []byte
		if err := pool.QueryRow(ctx,
			`SELECT outcome, detail FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`,
			draft).Scan(&outcome, &detailRaw); err != nil {
			t.Fatalf("read content_validations: %v", err)
		}
		if outcome != "PASS" {
			t.Fatalf("outcome = %s, want PASS", outcome)
		}
		var detail map[string]any
		if err := json.Unmarshal(detailRaw, &detail); err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		if detail["validation_profile"] != "representative" {
			t.Fatalf("detail.validation_profile = %v, want representative (evidence must record the profile)", detail["validation_profile"])
		}
		cov, ok := detail["validation_coverage"].(map[string]any)
		if !ok {
			t.Fatalf("detail.validation_coverage missing or not an object: %v", detail["validation_coverage"])
		}
		if cov["selected_steps"] == nil || cov["total_steps"] == nil || cov["techniques_selected"] == nil {
			t.Fatalf("coverage accounting incomplete in evidence: %v", cov)
		}
	})
}
