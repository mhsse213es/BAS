package api

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// A factory-validation dispatch must bound a large scenario to a deterministic
// representative subset (one step per technique by default) and record honest
// coverage on the run -- never dispatch the full expansion, never claim it did.
func TestDispatchRun_RepresentativeProfileBoundsAndRecordsCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// 3 techniques x 3 custom steps each = 9 expanded steps.
		var steps []scenario.Step
		for _, tech := range []string{"T1001", "T1002", "T1003"} {
			for i := 1; i <= 3; i++ {
				steps = append(steps, scenario.Step{
					Name: tech + "-" + strconv.Itoa(i), TechniqueID: tech,
					Framework: "custom", Command: "echo " + tech,
				})
			}
		}
		sc, engine := minimalLiveScenario(t, "dr-representative", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-representative"
		seedActiveAgent(t, pool, agentID, "Windows")
		if _, err := pool.Exec(ctx, `UPDATE agents SET is_factory_lab = true WHERE agent_id = $1`, agentID); err != nil {
			t.Fatalf("mark lab agent: %v", err)
		}
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runID, skip, err := h.DispatchFactoryValidation(ctx, sc, agentID)
		if err != nil || skip != "" {
			t.Fatalf("factory-validation dispatch: skip=%q err=%v", skip, err)
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode scenario command: %v", err)
		}
		// Default limits are PerTechnique=1 -> one representative step per
		// technique -> 3 dispatched, bounded down from the full 9.
		if len(cmd.Steps) != 3 {
			t.Fatalf("dispatched %d steps, want 3 (one representative per technique, bounded from 9)", len(cmd.Steps))
		}

		var profile string
		var covRaw []byte
		if err := pool.QueryRow(ctx,
			`SELECT validation_profile, validation_coverage FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&profile, &covRaw); err != nil {
			t.Fatalf("read validation profile/coverage: %v", err)
		}
		if profile != "representative" {
			t.Fatalf("validation_profile = %q, want representative", profile)
		}
		var cov scenario.ValidationCoverage
		if err := json.Unmarshal(covRaw, &cov); err != nil {
			t.Fatalf("decode coverage: %v", err)
		}
		if cov.TotalSteps != 9 || cov.SelectedSteps != 3 || cov.TechniquesSelected != 3 {
			t.Fatalf("coverage = %+v, want total=9 selected=3 techniques_selected=3", cov)
		}
		// Honesty: a representative subset is strictly smaller than the whole.
		if cov.SelectedSteps >= cov.TotalSteps {
			t.Fatalf("representative selection must be a strict subset: selected %d of %d", cov.SelectedSteps, cov.TotalSteps)
		}
	})
}
