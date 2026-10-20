package api

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
)

// A campaign stage bound to the factory-owned lab agent is refused by the same dispatch
// gate single runs use. The gate is server-side and reads is_factory_lab from the agent
// row, so a stage cannot reach the lab agent in any mode but factory-validation.
func TestFactoryLabGate_StageRefusedOnLabAgent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version, state, is_factory_lab)
			VALUES ('fl-agent-1','fl-host','Windows','active',true)
			ON CONFLICT (agent_id) DO UPDATE SET is_factory_lab = true`)
		h := New(pool, nil, scenario.NewEngine(t.TempDir()), testJWTSecret)
		sc := &scenario.Scenario{ID: "credential-access", Name: "credential-access", SupportedOS: []string{"windows"}}

		// The content-registry step is skipped by passing the factory-validation kind. The
		// factory-lab gate below it is the same code for every kind, so it is still exercised.
		runID, skip, err := h.dispatchRun(ctx, sc, "fl-agent-1", dispatchOpts{Mode: "posture", Kind: contentregistry.KindFactoryValidation})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if runID != "" || !strings.Contains(skip, "factory-owned lab agent cannot be dispatched to in mode posture") {
			t.Fatalf("runID=%q skip=%q, want the factory-lab refusal and no run", runID, skip)
		}
	})
}
