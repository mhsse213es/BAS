package iocregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegisterGenerated_CreatesIOCAndSighting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if err := RegisterGenerated(context.Background(), pool, TypeFilename, "explorer_update_ab12.exe", "sc-1", "run-1", "agent-1", "T1027"); err != nil {
			t.Fatalf("RegisterGenerated: %v", err)
		}

		var source, origin, status string
		if err := pool.QueryRow(context.Background(),
			`SELECT source, origin, status FROM iocs WHERE type = 'filename' AND value = 'explorer_update_ab12.exe'`).
			Scan(&source, &origin, &status); err != nil {
			t.Fatalf("query iocs: %v", err)
		}
		if source != "variant" || origin != "generated" || status != "generated" {
			t.Errorf("source/origin/status = %q/%q/%q, want variant/generated/generated", source, origin, status)
		}

		var sightingScenario, sightingRun, sightingAgent, sightingTechnique string
		if err := pool.QueryRow(context.Background(), `
			SELECT s.scenario_id, s.run_id, s.agent_id, s.technique_id FROM ioc_sightings s
			JOIN iocs i ON i.id = s.ioc_id WHERE i.value = 'explorer_update_ab12.exe'`).
			Scan(&sightingScenario, &sightingRun, &sightingAgent, &sightingTechnique); err != nil {
			t.Fatalf("query sighting: %v", err)
		}
		if sightingScenario != "sc-1" || sightingRun != "run-1" || sightingAgent != "agent-1" || sightingTechnique != "T1027" {
			t.Errorf("sighting = %q/%q/%q/%q, want sc-1/run-1/agent-1/T1027", sightingScenario, sightingRun, sightingAgent, sightingTechnique)
		}
	})
}
