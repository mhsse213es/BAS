package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCheckRunDrift_SyntheticLegacyAndMissing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		seedAgent(t, pool, "da")
		h := New(pool, ws.NewHub(), e, "")
		ctx := context.Background()
		var synth, legacy string
		// Completed runs: a unique index allows only one running run per agent.
		if err := pool.QueryRow(ctx,
			`INSERT INTO scenario_runs (scenario_id, agent_id, status, execution_kind) VALUES ('x','da','completed','remediation') RETURNING id`).Scan(&synth); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO scenario_runs (scenario_id, agent_id, status, execution_kind) VALUES ('old','da','completed','legacy') RETURNING id`).Scan(&legacy); err != nil {
			t.Fatal(err)
		}
		if rep, err := h.checkRunDrift(ctx, synth); err != nil || rep.Status != "not_applicable" || len(rep.Items) != 0 {
			t.Fatalf("synthetic: %+v err=%v", rep, err)
		}
		if rep, err := h.checkRunDrift(ctx, legacy); err != nil || rep.Status != "unversioned" {
			t.Fatalf("legacy: %+v err=%v", rep, err)
		}
		// A run that does not exist is a permanent (no-rows) unreadable.
		if rep, err := h.checkRunDrift(ctx, "00000000-0000-0000-0000-000000000000"); err != nil || rep.Status != "unreadable" {
			t.Fatalf("missing run: %+v err=%v", rep, err)
		}
	})
}
