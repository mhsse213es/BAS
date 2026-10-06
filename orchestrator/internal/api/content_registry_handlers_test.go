package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/scenario"
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

// driftRun saves a versioned scenario, then inserts a completed content run
// pinned to it with the given raw step_meta.
func driftRun(t *testing.T, pool *pgxpool.Pool, h *Handler, agent, meta string) string {
	t.Helper()
	ctx := context.Background()
	if err := h.engine.SaveAs(ctx, &scenario.Scenario{ID: "dr", Name: "D", Steps: []scenario.Step{
		{Name: "s1", TechniqueID: "T1059", Framework: "custom", Executor: "powershell", Command: "echo 1"}}}, "user:op"); err != nil {
		t.Fatal(err)
	}
	ev, err := h.engine.ResolveExecutable(ctx, "dr")
	if err != nil {
		t.Fatal(err)
	}
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO scenario_runs (scenario_id, agent_id, status, execution_kind, content_version_id, step_meta)
		 VALUES ('dr',$1,'completed','content',$2,$3::jsonb) RETURNING id`, agent, ev.VersionID, meta).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCheckRunDrift_MixedPlatformsAndEmptyMeta(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		seedAgent(t, pool, "dm")
		h := New(pool, ws.NewHub(), e, "")
		ctx := context.Background()

		id := driftRun(t, pool, h, "dm", `{"a":{"platform":"windows","resolvedSha256":"x"},"b":{"platform":"linux","resolvedSha256":"y"}}`)
		rep, err := h.checkRunDrift(ctx, id)
		if err != nil || rep.Status != "checked" || rep.Reason != "mixed dispatch platforms" || len(rep.Items) != 2 {
			t.Fatalf("mixed: %+v err=%v", rep, err)
		}
		for _, it := range rep.Items {
			if it.Status != "DRIFT_UNKNOWN" {
				t.Fatalf("mixed item: %+v", it)
			}
		}

		// No recorded platform and an agent whose OS cannot be classified.
		if _, err := pool.Exec(ctx, `UPDATE agents SET os_version='plan9' WHERE agent_id='dm'`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE scenario_runs SET step_meta='{"a":{"resolvedSha256":"x"}}' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		rep, err = h.checkRunDrift(ctx, id)
		if err != nil || rep.Reason != "dispatch platform unknown" || len(rep.Items) != 1 || rep.Items[0].Status != "DRIFT_UNKNOWN" {
			t.Fatalf("unknown platform: %+v err=%v", rep, err)
		}

		// Empty step_meta must never read as "nothing drifted".
		for _, set := range []string{`'{}'::jsonb`, `'null'::jsonb`} {
			if _, err := pool.Exec(ctx, `UPDATE scenario_runs SET step_meta=`+set+` WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
			rep, err = h.checkRunDrift(ctx, id)
			if err != nil || rep.Status != "checked" || rep.Reason != "no step metadata recorded" || len(rep.Items) != 0 {
				t.Fatalf("empty meta %s: %+v err=%v", set, rep, err)
			}
		}

		// ART components without a configured store is an error, not drift.
		if _, err := pool.Exec(ctx, `UPDATE scenario_runs SET step_meta='{"a":{"component":"art","platform":"windows","resolvedSha256":"x"}}' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := h.checkRunDrift(ctx, id); err == nil {
			t.Fatal("want error for ART steps with no ART store")
		}
	})
}

func TestDispatchRun_StampsDispatchPlatformOnExplicitSteps(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		ctx := context.Background()
		if err := e.SaveAs(ctx, &scenario.Scenario{ID: "plat", Name: "P", Steps: []scenario.Step{
			{Name: "s1", TechniqueID: "T1059", Framework: "custom", Executor: "bash", Command: "echo 1"}}}, "user:op"); err != nil {
			t.Fatal(err)
		}
		seedAgent(t, pool, "pl")
		if _, err := pool.Exec(ctx, `UPDATE agents SET os_version='Ubuntu 22.04 Linux' WHERE agent_id='pl'`); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), e, "")
		sc, _ := e.Get("plat")
		_, _, _ = h.dispatchRun(ctx, sc, "pl", dispatchOpts{}) // agent offline: row + step_meta still written
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT step_meta FROM scenario_runs WHERE scenario_id='plat'`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		meta := map[string]scenario.StepMeta{}
		if err := json.Unmarshal(raw, &meta); err != nil || len(meta) == 0 {
			t.Fatalf("step_meta %s err=%v", raw, err)
		}
		for id, m := range meta {
			if m.Platform != "linux" {
				t.Fatalf("%s platform=%q want linux", id, m.Platform)
			}
		}
	})
}
