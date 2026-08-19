package verifysync

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/verification"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

type fakeResolver struct {
	sc  *scenario.Scenario
	exp map[string][]scenario.ExpectedDetection
}

func (f fakeResolver) Get(id string) (*scenario.Scenario, bool) {
	if f.sc == nil || f.sc.ID != id {
		return nil, false
	}
	return f.sc, true
}

func (f fakeResolver) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	return f.exp[step.TechniqueID], nil
}

func endpointExp(id, provider string) scenario.ExpectedDetection {
	return scenario.ExpectedDetection{
		ID: id, Provider: provider, Type: scenario.DomainEndpoint,
		Confidence: scenario.ConfidenceRequired,
	}
}

func TestProcessRun_NeverOverwritesExistingRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := verification.NewStore(pool)

		// exp-manual already has a human-reviewed record — must survive untouched.
		if _, err := store.Attest(ctx, verification.AttestInput{
			RunID: "run-1", ExpectationID: "exp-manual", VerifiedBy: "analyst",
			Result: verification.ResultNotDetected, WorkflowState: verification.StateApproved,
			Source: verification.SourceManual,
		}); err != nil {
			t.Fatalf("seed manual attestation: %v", err)
		}

		resolver := fakeResolver{
			sc: &scenario.Scenario{ID: "sc-1", Steps: []scenario.Step{
				{TechniqueID: "T1055"}, {TechniqueID: "T1003"},
			}},
			exp: map[string][]scenario.ExpectedDetection{
				"T1055": {endpointExp("exp-manual", "microsoft_defender")},
				"T1003": {endpointExp("exp-auto", "microsoft_defender")},
			},
		}

		job := NewJob(pool, store, resolver)
		resultsRaw := []byte(`[{"id":"T1055","detectionVerdict":"undetected"},{"id":"T1003","detectionVerdict":"detected","detectionAlert":{"provider":"Microsoft Defender","channel":"c","eventId":1,"confidence":"high"}}]`)
		if err := job.processRun(ctx, "run-1", "sc-1", resultsRaw); err != nil {
			t.Fatalf("processRun: %v", err)
		}

		current, err := store.CurrentForRun(ctx, "run-1")
		if err != nil {
			t.Fatalf("CurrentForRun: %v", err)
		}

		manual := current["exp-manual"]
		if manual.Source != verification.SourceManual || manual.Result != verification.ResultNotDetected {
			t.Fatalf("exp-manual record was overwritten: %+v, want untouched manual/NotDetected", manual)
		}

		auto := current["exp-auto"]
		if auto.Source != verification.SourceAutomatic || auto.Result != verification.ResultDetected {
			t.Fatalf("exp-auto = %+v, want new automatic/Detected record", auto)
		}
	})
}

func TestProcessRun_ZeroExpectations_NoError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := verification.NewStore(pool)
		resolver := fakeResolver{sc: &scenario.Scenario{ID: "sc-empty", Steps: []scenario.Step{{TechniqueID: "T9999"}}}}
		job := NewJob(pool, store, resolver)
		if err := job.processRun(context.Background(), "run-empty", "sc-empty", nil); err != nil {
			t.Fatalf("processRun with zero expectations: %v", err)
		}
	})
}

func TestTick_MarksProcessedRunsAutoVerified(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// scenario_runs.agent_id has a NOT NULL FK to agents(agent_id) —
		// seed an agent row first (mirrors internal/pathcorrelation's and
		// internal/exposure's existing test pattern for this exact table).
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			 VALUES ('vs-tick-agent', 'VSHOST01', '10.0.0.5', 'Windows 11', 'idle', 'active', NOW())`); err != nil {
			t.Fatalf("seed agents: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, agent_id, scenario_id, name, status, results, started_at)
			 VALUES ('run-tick-1', 'vs-tick-agent', 'sc-tick', 'n', 'completed', '[]', NOW())`); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}
		store := verification.NewStore(pool)
		resolver := fakeResolver{sc: &scenario.Scenario{ID: "sc-tick", Steps: nil}}
		job := NewJob(pool, store, resolver)
		job.Tick(ctx)

		var autoVerified bool
		if err := pool.QueryRow(ctx, `SELECT auto_verified FROM scenario_runs WHERE id='run-tick-1'`).Scan(&autoVerified); err != nil {
			t.Fatalf("query auto_verified: %v", err)
		}
		if !autoVerified {
			t.Fatal("auto_verified = false after Tick, want true")
		}
	})
}

var _ reporting.ScenarioResolver = fakeResolver{}

func TestAnnotateSinkReceipts_SetsObservedOnlyForIssuedTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := verification.NewStore(pool)
		job := NewJob(pool, store, fakeResolver{})

		// T1567: token issued AND received -> want true.
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
			 VALUES ('tok-received', 'run-sink-annotate', 'T1567', NOW() + interval '10 minutes')`); err != nil {
			t.Fatalf("seed dlp_sink_tokens (received): %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_receipts (token, payload_hash, payload_size, channel)
			 VALUES ('tok-received', 'deadbeef', 42, 'https-post')`); err != nil {
			t.Fatalf("seed dlp_sink_receipts: %v", err)
		}

		// T1052.001: token issued, never received -> want false.
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
			 VALUES ('tok-not-received', 'run-sink-annotate', 'T1052.001', NOW() + interval '10 minutes')`); err != nil {
			t.Fatalf("seed dlp_sink_tokens (not received): %v", err)
		}

		// T1115: no token issued at all -> want nil (untouched).
		results := []models.SimulationResult{
			{ID: "T1567"},
			{ID: "T1052.001"},
			{ID: "T1115"},
		}

		if err := job.annotateSinkReceipts(ctx, "run-sink-annotate", results); err != nil {
			t.Fatalf("annotateSinkReceipts: %v", err)
		}

		if results[0].SinkTokenObserved == nil || !*results[0].SinkTokenObserved {
			t.Errorf("T1567 SinkTokenObserved = %v, want true", results[0].SinkTokenObserved)
		}
		if results[1].SinkTokenObserved == nil || *results[1].SinkTokenObserved {
			t.Errorf("T1052.001 SinkTokenObserved = %v, want false", results[1].SinkTokenObserved)
		}
		if results[2].SinkTokenObserved != nil {
			t.Errorf("T1115 SinkTokenObserved = %v, want nil (no token was ever issued for this technique)", *results[2].SinkTokenObserved)
		}
	})
}
