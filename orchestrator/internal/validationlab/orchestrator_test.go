package validationlab

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func newTestRegistry(t *testing.T, pool *pgxpool.Pool) *contentregistry.Registry {
	t.Helper()
	return contentregistry.New(pool, testutil.DevVerifier())
}

func seedThreat(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx := context.Background()
	var actor, threat string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ($1)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`, name).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, $2) RETURNING id`, actor, name).Scan(&threat); err != nil {
		t.Fatal(err)
	}
	return threat
}

func nonDestructiveArtifact(id string) []byte {
	return []byte("id: " + id + "\nname: N\nsteps:\n  - {name: a, technique_id: T1082, framework: custom, command: x}\n")
}

// destructiveArtifact uses a step (not art_techniques) referencing an
// unknown technique -- safetyVerdict fails closed to "destructive" only
// for steps; a dynamic-only (art_techniques) artifact resolves "unresolved"
// instead (see analyze_test.go's TestAnalyze_DynamicSafetyIsUnresolvedUnlessDestructive).
func destructiveArtifact(id string) []byte {
	return []byte("id: " + id + "\nname: D\nsteps:\n  - {name: a, technique_id: T9999, framework: custom, command: y}\n")
}

// mustCreateDraftVersion creates a DRAFT version via RegisterGenerated
// (created_by = ActorGenerator) when ownerActor is contentregistry.ActorGenerator,
// or directly seeds an operator-authored DRAFT (created_by = ActorIntake)
// otherwise -- the two cases this package's selection logic must distinguish.
func mustCreateDraftVersion(t *testing.T, reg *contentregistry.Registry, pool *pgxpool.Pool, ownerActor, id string, artifact []byte) string {
	t.Helper()
	ctx := context.Background()
	if ownerActor == contentregistry.ActorGenerator {
		thr := seedThreat(t, pool, id)
		vid, _, err := reg.RegisterGenerated(ctx, contentregistry.GeneratedCandidate{
			ContentID: id, Artifact: artifact, ThreatID: thr,
		})
		if err != nil {
			t.Fatalf("RegisterGenerated(%s): %v", id, err)
		}
		return vid
	}
	// Operator/intake-authored content has no generator ownership requirement;
	// seed it directly via the scenarios + content_versions tables the way
	// migration-era rows were written.
	if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, id); err != nil {
		t.Fatalf("seed scenarios row for %s: %v", id, err)
	}
	var vid string
	if err := pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes, trust_level, lifecycle, intake_source, schema_version, created_by)
		VALUES ($1, 'LOCAL', 1, 'n/a-'||$1, octet_length($2::bytea), $2::bytea, 'UNTRUSTED', 'DRAFT', 'custom', 1, $3)
		RETURNING id`, id, artifact, ownerActor).Scan(&vid); err != nil {
		t.Fatalf("seed content_versions row for %s: %v", id, err)
	}
	return vid
}

func assertLifecycle(t *testing.T, reg *contentregistry.Registry, vid string, want contentregistry.Lifecycle) {
	t.Helper()
	v, err := reg.LoadVersion(context.Background(), vid)
	if err != nil {
		t.Fatalf("LoadVersion: %v", err)
	}
	if v.Lifecycle != want {
		t.Fatalf("lifecycle = %s, want %s", v.Lifecycle, want)
	}
}

func TestRunOnce_SelectsOnlyTCFOriginatedDraft(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		generatorDraft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-select-generator", nonDestructiveArtifact("vl-select-generator"))
		operatorDraft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorIntake, "vl-select-operator", nonDestructiveArtifact("vl-select-operator"))

		o := NewOrchestrator(pool, reg, nil, "lab-agent-1", 0)
		if err := o.runOnce(ctx); err != nil {
			t.Fatalf("runOnce: %v", err)
		}

		assertLifecycle(t, reg, generatorDraft, contentregistry.LifecycleValidating)
		assertLifecycle(t, reg, operatorDraft, contentregistry.LifecycleDraft) // untouched
	})
}

func TestRunOnce_SafetyRecheckRefusalReturnsToDraft(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		destructiveDraft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-recheck-refuse", destructiveArtifact("vl-recheck-refuse"))

		o := NewOrchestrator(pool, reg, nil, "lab-agent-1", 0)
		if err := o.runOnce(ctx); err != nil {
			t.Fatalf("runOnce: %v", err)
		}

		assertLifecycle(t, reg, destructiveDraft, contentregistry.LifecycleDraft)

		// STRUCTURAL/STATIC rows are written by createVersion at intake time
		// (unrelated to this orchestrator); only EXECUTION-level rows are
		// this orchestrator's concern, and a safety-recheck refusal must
		// never write one.
		var executionCount int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`, destructiveDraft).Scan(&executionCount)
		if executionCount != 0 {
			t.Fatalf("a safety-recheck refusal must not write an EXECUTION-level content_validations row, got %d", executionCount)
		}
	})
}

type fakeDispatcher struct {
	runID      string
	skipReason string
	err        error
}

func (f *fakeDispatcher) DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (string, string, error) {
	return f.runID, f.skipReason, f.err
}

func mustInsertAgent(t *testing.T, pool *pgxpool.Pool, agentID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, is_factory_lab) VALUES ($1, 'h', true) ON CONFLICT DO NOTHING`, agentID); err != nil {
		t.Fatalf("seed agent %s: %v", agentID, err)
	}
}

func mustInsertScenarioRun(t *testing.T, pool *pgxpool.Pool, agentID, status string) string {
	t.Helper()
	var runID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO scenario_runs (scenario_id, agent_id, status) VALUES ('vl-scenario', $1, $2) RETURNING id`,
		agentID, status).Scan(&runID); err != nil {
		t.Fatalf("seed scenario_run for %s: %v", agentID, err)
	}
	return runID
}

func TestRunOnce_SuccessfulRunTransitionsToValidated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		draft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-success", nonDestructiveArtifact("vl-success"))
		mustInsertAgent(t, pool, "vl-lab-agent-success")
		runID := mustInsertScenarioRun(t, pool, "vl-lab-agent-success", "completed")

		o := NewOrchestrator(pool, reg, &fakeDispatcher{runID: runID}, "vl-lab-agent-success", 0)
		if err := o.runOnce(ctx); err != nil {
			t.Fatalf("runOnce: %v", err)
		}

		assertLifecycle(t, reg, draft, contentregistry.LifecycleValidated)

		var outcome, gotRunID string
		if err := pool.QueryRow(ctx,
			`SELECT outcome, run_id FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`,
			draft).Scan(&outcome, &gotRunID); err != nil {
			t.Fatalf("content_validations row: %v", err)
		}
		if outcome != "PASS" || gotRunID != runID {
			t.Fatalf("got outcome=%s run_id=%s, want PASS/%s", outcome, gotRunID, runID)
		}
	})
}

func TestRunOnce_FailedRunReturnsToDraft(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		draft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-failed", nonDestructiveArtifact("vl-failed"))
		mustInsertAgent(t, pool, "vl-lab-agent-failed")
		runID := mustInsertScenarioRun(t, pool, "vl-lab-agent-failed", "failed")

		o := NewOrchestrator(pool, reg, &fakeDispatcher{runID: runID}, "vl-lab-agent-failed", 0)
		if err := o.runOnce(ctx); err != nil {
			t.Fatalf("runOnce: %v", err)
		}

		assertLifecycle(t, reg, draft, contentregistry.LifecycleDraft)
		var outcome string
		pool.QueryRow(ctx, `SELECT outcome FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`, draft).Scan(&outcome)
		if outcome != "FAIL" {
			t.Fatalf("got outcome=%s, want FAIL", outcome)
		}
	})
}

func TestRunOnce_DispatchFailureRecordsErrorWithNullRunID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		draft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-dispatchfail", nonDestructiveArtifact("vl-dispatchfail"))

		o := NewOrchestrator(pool, reg, &fakeDispatcher{skipReason: "agent busy"}, "vl-lab-agent-dispatchfail", 0)

		if err := o.runOnce(ctx); err != nil {
			t.Fatalf("runOnce: %v", err)
		}

		assertLifecycle(t, reg, draft, contentregistry.LifecycleDraft)
		var outcome string
		var runID *string
		if err := pool.QueryRow(ctx,
			`SELECT outcome, run_id FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`,
			draft).Scan(&outcome, &runID); err != nil {
			t.Fatalf("content_validations row: %v — a dispatch failure must still be honestly recorded against the real CHECK constraint", err)
		}
		if outcome != "ERROR" || runID != nil {
			t.Fatalf("got outcome=%s run_id=%v, want ERROR/nil", outcome, runID)
		}
	})
}

func TestRunOnce_TimeoutReturnsToDraft(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		draft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-timeout", nonDestructiveArtifact("vl-timeout"))
		mustInsertAgent(t, pool, "vl-lab-agent-timeout")
		runID := mustInsertScenarioRun(t, pool, "vl-lab-agent-timeout", "running") // never completes

		o := NewOrchestrator(pool, reg, &fakeDispatcher{runID: runID}, "vl-lab-agent-timeout", 0)
		o.timeout = 50 * time.Millisecond
		o.pollEvery = 10 * time.Millisecond
		if err := o.runOnce(ctx); err != nil {
			t.Fatalf("runOnce: %v", err)
		}

		assertLifecycle(t, reg, draft, contentregistry.LifecycleDraft)
		var outcome string
		pool.QueryRow(ctx, `SELECT outcome FROM content_validations WHERE content_version_id = $1 AND level = 'EXECUTION'`, draft).Scan(&outcome)
		if outcome != "ERROR" {
			t.Fatalf("got outcome=%s, want ERROR", outcome)
		}
	})
}

func TestResolveOrphaned_RecoversAfterSimulatedRestart(t *testing.T) {
	// Simulates a crash: a version is already VALIDATING with a real,
	// already-completed run_id, but no Orchestrator instance in this test
	// ever called runOnce for it -- proving resolution reads only durable
	// state (content_versions.lifecycle + content_validations/scenario_runs),
	// never in-memory tracking of what this process personally dispatched.
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		draft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-orphan", nonDestructiveArtifact("vl-orphan"))
		if err := reg.Transition(ctx, draft, contentregistry.LifecycleValidating, contentregistry.ActorValidationLab, "claimed"); err != nil {
			t.Fatalf("setup transition: %v", err)
		}
		mustInsertAgent(t, pool, "vl-lab-agent-orphan")
		runID := mustInsertScenarioRun(t, pool, "vl-lab-agent-orphan", "completed")

		o := NewOrchestrator(pool, reg, nil, "vl-lab-agent-orphan", 0) // resolveOrphaned never dispatches, so no fake dispatcher is needed here
		o.recordExecutionOutcome(ctx, draft, runID, "NO_DATA", map[string]any{"status": "dispatched"})

		if err := o.resolveOrphaned(ctx); err != nil {
			t.Fatalf("resolveOrphaned: %v", err)
		}
		assertLifecycle(t, reg, draft, contentregistry.LifecycleValidated)
	})
}

func TestRunOnce_ConcurrentClaimOnlyOneWins(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		draft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-concurrent-claim", nonDestructiveArtifact("vl-concurrent-claim"))

		o1 := NewOrchestrator(pool, reg, nil, "lab-agent-1", 0)
		o2 := NewOrchestrator(pool, reg, nil, "lab-agent-1", 0)

		err1 := o1.runOnce(ctx)
		err2 := o2.runOnce(ctx)
		if err1 != nil || err2 != nil {
			t.Fatalf("runOnce errors: %v, %v", err1, err2)
		}
		assertLifecycle(t, reg, draft, contentregistry.LifecycleValidating)
	})
}
