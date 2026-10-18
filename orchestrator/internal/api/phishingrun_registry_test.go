package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishval"
)

// seedPhishingRunExecution creates a minimal plan+execution, mirroring
// internal/exercise's own (package-private) seedExecution helper --
// exercise_evidence.execution_id is FK-constrained to
// exercise_executions(id), which is itself FK-constrained to
// exercise_plans(id), so a real evidence round-trip needs both ancestors.
func seedPhishingRunExecution(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	store := exercise.NewStore(pool)
	p := &exercise.Plan{Name: "seed", Steps: []exercise.PlanStep{{ID: "a", Type: exercise.StepTypeNotify}}}
	if err := store.CreatePlan(ctx, p); err != nil {
		t.Fatalf("seedPhishingRunExecution CreatePlan: %v", err)
	}
	ex := &exercise.Execution{PlanID: p.ID, Name: "seed", Status: exercise.ExecRunning}
	if err := store.CreateExecution(ctx, ex); err != nil {
		t.Fatalf("seedPhishingRunExecution CreateExecution: %v", err)
	}
	return ex.ID
}

func TestLookupPhishingRunExecutor_PHDET002Registered(t *testing.T) {
	_, ok := LookupPhishingRunExecutor("PH-DET-002")
	if !ok {
		t.Fatal("PH-DET-002 must be registered as executable")
	}
}

func TestLookupPhishingRunExecutor_UnregisteredCatalogScenario_NotFound(t *testing.T) {
	// PH-BEC-002 is a real, adapter-tested catalog scenario with no
	// executor wired yet -- it must not appear executable merely
	// because it exists in phishcatalog.
	_, ok := LookupPhishingRunExecutor("PH-BEC-002")
	if ok {
		t.Fatal("PH-BEC-002 must not be executable yet")
	}
}

func TestLookupPhishingRunExecutor_PHID001Registered(t *testing.T) {
	_, ok := LookupPhishingRunExecutor("PH-ID-001")
	if !ok {
		t.Fatal("PH-ID-001 must be registered as executable")
	}
}

func TestExecutePHID001_ClickEvidenceRecorded_Pass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		chain := exercise.NewEvidenceChain(exercise.NewStore(pool))
		if _, err := chain.Append(context.Background(), execID, "", "link_clicked", "target-1", "test", nil); err != nil {
			t.Fatalf("Append evidence: %v", err)
		}

		env := PhishingRunExecutorEnv{Pool: pool}
		outcome, err := executePHID001(context.Background(), env, "run-1", map[string]any{"executionId": execID})
		if err != nil {
			t.Fatalf("executePHID001: %v", err)
		}
		if outcome.UserInteraction.Verdict != phishval.VerdictPass {
			t.Errorf("UserInteraction.Verdict = %q, want %q", outcome.UserInteraction.Verdict, phishval.VerdictPass)
		}
	})
}

// TestExecutePHID001_RealExecutionNoEvidence_Fail proves the
// deliberate, documented semantics of FromExerciseInteractionEvidence:
// for an execution that genuinely exists, ListEvidence is
// authoritative, so zero evidence rows is a real, evidenced
// InteractionNone -- the target was tracked and never clicked -- not
// an "unknown" NotTested case. Expectation is InteractionClicked, so
// an evidenced None correctly contradicts it (Fail), never Pass.
func TestExecutePHID001_RealExecutionNoEvidence_Fail(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)

		env := PhishingRunExecutorEnv{Pool: pool}
		outcome, err := executePHID001(context.Background(), env, "run-1", map[string]any{"executionId": execID})
		if err != nil {
			t.Fatalf("executePHID001: %v", err)
		}
		if outcome.UserInteraction.Verdict != phishval.VerdictFail {
			t.Errorf("UserInteraction.Verdict = %q, want %q (a real execution's own authoritative absence of evidence is a genuine negative, not NotTested)", outcome.UserInteraction.Verdict, phishval.VerdictFail)
		}
	})
}

func TestExecutePHID001_MissingExecutionID_Error(t *testing.T) {
	env := PhishingRunExecutorEnv{Pool: nil}
	_, err := executePHID001(context.Background(), env, "run-1", map[string]any{})
	if err == nil {
		t.Fatal("want an error for a missing executionId parameter")
	}
}

// TestExecutePHID001_UnknownExecutionID_ErrorNeverFabricatesFail proves
// a typo'd/nonexistent execution ID errors out rather than silently
// grading as a confident Fail (which zero real evidence correctly
// would for an execution that actually ran -- see the sibling test
// above). Without this existence check, "we don't know this
// execution" and "we know it and nothing happened" would be
// indistinguishable, fabricating a verdict for something that never ran.
func TestExecutePHID001_UnknownExecutionID_ErrorNeverFabricatesFail(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		env := PhishingRunExecutorEnv{Pool: pool}
		_, err := executePHID001(context.Background(), env, "run-1", map[string]any{"executionId": "does-not-exist"})
		if err == nil {
			t.Fatal("want an error for an unknown executionId, not a silently-graded verdict")
		}
	})
}

func TestExecutePHDET002_TicketCreated_Pass(t *testing.T) {
	env := PhishingRunExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
		ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: true, Timestamp: time.Now(),
	}})}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictPass)
	}
}

func TestExecutePHDET002_NoEvidence_NotTested(t *testing.T) {
	env := PhishingRunExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(nil)}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (absent evidence must never become Pass or Fail)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}

// TestExecutePHDET002_NilProvider_NotTestedNeverPanics proves the
// as-shipped, unconfigured-by-default production path (Handler.New
// without a WithPhishingRun call -- confirmed via grep that
// cmd/server/main.go never calls it) degrades to NotTested exactly
// like "provider configured but found no evidence," never a panic on
// a nil-interface method call.
func TestExecutePHDET002_NilProvider_NotTestedNeverPanics(t *testing.T) {
	env := PhishingRunExecutorEnv{ReportTicketProvider: nil}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (an unconfigured provider must never panic or fabricate a verdict)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}

func TestExecutePHDET002_TicketNotCreated_Fail(t *testing.T) {
	env := PhishingRunExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
		ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: false, Timestamp: time.Now(),
	}})}
	outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": "exec-1", "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}
