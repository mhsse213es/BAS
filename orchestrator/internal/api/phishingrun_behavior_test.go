package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishval"
)

// executionCreatedAt reads the persisted creation time the window is anchored to.
func executionCreatedAt(t *testing.T, pool *pgxpool.Pool, execID string) time.Time {
	t.Helper()
	ex, err := exercise.NewStore(pool).GetExecution(context.Background(), execID)
	if err != nil {
		t.Fatalf("GetExecution %s: %v", execID, err)
	}
	return ex.CreatedAt
}

func detTicket(execID string, created bool, at time.Time) phishbridge.ReportTicketEvidence {
	return phishbridge.ReportTicketEvidence{ExecutionID: execID, TargetID: "target-1", TicketCreated: created, Timestamp: at}
}

// A ticket inside the 24 hours after execution is found. A ticket dated in the
// future, relative to the check, is still found. The old check-time window
// excluded it.
func TestExecutePHDET002_TicketInWindowAfterExecution_Found(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		env := PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(
			[]phishbridge.ReportTicketEvidence{detTicket(execID, true, anchor.Add(time.Hour))})}

		outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": execID, "targetId": "target-1"})
		if err != nil {
			t.Fatalf("executePHDET002: %v", err)
		}
		if outcome.Response.Verdict != phishval.VerdictPass {
			t.Errorf("Response.Verdict = %q, want %q for a ticket inside the window", outcome.Response.Verdict, phishval.VerdictPass)
		}
		if !strings.Contains(outcome.Response.Reason, "anchored to execution creation") {
			t.Errorf("Reason = %q, want the anchored window recorded", outcome.Response.Reason)
		}
	})
}

// Only tickets outside the window, before or after it, leave the result
// inconclusive. A missing ticket is not proof that triage failed.
func TestExecutePHDET002_TicketsOutsideWindow_Inconclusive(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		env := PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(
			[]phishbridge.ReportTicketEvidence{
				detTicket(execID, true, anchor.Add(-time.Hour)),
				detTicket(execID, true, anchor.Add(25*time.Hour)),
			})}

		outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": execID, "targetId": "target-1"})
		if err != nil {
			t.Fatalf("executePHDET002: %v", err)
		}
		if outcome.Response.Verdict == phishval.VerdictPass || outcome.Response.Verdict == phishval.VerdictFail {
			t.Errorf("Response.Verdict = %q, want inconclusive when no ticket is inside the window", outcome.Response.Verdict)
		}
	})
}

// Regrading the same execution against the same evidence gives the same result,
// including the window and the response timestamp. Neither depends on when the check runs.
func TestExecutePHDET002_RegradeIsStable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		env := PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(
			[]phishbridge.ReportTicketEvidence{detTicket(execID, true, anchor.Add(time.Hour))})}
		params := map[string]any{"executionId": execID, "targetId": "target-1"}

		first, err := executePHDET002(context.Background(), env, "run-1", params)
		if err != nil {
			t.Fatalf("first grade: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		second, err := executePHDET002(context.Background(), env, "run-1", params)
		if err != nil {
			t.Fatalf("second grade: %v", err)
		}
		if first.Response.Verdict != second.Response.Verdict || first.Response.Reason != second.Response.Reason {
			t.Errorf("regrade differs: %+v vs %+v", first.Response, second.Response)
		}
		if first.Observation.Response == nil || second.Observation.Response == nil ||
			!first.Observation.Response.Timestamp.Equal(second.Observation.Response.Timestamp) {
			t.Error("response timestamp changed between regrades; it must be the execution anchor")
		}
	})
}

// With no ITSM connector configured the result is inconclusive, never a missed ticket.
func TestExecutePHDET002_NoConnector_InconclusiveNotFail(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		env := PhishingRunExecutorEnv{Pool: pool}
		outcome, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": execID, "targetId": "target-1"})
		if err != nil {
			t.Fatalf("executePHDET002: %v", err)
		}
		if outcome.Response.Verdict == phishval.VerdictFail || outcome.Response.Verdict == phishval.VerdictPass {
			t.Errorf("Response.Verdict = %q, want not-tested without a connector", outcome.Response.Verdict)
		}
	})
}

// An observed click is reported as behavior. It is not a pass or fail of an identity control.
func TestExecutePHID001_ClickReportedAsBehavior_NotControlVerdict(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		chain := exercise.NewEvidenceChain(exercise.NewStore(pool))
		if _, err := chain.Append(context.Background(), execID, "", "link_clicked", "target-1", "test", nil); err != nil {
			t.Fatalf("Append evidence: %v", err)
		}
		outcome, err := executePHID001(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1", map[string]any{"executionId": execID})
		if err != nil {
			t.Fatalf("executePHID001: %v", err)
		}
		if outcome.UserInteraction.Verdict != phishval.VerdictNotApplicable {
			t.Errorf("UserInteraction.Verdict = %q, want %q: behavior is not a control verdict", outcome.UserInteraction.Verdict, phishval.VerdictNotApplicable)
		}
		if outcome.Observation.UserInteraction == nil || outcome.Observation.UserInteraction.Outcome != phishval.InteractionClicked {
			t.Errorf("observed outcome = %+v, want clicked", outcome.Observation.UserInteraction)
		}
		if !strings.Contains(outcome.UserInteraction.Reason, "not a control-efficacy verdict") {
			t.Errorf("Reason = %q, want it to state this is behavioral evidence", outcome.UserInteraction.Reason)
		}
	})
}

// No tracked interaction is reported as "not observed", not as a failed control. Its
// timestamp is the execution's creation, so a regrade gives the same observation.
func TestExecutePHID001_NoInteraction_NotObservedNotFail(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		env := PhishingRunExecutorEnv{Pool: pool}

		first, err := executePHID001(context.Background(), env, "run-1", map[string]any{"executionId": execID})
		if err != nil {
			t.Fatalf("executePHID001: %v", err)
		}
		if first.UserInteraction.Verdict == phishval.VerdictFail || first.UserInteraction.Verdict == phishval.VerdictPass {
			t.Errorf("UserInteraction.Verdict = %q, want no control pass or fail for behavior", first.UserInteraction.Verdict)
		}
		if first.Observation.UserInteraction == nil || first.Observation.UserInteraction.Outcome != phishval.InteractionNone {
			t.Fatalf("observed outcome = %+v, want no_interaction", first.Observation.UserInteraction)
		}
		if !first.Observation.UserInteraction.Timestamp.Equal(anchor) {
			t.Errorf("timestamp = %v, want the execution creation %v, not the check time", first.Observation.UserInteraction.Timestamp, anchor)
		}
		second, err := executePHID001(context.Background(), env, "run-1", map[string]any{"executionId": execID})
		if err != nil {
			t.Fatalf("regrade: %v", err)
		}
		if first.UserInteraction.Reason != second.UserInteraction.Reason {
			t.Errorf("regrade reason differs: %q vs %q", first.UserInteraction.Reason, second.UserInteraction.Reason)
		}
	})
}
