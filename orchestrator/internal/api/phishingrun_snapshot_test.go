package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishingrun"
	"github.com/audspect/bas/internal/phishval"
)

func snapTicket(execID string, created bool, at time.Time, ref string) phishbridge.ReportTicketEvidence {
	return phishbridge.ReportTicketEvidence{ExecutionID: execID, TargetID: "target-1", TicketCreated: created, Timestamp: at, TicketRef: ref}
}

func runDET002(t *testing.T, env PhishingRunExecutorEnv, execID string) phishval.Outcome {
	t.Helper()
	out, err := executePHDET002(context.Background(), env, "run-1", map[string]any{"executionId": execID, "targetId": "target-1"})
	if err != nil {
		t.Fatalf("executePHDET002: %v", err)
	}
	return out
}

// A complete search that finds no ticket is a missed-triage finding.
func TestDET002Snapshot_CompleteEmpty_IsMissedTriage(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		env := PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(nil, phishval.CollectionComplete)}
		out := runDET002(t, env, execID)
		if out.Response.Verdict != phishval.VerdictFail {
			t.Errorf("Response.Verdict = %q, want fail: a complete search found no triage ticket", out.Response.Verdict)
		}
		if out.Collection == nil || out.Collection.Completeness != phishval.CollectionComplete {
			t.Errorf("Collection = %+v, want a complete collection record", out.Collection)
		}
	})
}

// An empty result from an incomplete search is never a missed ticket.
func TestDET002Snapshot_IncompleteEmpty_Inconclusive(t *testing.T) {
	for _, c := range []phishval.CollectionCompleteness{phishval.CollectionPartial, phishval.CollectionTruncated} {
		t.Run(string(c), func(t *testing.T) {
			sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
				execID := seedPhishingRunExecution(t, pool)
				env := PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(nil, c)}
				out := runDET002(t, env, execID)
				if out.Response.Verdict == phishval.VerdictFail || out.Response.Verdict == phishval.VerdictPass {
					t.Errorf("%s empty search: Response.Verdict = %q, want inconclusive", c, out.Response.Verdict)
				}
				if out.Collection == nil || out.Collection.Completeness != c {
					t.Errorf("Collection completeness = %+v, want %s", out.Collection, c)
				}
			})
		})
	}
}

// A connector outage or a permission failure is recorded and never graded as absence.
func TestDET002Snapshot_ConnectorFailure_RecordedInconclusive(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		env := PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(nil, phishval.CollectionComplete).
			WithFailure(errors.New("403 forbidden: missing ticket-read permission"))}
		out := runDET002(t, env, execID)
		// The response dimension shows an inconclusive collection as not_tested. Either way
		// it must be neither a pass nor a fail.
		if out.Response.Verdict == phishval.VerdictPass || out.Response.Verdict == phishval.VerdictFail {
			t.Errorf("Response.Verdict = %q, want not graded on a permission failure", out.Response.Verdict)
		}
		if out.Collection == nil || out.Collection.Completeness != phishval.CollectionFailed {
			t.Errorf("Collection = %+v, want a failed collection record", out.Collection)
		}
	})
}

// A matching ticket passes even from an incomplete search, because positive evidence
// is not undone by an unread page.
func TestDET002Snapshot_MatchFromPartialSearch_Passes(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		env := PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(
			[]phishbridge.ReportTicketEvidence{snapTicket(execID, true, anchor.Add(time.Hour), "INC-1")}, phishval.CollectionPartial)}
		out := runDET002(t, env, execID)
		if out.Response.Verdict != phishval.VerdictPass {
			t.Errorf("Response.Verdict = %q, want pass for a matching record", out.Response.Verdict)
		}
	})
}

// A contradicting record is a failure only from a complete search. From an incomplete
// one, an unread page could hold the record that changes the answer.
func TestDET002Snapshot_ContradictingRecord_FailOnlyWhenComplete(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		rec := []phishbridge.ReportTicketEvidence{snapTicket(execID, false, anchor.Add(time.Hour), "")}

		complete := runDET002(t, PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(rec, phishval.CollectionComplete)}, execID)
		if complete.Response.Verdict != phishval.VerdictFail {
			t.Errorf("complete contradicting search: %q, want fail", complete.Response.Verdict)
		}
		partial := runDET002(t, PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(rec, phishval.CollectionPartial)}, execID)
		if partial.Response.Verdict == phishval.VerdictFail {
			t.Errorf("partial contradicting search: %q, must not be a failure", partial.Response.Verdict)
		}
	})
}

// The window is inclusive at both ends. One nanosecond past the end is outside it.
func TestDET002Snapshot_WindowBoundaries(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		end := anchor.Add(detTriageWindow)

		atStart := runDET002(t, PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(
			[]phishbridge.ReportTicketEvidence{snapTicket(execID, true, anchor, "A")}, phishval.CollectionComplete)}, execID)
		if atStart.Response.Verdict != phishval.VerdictPass {
			t.Errorf("ticket at window start: %q, want pass", atStart.Response.Verdict)
		}
		atEnd := runDET002(t, PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(
			[]phishbridge.ReportTicketEvidence{snapTicket(execID, true, end, "B")}, phishval.CollectionComplete)}, execID)
		if atEnd.Response.Verdict != phishval.VerdictPass {
			t.Errorf("ticket at window end: %q, want pass", atEnd.Response.Verdict)
		}
		pastEnd := runDET002(t, PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(
			[]phishbridge.ReportTicketEvidence{snapTicket(execID, true, end.Add(time.Nanosecond), "C")}, phishval.CollectionComplete)}, execID)
		if pastEnd.Response.Verdict != phishval.VerdictFail {
			t.Errorf("ticket 1ns after window end: %q, want fail (outside the window)", pastEnd.Response.Verdict)
		}
	})
}

// Duplicate events for one ticket do not change the answer or the record list.
func TestDET002Snapshot_DuplicateRecords_SameAnswerOneRecordID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		dup := []phishbridge.ReportTicketEvidence{
			snapTicket(execID, true, anchor.Add(time.Hour), "INC-7"),
			snapTicket(execID, true, anchor.Add(time.Hour+time.Minute), "INC-7"),
		}
		out := runDET002(t, PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(dup, phishval.CollectionComplete)}, execID)
		if out.Response.Verdict != phishval.VerdictPass {
			t.Errorf("duplicate matching records: %q, want pass", out.Response.Verdict)
		}
		if out.Collection == nil || len(out.Collection.RecordIDs) != 1 {
			t.Errorf("RecordIDs = %+v, want one distinct ticket", out.Collection)
		}
	})
}

// The record of one run is never rewritten by a later run. Each run keeps its own
// window, collection time, record IDs, and completeness, even when the connector
// returns different data on the second run.
func TestDET002Snapshot_RegradeDoesNotRewriteEarlierRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure schema: %v", err)
		}
		execID := seedPhishingRunExecution(t, pool)
		anchor := executionCreatedAt(t, pool, execID)
		params := map[string]any{"executionId": execID, "targetId": "target-1"}
		req := PhishingRunRequest{ScenarioID: "PH-DET-002", Parameters: params, InitiatedBy: "user-1"}

		first, err := ExecutePhishingRun(ctx, pool, PhishingRunExecutorEnv{Pool: pool,
			ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(
				[]phishbridge.ReportTicketEvidence{snapTicket(execID, true, anchor.Add(time.Hour), "INC-1")}, phishval.CollectionComplete)}, req)
		if err != nil {
			t.Fatalf("first run: %v", err)
		}
		// Later, the connector returns different data for the same execution.
		second, err := ExecutePhishingRun(ctx, pool, PhishingRunExecutorEnv{Pool: pool,
			ReportTicketProvider: phishbridge.NewFixtureSnapshotProvider(nil, phishval.CollectionComplete)}, req)
		if err != nil {
			t.Fatalf("second run: %v", err)
		}

		reloaded, err := db.GetPhishingRun(ctx, pool, first.ID)
		if err != nil {
			t.Fatalf("reload first run: %v", err)
		}
		var kept phishval.Outcome
		if err := json.Unmarshal(reloaded.Result, &kept); err != nil {
			t.Fatalf("decode first run: %v", err)
		}
		if kept.Response.Verdict != phishval.VerdictPass {
			t.Errorf("first run's verdict changed to %q after a later regrade", kept.Response.Verdict)
		}
		if kept.Collection == nil || len(kept.Collection.RecordIDs) != 1 || kept.Collection.RecordIDs[0] != "INC-1" {
			t.Errorf("first run's collection record was rewritten: %+v", kept.Collection)
		}

		var later phishval.Outcome
		reloadedSecond, _ := db.GetPhishingRun(ctx, pool, second.ID)
		if err := json.Unmarshal(reloadedSecond.Result, &later); err != nil {
			t.Fatalf("decode second run: %v", err)
		}
		if later.Response.Verdict != phishval.VerdictFail {
			t.Errorf("second run = %q, want fail (complete search, no ticket)", later.Response.Verdict)
		}
		if first.Status != phishingrun.StatusCompleted || second.Status != phishingrun.StatusCompleted {
			t.Errorf("runs not completed: %q %q", first.Status, second.Status)
		}
	})
}

// A provider that cannot report completeness is treated as Partial. Its absence is
// never a finding.
func TestDET002Snapshot_LegacyProviderIsPartial(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		env := PhishingRunExecutorEnv{Pool: pool, ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(nil)}
		out := runDET002(t, env, execID)
		if out.Response.Verdict == phishval.VerdictFail {
			t.Errorf("legacy empty result: %q, must not be a missed-triage finding", out.Response.Verdict)
		}
		if out.Collection == nil || out.Collection.Completeness != phishval.CollectionPartial {
			t.Errorf("Collection = %+v, want partial", out.Collection)
		}
	})
}
