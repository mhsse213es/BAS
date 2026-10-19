package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/phishval"
)

// backdateExecution moves an execution's start back, so its window can be closed.
func backdateExecution(t *testing.T, pool *pgxpool.Pool, execID string, at time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE exercise_executions SET created_at = $2 WHERE id = $1`, execID, at); err != nil {
		t.Fatalf("backdate execution: %v", err)
	}
}

func TestInteractionWindow_DefaultIs72HoursFromStart(t *testing.T) {
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	w, err := interactionWindow(start, map[string]any{})
	if err != nil {
		t.Fatalf("interactionWindow: %v", err)
	}
	if !w.End.Equal(start.Add(72 * time.Hour)) {
		t.Errorf("End = %v, want start+72h", w.End)
	}
}

func TestInteractionWindow_ExpiryInsideMaximumIsUsed(t *testing.T) {
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	exp := start.Add(10 * time.Hour)
	w, err := interactionWindow(start, map[string]any{"expiresAt": exp.Format(time.RFC3339)})
	if err != nil {
		t.Fatalf("interactionWindow: %v", err)
	}
	if !w.End.Equal(exp) {
		t.Errorf("End = %v, want the configured expiry %v", w.End, exp)
	}
}

// An expiry at or before the start, or beyond the 72-hour maximum, is refused.
func TestInteractionWindow_InvalidExpiryRefused(t *testing.T) {
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"before start":   start.Add(-time.Hour),
		"equal to start": start,
		"beyond maximum": start.Add(72*time.Hour + time.Second),
	}
	for name, exp := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := interactionWindow(start, map[string]any{"expiresAt": exp.Format(time.RFC3339)}); err == nil {
				t.Errorf("expiresAt %s was accepted; it must be refused", name)
			}
		})
	}
	if _, err := interactionWindow(start, map[string]any{"expiresAt": "not-a-time"}); err == nil {
		t.Error("a malformed expiresAt was accepted")
	}
}

// Exactly at the 72-hour maximum is allowed.
func TestInteractionWindow_ExactlyMaximumAllowed(t *testing.T) {
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	if _, err := interactionWindow(start, map[string]any{"expiresAt": start.Add(72 * time.Hour).Format(time.RFC3339)}); err != nil {
		t.Errorf("an expiry exactly at the maximum was refused: %v", err)
	}
}

// While the window is still open, "no interaction" is provisional. It is not a final result.
func TestPHID001_OpenWindowNoInteraction_Provisional(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		out, err := executePHID001(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1", map[string]any{"executionId": execID})
		if err != nil {
			t.Fatalf("executePHID001: %v", err)
		}
		if out.UserInteraction.Verdict != phishval.VerdictInconclusive {
			t.Errorf("open window, nothing observed: %q, want inconclusive (not final)", out.UserInteraction.Verdict)
		}
		if !strings.Contains(out.UserInteraction.Reason, "still open") {
			t.Errorf("Reason = %q, want it to say the window is open", out.UserInteraction.Reason)
		}
	})
}

// After the window has closed, "no interaction" is a final observation.
func TestPHID001_ClosedWindowNoInteraction_Final(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		backdateExecution(t, pool, execID, time.Now().UTC().Add(-100*time.Hour))
		out, err := executePHID001(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1", map[string]any{"executionId": execID})
		if err != nil {
			t.Fatalf("executePHID001: %v", err)
		}
		if out.UserInteraction.Verdict != phishval.VerdictNotApplicable {
			t.Errorf("closed window, nothing observed: %q, want a final observation", out.UserInteraction.Verdict)
		}
		if !strings.Contains(out.UserInteraction.Reason, "has closed") {
			t.Errorf("Reason = %q, want it to say the window has closed", out.UserInteraction.Reason)
		}
	})
}

// A regrade reports the same window it reported before. Its end is fixed by the start
// and the expiry, not by when the regrade runs.
func TestPHID001_RegradeKeepsWindow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		env := PhishingRunExecutorEnv{Pool: pool}
		params := map[string]any{"executionId": execID}
		first, err := executePHID001(context.Background(), env, "run-1", params)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		second, err := executePHID001(context.Background(), env, "run-1", params)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if first.Collection == nil || second.Collection == nil ||
			!first.Collection.WindowEnd.Equal(second.Collection.WindowEnd) ||
			!first.Collection.WindowStart.Equal(second.Collection.WindowStart) {
			t.Errorf("window changed between regrades: %+v vs %+v", first.Collection, second.Collection)
		}
	})
}

// The window that was used is retained with the outcome, with its completeness.
func TestPHID001_CollectionRecordRetainsWindowAndCompleteness(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		execID := seedPhishingRunExecution(t, pool)
		out, err := executePHID001(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1", map[string]any{"executionId": execID})
		if err != nil {
			t.Fatalf("executePHID001: %v", err)
		}
		anchor := executionCreatedAt(t, pool, execID)
		if out.Collection == nil || out.Collection.Completeness != phishval.CollectionComplete {
			t.Fatalf("Collection = %+v, want a complete collection record", out.Collection)
		}
		if !out.Collection.WindowStart.Equal(anchor) || !out.Collection.WindowEnd.Equal(anchor.Add(72*time.Hour)) {
			t.Errorf("recorded window %v..%v, want %v..%v", out.Collection.WindowStart, out.Collection.WindowEnd, anchor, anchor.Add(72*time.Hour))
		}
	})
}

// Evidence after a closed window's end does not count toward the observation.
func TestEventsInWindow_ExcludesAfterEndAndBeforeStart(t *testing.T) {
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	end := start.Add(72 * time.Hour)
	w := emailgwefficacy.TimeWindow{Start: start, End: end}
	events := []exercise.Evidence{
		{CreatedAt: start.Add(-time.Second)},
		{CreatedAt: start},
		{CreatedAt: end},
		{CreatedAt: end.Add(time.Nanosecond)},
	}
	got := eventsInWindow(events, w)
	if len(got) != 2 {
		t.Errorf("kept %d events, want 2 (start and end are inclusive)", len(got))
	}
}
