package exercise

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedTicketAndWait seeds a running execution whose ticket step already completed (ticket INC7 on connector
// cfg-1) and a wait_for_ticket step watching it.
func seedTicketAndWait(t *testing.T, e *Executor, store *Store, until string, timeoutSecs int) (*Execution, PlanStep) {
	t.Helper()
	ctx := context.Background()
	tkStep := PlanStep{ID: "tk", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{ConnectorID: "cfg-1", Subject: "drill"}}}
	waitStep := PlanStep{ID: "w", Type: StepTypeWaitForTicket, TimeoutSecs: timeoutSecs,
		Config: StepConfig{WaitForTicket: &WaitForTicketConfig{TicketStepID: "tk", Until: until}}}
	ex := seedRunningExecution(t, store, e, []PlanStep{tkStep, waitStep})
	if err := store.SetStepResult(ctx, ex.ID, "tk", map[string]any{"connector_id": "cfg-1", "ticket_id": "INC7", "channel": "ticket"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetStepStatus(ctx, ex.ID, "tk", StepCompleted, ""); err != nil {
		t.Fatal(err)
	}
	// the wait step enters the waiting state, as it would when the executor dispatches it
	se, _ := store.GetStepExecByStepID(ctx, ex.ID, "w")
	st := ex2step(store, ex, "w")
	if err := e.registry.Dispatch(ctx, ex, &st, se); err != nil {
		t.Fatalf("dispatch wait_for_ticket: %v", err)
	}
	return ex, waitStep
}

func newWaitExecutor(pool *pgxpool.Pool, tk *fakeTicketing) (*Executor, *Store) {
	e, store := newTestExecutor(pool)
	e.RegisterBuiltins(nil, nil, nil, nil)
	e.RegisterChannelBuiltins(nil, tk)
	e.RegisterBuiltinTriggers()
	return e, store
}

func checkTrigger(t *testing.T, e *Executor, store *Store, ex *Execution, ps PlanStep) (bool, map[string]any) {
	t.Helper()
	se, _ := store.GetStepExecByStepID(context.Background(), ex.ID, ps.ID)
	fired, payload, err := e.triggerWaitForTicket(context.Background(), ex, &ps, se)
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	return fired, payload
}

func TestWaitForTicket_FiresWhenTheSOCAcknowledgesAndScoresIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		tk := &fakeTicketing{statuses: []string{"open", "open", "in_progress"}}
		e, store := newWaitExecutor(pool, tk)
		ex, ps := seedTicketAndWait(t, e, store, "", 0) // default: acknowledged
		ctx := context.Background()

		if fired, _ := checkTrigger(t, e, store, ex, ps); fired {
			t.Fatal("a ticket still open must not fire the wait")
		}
		if fired, _ := checkTrigger(t, e, store, ex, ps); fired {
			t.Fatal("a ticket still open must not fire the wait")
		}
		if n := evidenceCount(t, store, ex.ID, "soc_acknowledged"); n != 0 {
			t.Fatalf("soc_acknowledged recorded %d times before any acknowledgement", n)
		}
		fired, payload := checkTrigger(t, e, store, ex, ps)
		if !fired || payload["ticket_status"] != "in_progress" {
			t.Fatalf("fired=%v payload=%v, want fired with ticket_status in_progress", fired, payload)
		}
		if n := evidenceCount(t, store, ex.ID, "soc_acknowledged"); n != 1 {
			t.Fatalf("soc_acknowledged recorded %d times, want 1", n)
		}
		score := e.computeScore(ctx, ex)
		if !score.Technical.SOCAcknowledged {
			t.Fatal("the score must show the SOC acknowledged")
		}
	})
}

func TestWaitForTicket_UntilResolvedIgnoresInProgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		tk := &fakeTicketing{statuses: []string{"in_progress", "resolved"}}
		e, store := newWaitExecutor(pool, tk)
		ex, ps := seedTicketAndWait(t, e, store, "resolved", 0)

		if fired, _ := checkTrigger(t, e, store, ex, ps); fired {
			t.Fatal("until=resolved must not fire on in_progress")
		}
		if fired, payload := checkTrigger(t, e, store, ex, ps); !fired || payload["ticket_status"] != "resolved" {
			t.Fatalf("fired=%v payload=%v, want fired on resolved", fired, payload)
		}
	})
}

func TestWaitForTicket_WaitsQuietlyUntilTheTicketStepHasCreatedATicket(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		tk := &fakeTicketing{statuses: []string{"in_progress"}}
		e, store := newWaitExecutor(pool, tk)
		ex, ps := seedTicketAndWait(t, e, store, "", 0)
		// the ticket step is not done yet
		_ = store.SetStepStatus(context.Background(), ex.ID, "tk", StepRunning, "")

		if fired, _ := checkTrigger(t, e, store, ex, ps); fired {
			t.Fatal("must not fire before the ticket exists")
		}
		if tk.statusCall != 0 {
			t.Fatal("must not ask the connector for a status before there is a ticket")
		}
	})
}

func TestWaitForTicket_BadConfigFailsTheStepVisibly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := func(e *Executor, store *Store, step PlanStep, others ...PlanStep) *StepExecution {
			ex := seedRunningExecution(t, store, e, append(others, step))
			se, _ := store.GetStepExecByStepID(ctx, ex.ID, step.ID)
			st := ex2step(store, ex, step.ID)
			if err := e.registry.Dispatch(ctx, ex, &st, se); err != nil {
				t.Fatal(err)
			}
			got, _ := store.GetStepExecByStepID(ctx, ex.ID, step.ID)
			return got
		}
		e, store := newWaitExecutor(pool, &fakeTicketing{})

		if got := run(e, store, PlanStep{ID: "w1", Type: StepTypeWaitForTicket}); got.Status != StepFailed || !strings.Contains(got.Error, "missing wait_for_ticket config") {
			t.Fatalf("no config = %q / %q", got.Status, got.Error)
		}
		if got := run(e, store, PlanStep{ID: "w2", Type: StepTypeWaitForTicket, Config: StepConfig{WaitForTicket: &WaitForTicketConfig{TicketStepID: "nope"}}}); got.Status != StepFailed || !strings.Contains(got.Error, "ticket step") {
			t.Fatalf("unknown ticket step = %q / %q", got.Status, got.Error)
		}
		other := PlanStep{ID: "em", Type: StepTypeWait}
		if got := run(e, store, PlanStep{ID: "w3", Type: StepTypeWaitForTicket, Config: StepConfig{WaitForTicket: &WaitForTicketConfig{TicketStepID: "em"}}}, other); got.Status != StepFailed || !strings.Contains(got.Error, "ticket step") {
			t.Fatalf("a non-ticket step = %q / %q", got.Status, got.Error)
		}
		tk := PlanStep{ID: "tk", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{ConnectorID: "c", Subject: "s"}}}
		if got := run(e, store, PlanStep{ID: "w4", Type: StepTypeWaitForTicket, Config: StepConfig{WaitForTicket: &WaitForTicketConfig{TicketStepID: "tk", Until: "someday"}}}, tk); got.Status != StepFailed || !strings.Contains(got.Error, "until") {
			t.Fatalf("bad until = %q / %q", got.Status, got.Error)
		}
		// ticketing that cannot report status cannot satisfy this step; say so instead of waiting forever
		e2, store2 := newTestExecutor(pool)
		e2.RegisterBuiltins(nil, nil, nil, nil)
		e2.RegisterChannelBuiltins(nil, &fakeTicketNotifier{}) // notifier only: no TicketStatus
		e2.RegisterBuiltinTriggers()
		tk2 := PlanStep{ID: "tk", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{ConnectorID: "c", Subject: "s"}}}
		if got := run(e2, store2, PlanStep{ID: "w5", Type: StepTypeWaitForTicket, Config: StepConfig{WaitForTicket: &WaitForTicketConfig{TicketStepID: "tk"}}}, tk2); got.Status != StepFailed || !strings.Contains(got.Error, "status") {
			t.Fatalf("no status support = %q / %q", got.Status, got.Error)
		}
	})
}

// A SOC that never acknowledges is a real result, not an error: the step completes as timed out and the score
// does not claim an acknowledgement.
func TestWaitForTicket_TimeoutIsAnHonestNegativeResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		tk := &fakeTicketing{statuses: []string{"open"}}
		e, store := newWaitExecutor(pool, tk)
		ex, _ := seedTicketAndWait(t, e, store, "", 60)
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `UPDATE exercise_step_executions SET started_at = NOW() - interval '2 hours' WHERE execution_id=$1 AND step_id='w'`, ex.ID); err != nil {
			t.Fatal(err)
		}

		if err := e.advance(ctx, ex); err != nil {
			t.Fatal(err)
		}
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "w")
		if got.Status != StepCompleted || got.Result["timed_out"] != true {
			t.Fatalf("wait = %q / %v, want completed with timed_out", got.Status, got.Result)
		}
		if n := evidenceCount(t, store, ex.ID, "soc_acknowledged"); n != 0 {
			t.Fatalf("soc_acknowledged recorded %d times for a ticket nobody acknowledged", n)
		}
		if e.computeScore(ctx, ex).Technical.SOCAcknowledged {
			t.Fatal("the score must not claim an acknowledgement that never happened")
		}
	})
}
