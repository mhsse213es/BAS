package exercise

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The score's TicketCreated means the DEFENDERS raised a ticket. A ticket the exercise injects itself is not
// that signal: counting it would make an exercise that only injected a ticket look measurable, with a defender
// signal nobody produced.
func TestTicketStep_InjectedTicketIsNotADefenderSignal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.RegisterBuiltins(nil, nil, nil, nil)
		e.RegisterChannelBuiltins(nil, &fakeTicketNotifier{result: map[string]any{"channel": "ticket", "ticket_id": "INC1"}})
		ctx := context.Background()

		step := PlanStep{ID: "t", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{ConnectorID: "c", Subject: "drill"}}}
		ex := seedRunningExecution(t, store, e, []PlanStep{step})
		se, _ := store.GetStepExecByStepID(ctx, ex.ID, "t")
		st := ex2step(store, ex, "t")
		if err := e.registry.Dispatch(ctx, ex, &st, se); err != nil {
			t.Fatal(err)
		}
		// The handler marks the step completed first and appends its evidence just after, so wait for the
		// evidence itself; scoring before it exists would pass this test without ever seeing the bug.
		sawEvidence := false
		for i := 0; i < 100 && !sawEvidence; i++ {
			counts, _ := store.CountEvidenceByType(ctx, ex.ID)
			for _, n := range counts {
				if n > 0 {
					sawEvidence = true
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !sawEvidence {
			t.Fatal("the ticket step recorded no evidence")
		}

		score := e.computeScore(ctx, ex)
		if score.Technical.TicketCreated {
			t.Fatal("an injected exercise ticket must not set Technical.TicketCreated (that is a defender signal)")
		}
		if score.Measurable {
			t.Fatal("an exercise that only injected a ticket produced no measurable result")
		}
	})
}
