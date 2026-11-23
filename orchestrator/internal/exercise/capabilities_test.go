package exercise

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeTicketing is a ticketing backend that can also report status and close drill tickets.
type fakeTicketing struct {
	fakeTicketNotifier
	cmu        sync.Mutex
	closedIDs  []string
	closeNotes []string
	closeErr   error
	statuses   []string // returned in order, the last one repeats
	statusCall int
}

func (f *fakeTicketing) CloseExerciseTicket(_ context.Context, connectorID, ticketID, note string) error {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	if f.closeErr != nil {
		return f.closeErr
	}
	f.closedIDs = append(f.closedIDs, connectorID+"/"+ticketID)
	f.closeNotes = append(f.closeNotes, note)
	return nil
}

func (f *fakeTicketing) TicketStatus(_ context.Context, _, _ string) (string, error) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	if len(f.statuses) == 0 {
		return "open", nil
	}
	i := f.statusCall
	if i >= len(f.statuses) {
		i = len(f.statuses) - 1
	}
	f.statusCall++
	return f.statuses[i], nil
}

func (f *fakeTicketing) closed() []string {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return append([]string(nil), f.closedIDs...)
}

// seedCompletedTicket seeds a running execution whose ticket step already completed with a created ticket.
func seedCompletedTicket(t *testing.T, e *Executor, store *Store, keepOpen bool) *Execution {
	t.Helper()
	ctx := context.Background()
	step := PlanStep{ID: "tk", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{
		ConnectorID: "cfg-1", Subject: "drill", KeepOpen: keepOpen}}}
	ex := seedRunningExecution(t, store, e, []PlanStep{step})
	if err := store.SetStepResult(ctx, ex.ID, "tk", map[string]any{"connector_id": "cfg-1", "ticket_id": "INC7", "channel": "ticket"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetStepStatus(ctx, ex.ID, "tk", StepCompleted, ""); err != nil {
		t.Fatal(err)
	}
	return ex
}

func evidenceCount(t *testing.T, store *Store, execID, evType string) int {
	t.Helper()
	counts, err := store.CountEvidenceByType(context.Background(), execID)
	if err != nil {
		t.Fatal(err)
	}
	return counts[evType]
}

func newCleanupExecutor(pool *pgxpool.Pool, tk *fakeTicketing) (*Executor, *Store) {
	e, store := newTestExecutor(pool)
	e.RegisterBuiltins(nil, nil, nil, nil)
	e.RegisterChannelBuiltins(nil, tk)
	return e, store
}

func TestAbort_ClosesDrillTicketsExactlyOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		tk := &fakeTicketing{}
		e, store := newCleanupExecutor(pool, tk)
		ex := seedCompletedTicket(t, e, store, false)
		ctx := context.Background()

		if err := e.AbortExecution(ctx, ex.ID); err != nil {
			t.Fatal(err)
		}
		got := tk.closed()
		if len(got) != 1 || got[0] != "cfg-1/INC7" {
			t.Fatalf("closed = %v, want [cfg-1/INC7]", got)
		}
		if note := tk.closeNotes[0]; !strings.Contains(strings.ToLower(note), "exercise") {
			t.Fatalf("close note %q must say it was a drill", note)
		}
		if evidenceCount(t, store, ex.ID, "cleanup_done") != 1 {
			t.Fatal("want one cleanup_done evidence record")
		}
		// a second pass (for example abort after the exercise already finished) must not close it again
		e.cleanupExecution(ctx, ex)
		if n := len(tk.closed()); n != 1 {
			t.Fatalf("ticket closed %d times, want once", n)
		}
	})
}

func TestCleanup_KeepOpenLeavesTheTicketAndSaysSo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		tk := &fakeTicketing{}
		e, store := newCleanupExecutor(pool, tk)
		ex := seedCompletedTicket(t, e, store, true)
		ctx := context.Background()

		if err := e.AbortExecution(ctx, ex.ID); err != nil {
			t.Fatal(err)
		}
		if n := len(tk.closed()); n != 0 {
			t.Fatalf("keep_open ticket was closed %d times", n)
		}
		if evidenceCount(t, store, ex.ID, "cleanup_skipped") != 1 {
			t.Fatal("want a cleanup_skipped evidence record explaining why it was left open")
		}
	})
}

func TestCleanup_FailureIsRecordedAndDoesNotBlockAbort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		tk := &fakeTicketing{closeErr: errors.New("servicenow: 403 forbidden")}
		e, store := newCleanupExecutor(pool, tk)
		ex := seedCompletedTicket(t, e, store, false)
		ctx := context.Background()

		if err := e.AbortExecution(ctx, ex.ID); err != nil {
			t.Fatalf("a failed cleanup must not fail the abort: %v", err)
		}
		if evidenceCount(t, store, ex.ID, "cleanup_failed") != 1 {
			t.Fatal("a failed cleanup must be recorded, not dropped")
		}
		// once the connector recovers, a later pass closes it: the failure did not mark it cleaned
		tk.closeErr = nil
		e.cleanupExecution(ctx, ex)
		if got := tk.closed(); len(got) != 1 {
			t.Fatalf("after recovery closed = %v, want one close", got)
		}
	})
}

func TestCompletion_ClosesDrillTickets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		tk := &fakeTicketing{}
		e, store := newCleanupExecutor(pool, tk)
		ex := seedCompletedTicket(t, e, store, false)

		if err := e.advance(context.Background(), ex); err != nil { // every step is done, so this completes the exercise
			t.Fatal(err)
		}
		if got := tk.closed(); len(got) != 1 || got[0] != "cfg-1/INC7" {
			t.Fatalf("closed = %v, want the ticket closed when the exercise completes", got)
		}
	})
}

// A send in flight must really stop on abort: the request's context is cancelled, and the step ends cancelled,
// not failed. Before, the handler ran on a background context that nothing could cancel.
func TestAbort_CancelsASendInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reached := make(chan struct{})
		cancelled := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Go's server only notices a client disconnect (and cancels r.Context()) once the request body has
			// been read, so read it before signalling.
			_, _ = io.Copy(io.Discard, r.Body)
			close(reached)
			select {
			case <-r.Context().Done():
				close(cancelled)
			case <-time.After(10 * time.Second):
			}
		}))
		defer srv.Close()

		e, store := newTestExecutor(pool)
		e.RegisterBuiltins(nil, nil, nil, nil)
		e.RegisterChannelBuiltins(NewGoogleChatInjector(srv.URL), nil)
		ctx := context.Background()

		step := PlanStep{ID: "g", Type: StepTypeGoogleChat, Config: StepConfig{GoogleChat: &GoogleChatStepConfig{Text: "x"}}}
		ex := seedRunningExecution(t, store, e, []PlanStep{step})
		_ = store.SetStepStatus(ctx, ex.ID, "g", StepRunning, "")
		se, _ := store.GetStepExecByStepID(ctx, ex.ID, "g")
		st := ex2step(store, ex, "g")
		if err := e.registry.Dispatch(ctx, ex, &st, se); err != nil {
			t.Fatal(err)
		}
		select {
		case <-reached:
		case <-time.After(5 * time.Second):
			t.Fatal("the send never reached the server")
		}

		if err := e.AbortExecution(ctx, ex.ID); err != nil {
			t.Fatal(err)
		}
		select {
		case <-cancelled:
		case <-time.After(5 * time.Second):
			t.Fatal("abort did not cancel the in-flight request")
		}
		time.Sleep(300 * time.Millisecond) // let the goroutine finish; it must not overwrite the cancelled status
		got, _ := store.GetStepExecByStepID(ctx, ex.ID, "g")
		if got.Status != StepCancelled {
			t.Fatalf("step status = %q, want cancelled (not failed)", got.Status)
		}
	})
}
