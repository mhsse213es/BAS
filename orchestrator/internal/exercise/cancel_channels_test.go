package exercise

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Injector level: a cancelled context stops the remaining work and says so ──────────────────

// SMS sends one request per recipient. After a cancel it must stop, and report the cancellation as an error
// instead of returning a success whose "failed" count hides that the rest were never attempted.
func TestSMSInjector_StopsAtCancelAndReportsIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if atomic.AddInt32(&calls, 1) == 1 {
			cancel() // the operator aborts after the first message went out
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := NewSMSInjector(SMSGatewayConfig{URL: srv.URL, From: "BAS"}).Send(ctx, []string{"+1", "+2", "+3"}, "drill")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("%d messages attempted, want 1 (the rest must not be sent after the abort)", n)
	}
	// The abort landed while the first request was in flight, so whether it was delivered is unknown: it is
	// reported as interrupted, not counted as sent and not as failed.
	if res == nil || res["interrupted"] != "+1" || res["sent"] != 0 || res["failed"] != 0 || res["cancelled"] != true {
		t.Fatalf("result = %v, want the first number interrupted and nothing counted as sent or failed", res)
	}
}

// Cancelled before any message: nothing is attempted, and that is not reported as failures.
func TestSMSInjector_CancelledBeforeStartSendsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&calls, 1) }))
	defer srv.Close()

	res, err := NewSMSInjector(SMSGatewayConfig{URL: srv.URL}).Send(ctx, []string{"+1", "+2"}, "x")
	if !errors.Is(err, context.Canceled) || atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("err=%v calls=%d, want Canceled and no requests", err, atomic.LoadInt32(&calls))
	}
	if res["sent"] != 0 || res["failed"] != 0 {
		t.Fatalf("result = %v, want sent 0 and failed 0", res)
	}
}

// Email stops before the NEXT recipient. A message already being delivered cannot be interrupted (net/smtp has
// no context), so cancellation granularity is one message.
func TestSMTPInjector_StopsBeforeTheNextRecipientAtCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already aborted
	inj := NewSMTPInjector(SMTPConfig{Host: "127.0.0.1", Port: 1, FromAddr: "bas@example.test"}, nil)
	res, err := inj.Send(ctx, "se", "ex", &EmailConfig{Subject: "s", BodyHTML: "<p>x</p>"},
		[]Target{{ID: "1", Email: "a@example.test"}, {ID: "2", Email: "b@example.test"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res == nil || res["sent"] != 0 || res["failed"] != 0 {
		t.Fatalf("result = %v, want nothing attempted (sent 0, failed 0): an aborted send must not look like failed deliveries", res)
	}
}

// ── Step level: abort cancels an in-flight Slack, Teams or SMS send ──────────────────────────────

func TestAbort_CancelsSlackTeamsAndSMSInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	cases := []struct {
		name string
		typ  StepType
		cfg  StepConfig
		wire func(e *Executor, url string)
	}{
		{"slack", StepTypeSlack, StepConfig{Slack: &SlackStepConfig{Text: "x"}},
			func(e *Executor, u string) { e.RegisterBuiltins(nil, nil, NewSlackInjector(u), nil) }},
		{"teams", StepTypeTeams, StepConfig{Teams: &TeamsStepConfig{Text: "x"}},
			func(e *Executor, u string) { e.RegisterBuiltins(nil, nil, nil, NewTeamsInjector(u)) }},
		{"sms", StepTypeSendSMS, StepConfig{SMS: &SMSConfig{To: []string{"+1"}, Body: "x"}},
			func(e *Executor, u string) {
				e.RegisterBuiltins(nil, NewSMSInjector(SMSGatewayConfig{URL: u}), nil, nil)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
				reached := make(chan struct{})
				cancelled := make(chan struct{})
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body) // Go only notices a disconnect after the body is read
					close(reached)
					select {
					case <-r.Context().Done():
						close(cancelled)
					case <-time.After(10 * time.Second):
					}
				}))
				defer srv.Close()

				e, store := newTestExecutor(pool)
				tc.wire(e, srv.URL)
				ctx := context.Background()
				step := PlanStep{ID: "s", Type: tc.typ, Config: tc.cfg}
				ex := seedRunningExecution(t, store, e, []PlanStep{step})
				_ = store.SetStepStatus(ctx, ex.ID, "s", StepRunning, "")
				se, _ := store.GetStepExecByStepID(ctx, ex.ID, "s")
				st := ex2step(store, ex, "s")
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
				time.Sleep(300 * time.Millisecond)
				got, _ := store.GetStepExecByStepID(ctx, ex.ID, "s")
				if got.Status != StepCancelled {
					t.Fatalf("step status = %q, want cancelled (not failed or completed)", got.Status)
				}
			})
		})
	}
}
