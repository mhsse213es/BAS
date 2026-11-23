package exercise

import (
	"context"
	"encoding/json"
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

// ── Google Chat injector (no database) ──────────────────────────────────────

func TestGoogleChatInjector_PostsText(t *testing.T) {
	var body map[string]any
	var ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctype = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"spaces/S/messages/M"}`)) // Google returns a Message, not the full text
	}))
	defer srv.Close()

	res, err := NewGoogleChatInjector(srv.URL).Send(context.Background(), "drill: please acknowledge")
	if err != nil {
		t.Fatal(err)
	}
	if body["text"] != "drill: please acknowledge" {
		t.Fatalf("text = %v", body["text"])
	}
	if !strings.HasPrefix(ctype, "application/json") {
		t.Fatalf("content type = %q", ctype)
	}
	if res["channel"] != "google_chat" || res["sent"] != 1 {
		t.Fatalf("result = %v, want channel google_chat, sent 1", res)
	}
}

func TestGoogleChatInjector_UnconfiguredAndNon2xxAreErrors(t *testing.T) {
	if _, err := NewGoogleChatInjector("").Send(context.Background(), "x"); err == nil {
		t.Fatal("want an error when the webhook is not configured")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
	defer srv.Close()
	if _, err := NewGoogleChatInjector(srv.URL).Send(context.Background(), "x"); err == nil {
		t.Fatal("want an error on HTTP 429 (Google allows 1 request per second per space)")
	}
}

// Google rejects a message over 32,000 bytes; refusing it here gives a clear step failure and sends nothing.
func TestGoogleChatInjector_RefusesOversizedMessageWithoutSending(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	inj := NewGoogleChatInjector(srv.URL)

	if _, err := inj.Send(context.Background(), strings.Repeat("a", googleChatMaxBytes+1)); err == nil {
		t.Fatal("want an error for a message over the 32,000 byte limit")
	}
	if called {
		t.Fatal("an oversized message must not be sent")
	}
	// the limit is in bytes, not characters: 'é' is 2 bytes
	if _, err := inj.Send(context.Background(), strings.Repeat("é", googleChatMaxBytes/2+1)); err == nil {
		t.Fatal("want an error when multi-byte text exceeds the byte limit")
	}
	if _, err := inj.Send(context.Background(), strings.Repeat("a", googleChatMaxBytes)); err != nil {
		t.Fatalf("a message exactly at the limit must be allowed: %v", err)
	}
}

// ── Step handlers (database-backed, same harness as the other builtin handlers) ──

type fakeTicketNotifier struct {
	mu          sync.Mutex
	connectorID string
	subject     string
	body        string
	recordType  string
	result      map[string]any
	err         error
}

func (f *fakeTicketNotifier) NotifyStep(_ context.Context, connectorID, subject, body, recordType string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connectorID, f.subject, f.body, f.recordType = connectorID, subject, body, recordType
	return f.result, f.err
}

func runStep(t *testing.T, e *Executor, store *Store, step PlanStep) *StepExecution {
	t.Helper()
	ctx := context.Background()
	ex := seedRunningExecution(t, store, e, []PlanStep{step})
	se, _ := store.GetStepExecByStepID(ctx, ex.ID, step.ID)
	st := ex2step(store, ex, step.ID)
	if err := e.registry.Dispatch(ctx, ex, &st, se); err != nil {
		t.Fatalf("dispatch %s: %v", step.Type, err)
	}
	// the channel handlers finish in a goroutine; wait for a terminal state
	var got *StepExecution
	for i := 0; i < 100; i++ {
		got, _ = store.GetStepExecByStepID(ctx, ex.ID, step.ID)
		if got != nil && (got.Status == StepCompleted || got.Status == StepFailed) {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("step %s never finished; last status %v", step.ID, got)
	return nil
}

func TestChannelSteps_FailClearlyWhenNotConfiguredOrMissingConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.RegisterBuiltins(nil, nil, nil, nil)
		e.RegisterChannelBuiltins(nil, nil) // no Google Chat webhook, no ticketing

		g := runStep(t, e, store, PlanStep{ID: "g1", Type: StepTypeGoogleChat, Config: StepConfig{GoogleChat: &GoogleChatStepConfig{Text: "x"}}})
		if g.Status != StepFailed || !strings.Contains(g.Error, "not configured") {
			t.Fatalf("google_chat unconfigured = %q / %q, want failed 'not configured'", g.Status, g.Error)
		}
		tk := runStep(t, e, store, PlanStep{ID: "t1", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{ConnectorID: "c", Subject: "s"}}})
		if tk.Status != StepFailed || !strings.Contains(tk.Error, "not configured") {
			t.Fatalf("ticket unconfigured = %q / %q, want failed 'not configured'", tk.Status, tk.Error)
		}

		// configured executor, but the step carries no config of its own
		e2, store2 := newTestExecutor(pool)
		e2.RegisterBuiltins(nil, nil, nil, nil)
		e2.RegisterChannelBuiltins(NewGoogleChatInjector("http://127.0.0.1:1"), &fakeTicketNotifier{})
		g2 := runStep(t, e2, store2, PlanStep{ID: "g2", Type: StepTypeGoogleChat})
		if g2.Status != StepFailed || !strings.Contains(g2.Error, "missing google_chat config") {
			t.Fatalf("google_chat no config = %q / %q", g2.Status, g2.Error)
		}
		t2 := runStep(t, e2, store2, PlanStep{ID: "t2", Type: StepTypeTicket})
		if t2.Status != StepFailed || !strings.Contains(t2.Error, "missing ticket config") {
			t.Fatalf("ticket no config = %q / %q", t2.Status, t2.Error)
		}
		// a ticket needs a subject; an empty one must fail instead of creating a blank ticket
		t3 := runStep(t, e2, store2, PlanStep{ID: "t3", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{ConnectorID: "c"}}})
		if t3.Status != StepFailed || !strings.Contains(t3.Error, "subject") {
			t.Fatalf("ticket empty subject = %q / %q, want failed mentioning subject", t3.Status, t3.Error)
		}
	})
}

func TestChannelSteps_CompleteAndRecordWhatWasSent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &got)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		notifier := &fakeTicketNotifier{result: map[string]any{"channel": "ticket", "ticket_id": "INC1", "ticket_url": "https://itsm.example/INC1"}}

		e, store := newTestExecutor(pool)
		e.RegisterBuiltins(nil, nil, nil, nil)
		e.RegisterChannelBuiltins(NewGoogleChatInjector(srv.URL), notifier)

		g := runStep(t, e, store, PlanStep{ID: "g", Type: StepTypeGoogleChat, Config: StepConfig{GoogleChat: &GoogleChatStepConfig{Text: "phish reported?"}}})
		if g.Status != StepCompleted || got["text"] != "phish reported?" {
			t.Fatalf("google_chat = %q / sent %v", g.Status, got)
		}
		tk := runStep(t, e, store, PlanStep{ID: "t", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{
			ConnectorID: "cfg-1", Subject: "Suspicious login", Body: "details", RecordType: "incident"}}})
		if tk.Status != StepCompleted {
			t.Fatalf("ticket = %q / %q", tk.Status, tk.Error)
		}
		if notifier.connectorID != "cfg-1" || notifier.subject != "Suspicious login" || notifier.body != "details" || notifier.recordType != "incident" {
			t.Fatalf("notifier got %+v", notifier)
		}
		if tk.Result["ticket_id"] != "INC1" {
			t.Fatalf("the created ticket must be recorded in the step result, got %v", tk.Result)
		}

		// a connector failure fails the step with its reason, it is not swallowed
		notifier.err = errors.New("servicenow: 401 unauthorized")
		bad := runStep(t, e, store, PlanStep{ID: "t-bad", Type: StepTypeTicket, Config: StepConfig{Ticket: &TicketStepConfig{ConnectorID: "cfg-1", Subject: "s"}}})
		if bad.Status != StepFailed || !strings.Contains(bad.Error, "401") {
			t.Fatalf("ticket failure = %q / %q, want failed with the connector's reason", bad.Status, bad.Error)
		}
	})
}
