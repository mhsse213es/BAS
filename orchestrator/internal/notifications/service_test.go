package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

type fakeBroadcaster struct {
	mu   sync.Mutex
	msgs []models.WSMessage
}

func (f *fakeBroadcaster) BroadcastBrowsers(msg models.WSMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, msg)
}

func (f *fakeBroadcaster) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

func TestEmit_PersistsAndBroadcasts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, created_by, state)
			VALUES ('job-svc-1', 'batch_remediation', '{}', 'user-1', 'requested')`)
		store := NewStore(pool)
		bc := &fakeBroadcaster{}
		svc := NewService(store, bc)

		svc.Emit(ctx, Event{Type: EventJobCompleted, JobID: "job-svc-1", Severity: SeverityInfo, Message: "done", Timestamp: time.Now().UTC()})

		got, err := store.List(ctx, ListFilter{JobID: "job-svc-1", Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 || got[0].Type != EventJobCompleted {
			t.Fatalf("got %+v, want persisted job_completed event", got)
		}
		if bc.count() != 1 {
			t.Fatalf("broadcaster received %d messages, want 1", bc.count())
		}
		if bc.msgs[0].Type != models.MsgNotification {
			t.Errorf("broadcast message Type = %q, want %q", bc.msgs[0].Type, models.MsgNotification)
		}
	})
}

func TestEmit_FansOutToWebhooksAboveMinSeverity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, created_by, state)
			VALUES ('job-svc-2', 'batch_remediation', '{}', 'user-1', 'requested')`)
		store := NewStore(pool)

		received := make(chan []byte, 1)
		var gotSig string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			gotSig = r.Header.Get("X-BAS-Signature")
			received <- body
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		store.CreateWebhook(ctx, Webhook{Name: "high-sev-hook", URL: ts.URL, Secret: "topsecret", MinSeverity: "error", Enabled: true})
		store.CreateWebhook(ctx, Webhook{Name: "info-only-hook", URL: "http://127.0.0.1:1/unreachable", MinSeverity: "info", Enabled: false})

		svc := NewService(store, &fakeBroadcaster{})
		svc.Emit(ctx, Event{Type: EventJobFailed, JobID: "job-svc-2", Severity: SeverityCritical, Message: "all targets failed", Timestamp: time.Now().UTC()})

		select {
		case body := <-received:
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("webhook body not JSON: %v", err)
			}
			if payload["type"] != string(EventJobFailed) {
				t.Errorf("webhook payload type = %v, want %q", payload["type"], EventJobFailed)
			}
			mac := hmac.New(sha256.New, []byte("topsecret"))
			mac.Write(body)
			wantSig := hex.EncodeToString(mac.Sum(nil))
			if gotSig != wantSig {
				t.Errorf("X-BAS-Signature = %q, want %q", gotSig, wantSig)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for webhook POST -- fan-out never called the enabled hook")
		}
	})
}

func TestEmit_SkipsWebhookBelowMinSeverity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, created_by, state)
			VALUES ('job-svc-3', 'batch_remediation', '{}', 'user-1', 'requested')`)
		store := NewStore(pool)

		called := make(chan struct{}, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called <- struct{}{}
		}))
		defer ts.Close()
		store.CreateWebhook(ctx, Webhook{Name: "critical-only", URL: ts.URL, MinSeverity: "critical", Enabled: true})

		svc := NewService(store, &fakeBroadcaster{})
		svc.Emit(ctx, Event{Type: EventTargetDeferred, JobID: "job-svc-3", Severity: SeverityWarning, Message: "frozen", Timestamp: time.Now().UTC()})

		select {
		case <-called:
			t.Fatal("webhook was called for a Warning event despite min_severity=critical")
		case <-time.After(500 * time.Millisecond):
			// expected: no call within the wait window
		}
	})
}
