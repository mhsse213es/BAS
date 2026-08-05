# Job-Event Notifications (Phase 7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Push notifications for noteworthy Fleet Job Engine events (job-level lifecycle transitions + target-level exceptions) to connected browsers (WebSocket) and configured external webhooks (Slack/Teams/OpsGenie/custom), persisted to a flat history table.

**Architecture:** New DB-backed `internal/notifications` package (`Event`/`Store`/`Service`) that persists every emitted event, pushes it live via an injected `Broadcaster` interface (satisfied by `*ws.Hub`, same decoupling as `integrity.TamperBroadcaster`), and fans it out asynchronously to enabled webhook configs filtered by minimum severity. `internal/jobs.Dispatcher` gains an optional `NotifyFn` callback (mirroring the existing `DispatchFn`/`StatusFn` injection pattern) fired from its 4 existing state-mutation call sites in `Tick()`; `internal/api` is the only package that imports both `internal/jobs` and `internal/notifications` and connects them.

**Tech Stack:** Go, PostgreSQL (pgx/v5), chi router, existing `ws.Hub` WebSocket broadcaster, `net/http`+HMAC-SHA256 for webhook signing.

## Global Constraints

- No branches/PRs — commit directly to `main`, matching this initiative's established convention.
- `git push` after every commit (per repo convention).
- No email/SMTP delivery in this phase — explicitly deferred.
- No read/unread tracking, no delivery-status/retry tracking on notifications — flat append-only log only.
- `NotifyFn`/`h.notifications` are optional and MUST be nil-guarded everywhere they're invoked — every pre-existing test in `dispatch_test.go` and most of `job_handlers_test.go` never wires them, and an unguarded call would panic those tests.
- `internal/jobs` must never import `internal/notifications` or `internal/api` — `NotifyEvent`'s fields are plain strings, not the typed `notifications.EventType`/`Severity` constants.
- RBAC: read/list endpoints use `auth.CanExecuteRemediation` (Analyst+Admin); webhook config create/delete use `auth.CanApproveRemediation` (Admin-only) — both existing constants in `internal/auth/permissions.go`, no new permission added.

---

## File Structure

- **Create** `orchestrator/internal/notifications/types.go` — `EventType`/`Severity` consts, `Event` struct, `severityRank` helper.
- **Create** `orchestrator/internal/notifications/store.go` — `Store` (wraps `*pgxpool.Pool`), `Insert`, `List`, `CreateWebhook`, `ListWebhooks`, `DeleteWebhook`, `Webhook` struct.
- **Create** `orchestrator/internal/notifications/service.go` — `Service` (wraps `*Store` + `Broadcaster`), `NewService`, `Emit`.
- **Create** `orchestrator/internal/notifications/webhook.go` — `sendWebhook` (POST + HMAC-SHA256 signing), `Service.fanOutWebhooks`.
- **Create** `orchestrator/internal/jobs/notify.go` — `NotifyEvent` struct, `NotifyFn` type, local `notifyType*`/`notifySeverity*` string consts, `classifyJobTransition`.
- **Modify** `orchestrator/internal/jobs/dispatch.go` — add `notify NotifyFn` field + `SetNotify` method to `Dispatcher`; add 4 guarded emission call sites in `Tick()`.
- **Create** `orchestrator/internal/api/notifications_dispatch.go` — `dispatchJobNotify` adapter (`jobs.NotifyEvent` → `notifications.Event`), `Handler.WithNotifications`.
- **Create** `orchestrator/internal/api/notification_handlers.go` — `GetNotifications`, `CreateNotificationWebhook`, `ListNotificationWebhooks`, `DeleteNotificationWebhook`.
- **Modify** `orchestrator/internal/api/handlers.go` — add `notifications *notifications.Service` field to `Handler`.
- **Modify** `orchestrator/internal/api/job_dispatch.go` — `WithJobsDispatcher` calls `dispatcher.SetNotify(h.dispatchJobNotify)`.
- **Modify** `orchestrator/internal/api/job_handlers.go` — `CancelJob` emits `EventJobCancelled` after the existing `CancelJob` store call.
- **Modify** `orchestrator/internal/models/schema.go` — add `MsgNotification` WS message-type constant.
- **Modify** `orchestrator/internal/db/postgres.go` — add `notifications` and `notification_webhooks` tables + indexes.
- **Modify** `orchestrator/internal/api/routes.go` — 3 new routes.
- **Modify** `orchestrator/internal/api/rbac_matrix_test.go` — 3 new rows.
- **Modify** `orchestrator/cmd/server/main.go` — construct `notificationsStore` and add `.WithNotifications(notificationsStore)` to the handler chain.
- **Test** `orchestrator/internal/notifications/store_test.go`, `orchestrator/internal/notifications/service_test.go`, `orchestrator/internal/jobs/notify_test.go`, extensions to `orchestrator/internal/jobs/dispatch_test.go`, `orchestrator/internal/api/job_handlers_test.go`, `orchestrator/internal/api/notification_handlers_test.go`.

---

### Task 1: Notification event types + DB schema

**Files:**
- Create: `orchestrator/internal/notifications/types.go`
- Modify: `orchestrator/internal/db/postgres.go` (append after line 1318, the `idx_agent_maintenance_freezes_agent_id` index, before the closing `}` of the `stmts` slice at line 1319)
- Test: `orchestrator/internal/notifications/store_test.go` (written in Task 2, once `Store` exists to exercise the schema)

**Interfaces:**
- Produces: `notifications.EventType` (string type), `notifications.Severity` (string type), the 4 `EventJob*` + 2 `EventTarget*` constants, the 4 `Severity*` constants, `notifications.Event` struct, `notifications.severityRank(s Severity) int`.

- [ ] **Step 1: Write `types.go`**

```go
package notifications

import "time"

type EventType string

const (
	EventJobStarted   EventType = "job_started"
	EventJobCompleted EventType = "job_completed"
	EventJobPartial   EventType = "job_partially_completed"
	EventJobFailed    EventType = "job_failed"
	EventJobCancelled EventType = "job_cancelled"

	EventTargetFailed   EventType = "target_failed"
	EventTargetDeferred EventType = "target_deferred"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// severityRank orders severities low-to-high for min_severity webhook
// filtering -- a webhook configured with min_severity=warning receives
// warning, error, and critical events, not info.
func severityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityWarning:
		return 1
	case SeverityError:
		return 2
	case SeverityCritical:
		return 3
	default:
		return 0
	}
}

// Event is one emitted notification -- persisted, pushed live over
// WebSocket, and optionally fanned out to configured webhooks.
type Event struct {
	ID        string
	Type      EventType
	JobID     string
	TargetID  string // "" for job-level events
	AgentID   string // "" for job-level events
	Severity  Severity
	Message   string
	Metadata  map[string]any
	Timestamp time.Time
}
```

- [ ] **Step 2: Add the two tables to `postgres.go`**

Insert immediately after the `idx_agent_maintenance_freezes_agent_id` line (currently line 1318), before the closing `}` of the `stmts` slice:

```go
		// Sub-project 11 (Phase 7): Job-Event Notifications. See
		// docs/superpowers/specs/2026-08-05-job-event-notifications-design.md.
		`CREATE TABLE IF NOT EXISTS notifications (
			id         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			type       text        NOT NULL,
			job_id     text        NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
			target_id  text        NOT NULL DEFAULT '',
			agent_id   text        NOT NULL DEFAULT '',
			severity   text        NOT NULL,
			message    text        NOT NULL,
			metadata   jsonb       NOT NULL DEFAULT '{}',
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications (created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_notifications_job_id ON notifications (job_id)`,

		`CREATE TABLE IF NOT EXISTS notification_webhooks (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name         text        NOT NULL,
			url          text        NOT NULL,
			secret       text        NOT NULL DEFAULT '',
			min_severity text        NOT NULL DEFAULT 'warning',
			enabled      boolean     NOT NULL DEFAULT true,
			created_at   timestamptz NOT NULL DEFAULT NOW()
		)`,
```

- [ ] **Step 3: Verify it compiles and the package builds**

Run: `go build ./internal/notifications/... ./internal/db/...`
Expected: no errors (no tests yet -- `Store` doesn't exist until Task 2, so this step only confirms `types.go` and the `postgres.go` edit are syntactically valid Go/SQL).

- [ ] **Step 4: Commit**

```bash
git add internal/notifications/types.go internal/db/postgres.go
git commit -m "feat(notifications): add event/severity types and notifications schema"
git push
```

---

### Task 2: `notifications.Store` — persistence + webhook config CRUD

**Files:**
- Create: `orchestrator/internal/notifications/store.go`
- Test: `orchestrator/internal/notifications/store_test.go`

**Interfaces:**
- Consumes: `notifications.Event`, `notifications.EventType`, `notifications.Severity` (Task 1).
- Produces: `notifications.Store`, `notifications.NewStore(pool *pgxpool.Pool) *Store`, `(*Store).Insert(ctx, evt Event) error`, `(*Store).List(ctx, filter ListFilter) ([]Event, error)`, `notifications.ListFilter{JobID, Severity, Type string; Limit, Offset int}`, `notifications.Webhook{ID, Name, URL, Secret, MinSeverity string; Enabled bool; CreatedAt time.Time}`, `(*Store).CreateWebhook(ctx, w Webhook) (string, error)`, `(*Store).ListWebhooks(ctx) ([]Webhook, error)`, `(*Store).ListEnabledWebhooks(ctx) ([]Webhook, error)`, `(*Store).DeleteWebhook(ctx, id string) error`.

- [ ] **Step 1: Write the failing test**

```go
package notifications

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInsertAndList_RoundTripsEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, agent_ids, created_by, state)
			VALUES ('job-store-1', 'batch_remediation', '{}', '["a1"]', 'user-1', 'requested')`)
		store := NewStore(pool)

		err := store.Insert(ctx, Event{
			Type: EventTargetFailed, JobID: "job-store-1", TargetID: "t-1", AgentID: "a1",
			Severity: SeverityError, Message: "boom", Metadata: map[string]any{"errText": "boom"},
			Timestamp: time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}

		got, err := store.List(ctx, ListFilter{JobID: "job-store-1", Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d events, want 1", len(got))
		}
		if got[0].Type != EventTargetFailed || got[0].Message != "boom" || got[0].Severity != SeverityError {
			t.Errorf("event = %+v, want Type=target_failed Message=boom Severity=error", got[0])
		}
	})
}

func TestList_FiltersBySeverityAndType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, agent_ids, created_by, state)
			VALUES ('job-store-2', 'batch_remediation', '{}', '["a1"]', 'user-1', 'requested')`)
		store := NewStore(pool)
		store.Insert(ctx, Event{Type: EventTargetFailed, JobID: "job-store-2", Severity: SeverityError, Message: "e1", Timestamp: time.Now().UTC()})
		store.Insert(ctx, Event{Type: EventJobCompleted, JobID: "job-store-2", Severity: SeverityInfo, Message: "e2", Timestamp: time.Now().UTC()})

		got, err := store.List(ctx, ListFilter{Severity: string(SeverityError), Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 || got[0].Message != "e1" {
			t.Fatalf("got %+v, want exactly the severity=error event", got)
		}

		got, err = store.List(ctx, ListFilter{Type: string(EventJobCompleted), Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 || got[0].Message != "e2" {
			t.Fatalf("got %+v, want exactly the job_completed event", got)
		}
	})
}

func TestWebhookCRUD_CreateListDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		id, err := store.CreateWebhook(ctx, Webhook{Name: "slack-ops", URL: "https://example.test/hook", Secret: "shh", MinSeverity: "warning", Enabled: true})
		if err != nil {
			t.Fatalf("CreateWebhook: %v", err)
		}
		if id == "" {
			t.Fatal("CreateWebhook returned empty id")
		}

		all, err := store.ListWebhooks(ctx)
		if err != nil {
			t.Fatalf("ListWebhooks: %v", err)
		}
		if len(all) != 1 || all[0].Name != "slack-ops" || all[0].Secret != "shh" {
			t.Fatalf("ListWebhooks = %+v, want the created webhook with secret intact", all)
		}

		if err := store.DeleteWebhook(ctx, id); err != nil {
			t.Fatalf("DeleteWebhook: %v", err)
		}
		all, err = store.ListWebhooks(ctx)
		if err != nil {
			t.Fatalf("ListWebhooks after delete: %v", err)
		}
		if len(all) != 0 {
			t.Fatalf("ListWebhooks after delete = %+v, want empty", all)
		}
	})
}

func TestListEnabledWebhooks_ExcludesDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		store.CreateWebhook(ctx, Webhook{Name: "on", URL: "https://example.test/on", MinSeverity: "info", Enabled: true})
		store.CreateWebhook(ctx, Webhook{Name: "off", URL: "https://example.test/off", MinSeverity: "info", Enabled: false})

		enabled, err := store.ListEnabledWebhooks(ctx)
		if err != nil {
			t.Fatalf("ListEnabledWebhooks: %v", err)
		}
		if len(enabled) != 1 || enabled[0].Name != "on" {
			t.Fatalf("ListEnabledWebhooks = %+v, want exactly the enabled one", enabled)
		}
	})
}

func mustExecNotif(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("mustExecNotif: %v\nsql: %s", err, sql)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/notifications/... -run TestInsertAndList_RoundTripsEvent -v`
Expected: FAIL — `undefined: NewStore` (or package fails to compile, `Store` doesn't exist yet).

- [ ] **Step 3: Write `store.go`**

```go
package notifications

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Insert(ctx context.Context, evt Event) error {
	metaJSON, err := json.Marshal(evt.Metadata)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO notifications (type, job_id, target_id, agent_id, severity, message, metadata)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		string(evt.Type), evt.JobID, evt.TargetID, evt.AgentID, string(evt.Severity), evt.Message, metaJSON)
	return err
}

// ListFilter narrows GetNotifications results. Zero-value fields are
// unfiltered. Limit <= 0 is treated as the caller's responsibility --
// internal/api's handler is what clamps to a sane default/max.
type ListFilter struct {
	JobID    string
	Severity string
	Type     string
	Limit    int
	Offset   int
}

func (s *Store) List(ctx context.Context, f ListFilter) ([]Event, error) {
	where := "WHERE 1=1"
	args := []any{}
	argc := 1
	if f.JobID != "" {
		where += " AND job_id = $" + itoa(argc)
		args = append(args, f.JobID)
		argc++
	}
	if f.Severity != "" {
		where += " AND severity = $" + itoa(argc)
		args = append(args, f.Severity)
		argc++
	}
	if f.Type != "" {
		where += " AND type = $" + itoa(argc)
		args = append(args, f.Type)
		argc++
	}
	args = append(args, f.Limit, f.Offset)

	rows, err := s.pool.Query(ctx,
		`SELECT id, type, job_id, target_id, agent_id, severity, message, metadata, created_at
		 FROM notifications `+where+`
		 ORDER BY created_at DESC
		 LIMIT $`+itoa(argc)+` OFFSET $`+itoa(argc+1),
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var typ, sev string
		var metaJSON []byte
		if err := rows.Scan(&e.ID, &typ, &e.JobID, &e.TargetID, &e.AgentID, &sev, &e.Message, &metaJSON, &e.Timestamp); err != nil {
			return nil, err
		}
		e.Type = EventType(typ)
		e.Severity = Severity(sev)
		_ = json.Unmarshal(metaJSON, &e.Metadata)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Webhook is one configured outbound notification target.
type Webhook struct {
	ID          string
	Name        string
	URL         string
	Secret      string
	MinSeverity string
	Enabled     bool
	CreatedAt   time.Time
}

func (s *Store) CreateWebhook(ctx context.Context, w Webhook) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO notification_webhooks (name, url, secret, min_severity, enabled)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		w.Name, w.URL, w.Secret, w.MinSeverity, w.Enabled).Scan(&id)
	return id, err
}

func (s *Store) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	return s.queryWebhooks(ctx, `SELECT id, name, url, secret, min_severity, enabled, created_at FROM notification_webhooks ORDER BY created_at DESC`)
}

func (s *Store) ListEnabledWebhooks(ctx context.Context) ([]Webhook, error) {
	return s.queryWebhooks(ctx, `SELECT id, name, url, secret, min_severity, enabled, created_at FROM notification_webhooks WHERE enabled = true`)
}

func (s *Store) queryWebhooks(ctx context.Context, sql string) ([]Webhook, error) {
	rows, err := s.pool.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var w Webhook
		if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.Secret, &w.MinSeverity, &w.Enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) DeleteWebhook(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM notification_webhooks WHERE id = $1`, id)
	return err
}

func itoa(n int) string {
	// strconv.Itoa without importing strconv twice across the file -- kept
	// local since it's used only for building positional SQL placeholders.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
```

Note: `itoa` is written by hand only to avoid importing `strconv` for a single tiny helper here — actually, simpler and consistent with `audit.go`'s own `strconv.Itoa` usage: **use `strconv.Itoa` instead.** Replace the hand-rolled `itoa` function with an import of `"strconv"` at the top of the file and calls to `strconv.Itoa(argc)` throughout `List`. Delete the hand-rolled `itoa` function entirely. (This note exists because hand-rolling a stdlib function that's one import away is exactly the kind of unnecessary code this codebase avoids — `internal/api/audit.go` already imports `strconv` for the identical pattern.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/notifications/... -run 'TestInsertAndList_RoundTripsEvent|TestList_FiltersBySeverityAndType|TestWebhookCRUD_CreateListDelete|TestListEnabledWebhooks_ExcludesDisabled' -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/notifications/store.go internal/notifications/store_test.go
git commit -m "feat(notifications): add Store for event persistence and webhook config CRUD"
git push
```

---

### Task 3: `notifications.Service` — Emit, WS push, webhook fan-out

**Files:**
- Create: `orchestrator/internal/notifications/service.go`
- Create: `orchestrator/internal/notifications/webhook.go`
- Test: `orchestrator/internal/notifications/service_test.go`

**Interfaces:**
- Consumes: `notifications.Store` (Task 2), `notifications.Event`/`EventType`/`Severity`/`severityRank` (Task 1).
- Produces: `notifications.Broadcaster` interface, `notifications.Service`, `notifications.NewService(store *Store, broadcaster Broadcaster) *Service`, `(*Service).Emit(ctx context.Context, evt Event)`.

- [ ] **Step 1: Write the failing test**

```go
package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, agent_ids, created_by, state)
			VALUES ('job-svc-1', 'batch_remediation', '{}', '["a1"]', 'user-1', 'requested')`)
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
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, agent_ids, created_by, state)
			VALUES ('job-svc-2', 'batch_remediation', '{}', '["a1"]', 'user-1', 'requested')`)
		store := NewStore(pool)

		received := make(chan []byte, 1)
		var gotSig string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
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
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, agent_ids, created_by, state)
			VALUES ('job-svc-3', 'batch_remediation', '{}', '["a1"]', 'user-1', 'requested')`)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/notifications/... -run TestEmit_PersistsAndBroadcasts -v`
Expected: FAIL — `undefined: NewService` / `undefined: models.MsgNotification`.

- [ ] **Step 3: Add `MsgNotification` to `internal/models/schema.go`**

Add next to the existing `MsgTamperAlert` constant (in the `const (...)` block starting at `internal/models/schema.go:341`):

```go
	MsgNotification              = "notification"
```

- [ ] **Step 4: Write `service.go`**

```go
package notifications

import (
	"context"
	"log"

	"github.com/audspect/bas/internal/models"
)

// Broadcaster is the subset of ws.Hub that Service needs -- keeps this
// package free of a ws import, same reasoning as integrity.TamperBroadcaster.
type Broadcaster interface {
	BroadcastBrowsers(msg models.WSMessage)
}

type Service struct {
	store       *Store
	broadcaster Broadcaster
}

func NewService(store *Store, broadcaster Broadcaster) *Service {
	return &Service{store: store, broadcaster: broadcaster}
}

// Emit persists evt, pushes it live to every connected browser, and fans it
// out (async, best-effort) to every enabled webhook whose min_severity is
// at or below evt.Severity. A storage failure is logged but does not stop
// delivery -- a notification that failed to persist is still worth pushing.
func (s *Service) Emit(ctx context.Context, evt Event) {
	if err := s.store.Insert(ctx, evt); err != nil {
		log.Printf("[notifications] insert failed: %v", err)
	}

	s.broadcaster.BroadcastBrowsers(models.WSMessage{
		Type: models.MsgNotification,
		Data: evt,
	})

	go s.fanOutWebhooks(ctx, evt)
}
```

- [ ] **Step 5: Write `webhook.go`**

```go
package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

var webhookClient = &http.Client{Timeout: 10 * time.Second}

// fanOutWebhooks POSTs evt as JSON to every enabled webhook whose
// min_severity is at or below evt.Severity. Runs in its own goroutine
// (called via `go` from Emit) -- a slow or unreachable endpoint must never
// block job dispatch or the caller of Emit.
func (s *Service) fanOutWebhooks(ctx context.Context, evt Event) {
	hooks, err := s.store.ListEnabledWebhooks(ctx)
	if err != nil {
		log.Printf("[notifications] list webhooks failed: %v", err)
		return
	}
	body, err := json.Marshal(map[string]any{
		"type":     string(evt.Type),
		"jobId":    evt.JobID,
		"targetId": evt.TargetID,
		"agentId":  evt.AgentID,
		"severity": string(evt.Severity),
		"message":  evt.Message,
		"metadata": evt.Metadata,
	})
	if err != nil {
		log.Printf("[notifications] marshal event failed: %v", err)
		return
	}
	for _, hook := range hooks {
		if severityRank(evt.Severity) < severityRank(Severity(hook.MinSeverity)) {
			continue
		}
		if err := sendWebhook(hook, body); err != nil {
			log.Printf("[notifications] webhook %s delivery failed: %v", hook.Name, err)
		}
	}
}

func sendWebhook(hook Webhook, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if hook.Secret != "" {
		mac := hmac.New(sha256.New, []byte(hook.Secret))
		mac.Write(body)
		req.Header.Set("X-BAS-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := webhookClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

var _ = context.Background // keep context import available for future ctx-aware webhookClient use
```

Remove the trailing `var _ = context.Background` line and its `"context"` import if `go vet`/`go build` flags it as unused after Step 6 (it's a placeholder only if `context` ends up genuinely unused in this file — check before committing).

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/notifications/... -run 'TestEmit_PersistsAndBroadcasts|TestEmit_FansOutToWebhooksAboveMinSeverity|TestEmit_SkipsWebhookBelowMinSeverity' -v`
Expected: PASS (all 3 tests)

- [ ] **Step 7: Run `go vet` and fix any unused-import issues from Step 5's placeholder line**

Run: `go vet ./internal/notifications/...`
Expected: clean. If `context` is flagged unused in `webhook.go`, delete the `"context"` import and the placeholder `var _ = context.Background` line — `webhook.go` doesn't actually need `context` since `sendWebhook` uses a plain `*http.Request` without a context-aware call.

- [ ] **Step 8: Commit**

```bash
git add internal/notifications/service.go internal/notifications/webhook.go internal/notifications/service_test.go internal/models/schema.go
git commit -m "feat(notifications): add Service with WS broadcast and HMAC-signed webhook fan-out"
git push
```

---

### Task 4: `internal/jobs` — NotifyEvent, classifyJobTransition, wire into Tick()

**Files:**
- Create: `orchestrator/internal/jobs/notify.go`
- Modify: `orchestrator/internal/jobs/dispatch.go`
- Test: `orchestrator/internal/jobs/notify_test.go` (pure, no container)
- Test: extend `orchestrator/internal/jobs/dispatch_test.go` (container-backed)

**Interfaces:**
- Consumes: nothing outside `internal/jobs` — this task is entirely self-contained (the whole point of the `NotifyEvent` mirror type).
- Produces: `jobs.NotifyEvent` struct, `jobs.NotifyFn` type, `(*Dispatcher).SetNotify(fn NotifyFn)`, `jobs.classifyJobTransition(newState string) (eventType, severity string, ok bool)` (unexported — internal to the package, Task 5's adapter only needs `NotifyEvent`/`NotifyFn`).

- [ ] **Step 1: Write the failing test for `classifyJobTransition`**

```go
package jobs

import "testing"

func TestClassifyJobTransition(t *testing.T) {
	cases := []struct {
		newState  string
		wantType  string
		wantSev   string
		wantOk    bool
	}{
		{JobStateRunning, notifyTypeJobStarted, notifySeverityInfo, true},
		{JobStateCompleted, notifyTypeJobCompleted, notifySeverityInfo, true},
		{JobStatePartial, notifyTypeJobPartial, notifySeverityWarning, true},
		{JobStateFailed, notifyTypeJobFailed, notifySeverityCritical, true},
		{JobStateRequested, "", "", false},
		{JobStateCancelled, "", "", false},
	}
	for _, c := range cases {
		gotType, gotSev, gotOk := classifyJobTransition(c.newState)
		if gotType != c.wantType || gotSev != c.wantSev || gotOk != c.wantOk {
			t.Errorf("classifyJobTransition(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.newState, gotType, gotSev, gotOk, c.wantType, c.wantSev, c.wantOk)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/jobs/... -run TestClassifyJobTransition -v`
Expected: FAIL — `undefined: classifyJobTransition` (and the `notifyType*`/`notifySeverity*` consts).

- [ ] **Step 3: Write `notify.go`**

```go
package jobs

import "context"

// NotifyEvent is internal/jobs's own copy of the notification-event shape.
// internal/jobs must not import internal/notifications (same reason it
// never imports internal/api: DispatchFn/StatusFn/NotifyFn are all
// injected specifically to keep this package a leaf dependency). Type and
// Severity are plain strings here -- they must match
// notifications.EventType / notifications.Severity's string values
// exactly; internal/api's dispatchJobNotify is what connects the two.
type NotifyEvent struct {
	Type     string
	JobID    string
	TargetID string
	AgentID  string
	Severity string
	Message  string
	Metadata map[string]any
}

// NotifyFn is called for every notification-worthy event Tick() produces.
// Unlike DispatchFn/StatusFn, it is optional: SetNotify is not called by
// every test or every Handler construction, so every call site in
// dispatch.go MUST guard with `if d.notify != nil`.
type NotifyFn func(ctx context.Context, evt NotifyEvent)

func (d *Dispatcher) SetNotify(fn NotifyFn) { d.notify = fn }

// internal/jobs's own spelling of the event-type/severity strings it
// emits. Must match notifications.EventType / notifications.Severity's
// string values exactly.
const (
	notifyTypeJobStarted     = "job_started"
	notifyTypeJobCompleted   = "job_completed"
	notifyTypeJobPartial     = "job_partially_completed"
	notifyTypeJobFailed      = "job_failed"
	notifyTypeTargetFailed   = "target_failed"
	notifyTypeTargetDeferred = "target_deferred"

	notifySeverityInfo     = "info"
	notifySeverityWarning  = "warning"
	notifySeverityError    = "error"
	notifySeverityCritical = "critical"
)

// classifyJobTransition maps a Job's new aggregate state to the
// notification event it produces, or ok=false if this transition isn't
// notification-worthy. JobStateRequested never appears as a newState
// (AggregateState only returns it as a starting point, never a
// transition target reached from a different state). JobStateCancelled
// is excluded here because AggregateState never returns it either --
// CancelJob sets it directly via SQL, bypassing Tick() entirely; its
// EventJobCancelled is emitted by the CancelJob handler in internal/api,
// not here.
func classifyJobTransition(newState string) (eventType, severity string, ok bool) {
	switch newState {
	case JobStateRunning:
		return notifyTypeJobStarted, notifySeverityInfo, true
	case JobStateCompleted:
		return notifyTypeJobCompleted, notifySeverityInfo, true
	case JobStatePartial:
		return notifyTypeJobPartial, notifySeverityWarning, true
	case JobStateFailed:
		return notifyTypeJobFailed, notifySeverityCritical, true
	default:
		return "", "", false
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/jobs/... -run TestClassifyJobTransition -v`
Expected: PASS

- [ ] **Step 5: Add the `notify` field to `Dispatcher` and the 4 emission call sites in `dispatch.go`**

In `internal/jobs/dispatch.go`, add the field to the struct (currently lines 26-30):

```go
type Dispatcher struct {
	store    *Store
	dispatch DispatchFn
	status   StatusFn
	notify   NotifyFn
}
```

At line 73 (inside the in-flight-resolution loop, right after the existing `MarkTargetTerminal` call succeeds):

```go
		if err := d.store.MarkTargetTerminal(ctx, t.ID, state, errText); err != nil {
			continue
		}
		if state == TargetStateFailed && d.notify != nil {
			d.notify(ctx, NotifyEvent{
				Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
				Severity: notifySeverityError, Message: errText,
			})
		}
		touchedJobs[t.JobID] = true
```

At line 104 (inside the pending-targets loop, the frozen-agent branch):

```go
		if frozen, reason, ferr := d.store.IsAgentFrozen(ctx, t.AgentID); ferr == nil && frozen {
			d.store.MarkTargetDeferred(ctx, t.ID, reason)
			if d.notify != nil {
				d.notify(ctx, NotifyEvent{
					Type: notifyTypeTargetDeferred, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
					Severity: notifySeverityWarning, Message: reason,
				})
			}
			touchedJobs[t.JobID] = true
			continue
		}
```

At line 110 (the dispatch-error branch, same loop):

```go
		refID, dispatchErr := d.dispatch(ctx, job, t)
		if dispatchErr != nil {
			d.store.MarkTargetTerminal(ctx, t.ID, TargetStateFailed, dispatchErr.Error())
			if d.notify != nil {
				d.notify(ctx, NotifyEvent{
					Type: notifyTypeTargetFailed, JobID: t.JobID, TargetID: t.ID, AgentID: t.AgentID,
					Severity: notifySeverityError, Message: dispatchErr.Error(),
				})
			}
		} else {
			d.store.MarkTargetDispatched(ctx, t.ID, refID)
		}
		touchedJobs[t.JobID] = true
```

At line 128 (the touched-jobs state-aggregation loop):

```go
		newState := AggregateState(job.State, targets)
		if newState != job.State {
			if err := d.store.SetJobState(ctx, jobID, newState); err == nil {
				updated := job
				updated.State = newState
				jobCache[jobID] = updated
				if d.notify != nil {
					if evtType, sev, ok := classifyJobTransition(newState); ok {
						d.notify(ctx, NotifyEvent{Type: evtType, JobID: jobID, Severity: sev})
					}
				}
			}
		}
```

- [ ] **Step 6: Write the failing integration test in `dispatch_test.go`**

Add to `internal/jobs/dispatch_test.go`:

```go
func TestTick_NotifiesTargetFailedAndJobFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-notif-fail"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		var events []NotifyEvent
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			return "", errors.New("agent not connected")
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) {
			t.Fatal("status should not be called -- nothing was dispatched")
			return "", "", false
		})
		d.SetNotify(func(ctx context.Context, evt NotifyEvent) {
			events = append(events, evt)
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		if len(events) != 2 {
			t.Fatalf("got %d notify events, want 2 (target_failed + job_failed): %+v", len(events), events)
		}
		if events[0].Type != notifyTypeTargetFailed || events[0].JobID != job.ID || events[0].Message != "agent not connected" {
			t.Errorf("events[0] = %+v, want target_failed for job %s", events[0], job.ID)
		}
		if events[1].Type != notifyTypeJobFailed || events[1].JobID != job.ID {
			t.Errorf("events[1] = %+v, want job_failed for job %s", events[1], job.ID)
		}
	})
}

func TestTick_NotifiesTargetDeferred(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecJobsNotif(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('agent-notif-freeze', 'AGENT-NOTIF-FREEZE')`)
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"agent-notif-freeze"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		_, err = store.CreateFreeze(ctx, AgentFreeze{
			AgentID: "agent-notif-freeze", FromAt: time.Now().UTC().Add(-time.Hour), ToAt: time.Now().UTC().Add(time.Hour),
			Reason: "maintenance", CreatedBy: "admin-1",
		})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		var events []NotifyEvent
		d := NewDispatcher(store)
		d.SetDispatch(func(ctx context.Context, j Job, target JobTarget) (string, error) {
			t.Fatal("dispatch should not be called -- the agent is frozen")
			return "", nil
		})
		d.SetStatus(func(ctx context.Context, jobType, refID string) (string, string, bool) { return "", "", false })
		d.SetNotify(func(ctx context.Context, evt NotifyEvent) {
			events = append(events, evt)
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(events) != 1 || events[0].Type != notifyTypeTargetDeferred || events[0].JobID != job.ID {
			t.Fatalf("events = %+v, want exactly one target_deferred for job %s", events, job.ID)
		}
	})
}

func mustExecJobsNotif(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("mustExecJobsNotif: %v\nsql: %s", err, sql)
	}
}
```

- [ ] **Step 7: Run test to verify it fails**

Run: `go test ./internal/jobs/... -run 'TestTick_NotifiesTargetFailedAndJobFailed|TestTick_NotifiesTargetDeferred' -v`
Expected: FAIL — `d.SetNotify` undefined (before Step 5's edits are applied) or the events slice doesn't match (if Step 5 was already done, confirms the emission logic itself, not just compilation).

Do Step 5 before Step 6 if not already done in this task's execution order; the failing-test-first flow here means: write notify.go (Step 3) and confirm the pure unit test passes (Step 4) first, THEN write this integration test (Step 6) and confirm it fails only because dispatch.go hasn't been touched yet, THEN apply Step 5's edits, THEN re-run.

- [ ] **Step 8: Run full existing `dispatch_test.go` suite to confirm no regression (nil-guard check)**

Run: `go test ./internal/jobs/... -v`
Expected: PASS — every pre-existing test (`TestTick_DispatchesPendingTargetsUpToCap`, `TestTick_ResolvesTerminalTargetsAndAggregatesJobState`, `TestTick_DispatchErrorMarksTargetFailedWithoutAborting`, `TestTick_CancelledJobIsNeverTouched`, etc.) still passes even though none of them call `SetNotify` — this is the concrete proof the `if d.notify != nil` guards work.

- [ ] **Step 9: Commit**

```bash
git add internal/jobs/notify.go internal/jobs/dispatch.go internal/jobs/notify_test.go internal/jobs/dispatch_test.go
git commit -m "feat(jobs): emit NotifyEvent from Tick()'s 4 state-mutation points"
git push
```

---

### Task 5: Wire `internal/api` — Handler field, adapter, CancelJob emission

**Files:**
- Create: `orchestrator/internal/api/notifications_dispatch.go`
- Modify: `orchestrator/internal/api/handlers.go`
- Modify: `orchestrator/internal/api/job_dispatch.go`
- Modify: `orchestrator/internal/api/job_handlers.go`
- Test: extend `orchestrator/internal/api/job_handlers_test.go`

**Interfaces:**
- Consumes: `jobs.NotifyEvent`/`jobs.NotifyFn` (Task 4), `notifications.Service`/`notifications.Event`/`EventType`/`Severity` (Tasks 1-3).
- Produces: `Handler.notifications *notifications.Service` field, `(*Handler).WithNotifications(store *notifications.Store) *Handler`, `(*Handler).dispatchJobNotify(ctx context.Context, evt jobs.NotifyEvent)`.

- [ ] **Step 1: Add the `notifications` field to `Handler` and the `WithNotifications` constructor method**

In `internal/api/handlers.go`, add to the `Handler` struct (after the `jobsStore` field, line 105):

```go
	jobsStore             *jobs.Store          // nil when not loaded — Fleet Job Engine (batch remediation)
	notifications         *notifications.Service // nil when not loaded — Phase 7 job-event notifications
```

Add the import `"github.com/audspect/bas/internal/notifications"` to the file's import block.

- [ ] **Step 2: Write `notifications_dispatch.go`**

```go
package api

import (
	"context"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/notifications"
)

// WithNotifications attaches the Phase 7 notification service, backed by
// store and pushing live over the Handler's existing WebSocket hub.
func (h *Handler) WithNotifications(store *notifications.Store) *Handler {
	h.notifications = notifications.NewService(store, h.hub)
	return h
}

// dispatchJobNotify adapts a jobs.NotifyEvent (plain strings, defined in
// internal/jobs to avoid that package importing internal/notifications)
// into a typed notifications.Event and emits it. This is the sole place
// the two packages' vocabularies meet -- mirrors dispatchJobTarget /
// statusForJobTarget's role as the internal/jobs <-> internal/api bridge.
// Passed to jobsDispatcher.SetNotify in WithJobsDispatcher (job_dispatch.go).
func (h *Handler) dispatchJobNotify(ctx context.Context, evt jobs.NotifyEvent) {
	if h.notifications == nil {
		return
	}
	h.notifications.Emit(ctx, notifications.Event{
		Type:     notifications.EventType(evt.Type),
		JobID:    evt.JobID,
		TargetID: evt.TargetID,
		AgentID:  evt.AgentID,
		Severity: notifications.Severity(evt.Severity),
		Message:  evt.Message,
		Metadata: evt.Metadata,
	})
}
```

- [ ] **Step 3: Wire `SetNotify` in `WithJobsDispatcher`**

In `internal/api/job_dispatch.go`, modify `WithJobsDispatcher` (currently lines 131-136):

```go
func (h *Handler) WithJobsDispatcher(store *jobs.Store, dispatcher *jobs.Dispatcher) *Handler {
	h.jobsStore = store
	dispatcher.SetDispatch(h.dispatchJobTarget)
	dispatcher.SetStatus(h.statusForJobTarget)
	dispatcher.SetNotify(h.dispatchJobNotify)
	return h
}
```

`dispatcher.SetNotify(h.dispatchJobNotify)` is always called (unconditionally) even when `.WithNotifications(...)` hasn't been chained -- `dispatchJobNotify`'s own `if h.notifications == nil { return }` guard (Step 2) makes this safe. This means `d.notify` is never actually `nil` once `WithJobsDispatcher` runs; the `if d.notify != nil` guards added in Task 4 protect the narrower case of a `*Dispatcher` used directly in `internal/jobs`' own tests, which never call `WithJobsDispatcher` at all.

- [ ] **Step 4: Emit `EventJobCancelled` from `CancelJob`**

In `internal/api/job_handlers.go`, modify `CancelJob` (currently lines 121-138):

```go
func (h *Handler) CancelJob(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if _, err := h.jobsStore.Get(r.Context(), jobID); err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	cancelledCount, err := h.jobsStore.CancelJob(r.Context(), jobID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.notifications != nil {
		h.notifications.Emit(r.Context(), notifications.Event{
			Type: notifications.EventJobCancelled, JobID: jobID, Severity: notifications.SeverityWarning,
			Message: "job cancelled", Metadata: map[string]any{"cancelledCount": cancelledCount},
		})
	}
	h.auditLog(r, "jobs.cancel", jobID, map[string]any{"cancelledTargets": cancelledCount}, "cancelled")
	respond(w, map[string]any{"jobId": jobID, "state": jobs.JobStateCancelled, "cancelledTargets": cancelledCount})
}
```

Add the `"github.com/audspect/bas/internal/notifications"` import to `job_handlers.go`.

- [ ] **Step 5: Write the failing test**

Add to `internal/api/job_handlers_test.go`:

```go
func TestCancelJob_EmitsJobCancelledNotification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jcn-a1', 'JCN-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"jcn-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithNotifications(notifStore)

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "jobId", created.ID)
		w := httptest.NewRecorder()
		h.CancelJob(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		events, err := notifStore.List(context.Background(), notifications.ListFilter{JobID: created.ID, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 1 || events[0].Type != notifications.EventJobCancelled {
			t.Fatalf("events = %+v, want exactly one job_cancelled event", events)
		}
		if events[0].Metadata["cancelledCount"] != float64(1) {
			t.Errorf("Metadata[cancelledCount] = %v, want 1 (json.Unmarshal decodes numbers as float64)", events[0].Metadata["cancelledCount"])
		}
	})
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/api/... -run TestCancelJob_EmitsJobCancelledNotification -v`
Expected: FAIL — `undefined: notifications.NewStore` / `WithNotifications` undefined, before Steps 1-4 are applied. (Write this test after Steps 1-4 in execution order to see it fail specifically because the DB table doesn't exist yet or the handler doesn't emit -- adjust ordering as needed; the important verification is Step 7 passing after all edits land.)

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/api/... -run TestCancelJob_EmitsJobCancelledNotification -v`
Expected: PASS

- [ ] **Step 8: Run the existing `TestCancelJob_CancelsPendingTargetsAndJob` and `TestCancelJob_NotFound_404` to confirm the nil-guard on `h.notifications` works**

Run: `go test ./internal/api/... -run 'TestCancelJob_CancelsPendingTargetsAndJob|TestCancelJob_NotFound_404' -v`
Expected: PASS — both tests construct `Handler` without `.WithNotifications(...)`, proving `if h.notifications != nil` in `CancelJob` protects them.

- [ ] **Step 9: Commit**

```bash
git add internal/api/notifications_dispatch.go internal/api/handlers.go internal/api/job_dispatch.go internal/api/job_handlers.go internal/api/job_handlers_test.go
git commit -m "feat(api): wire notification emission into CancelJob and the Job Engine dispatcher"
git push
```

---

### Task 6: Read/config API surface — `GET /api/notifications`, webhook CRUD

**Files:**
- Create: `orchestrator/internal/api/notification_handlers.go`
- Test: `orchestrator/internal/api/notification_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `notifications.Store`/`Event`/`Webhook`/`ListFilter` (Tasks 1-2), `h.notifications` reaching into its store via a new accessor OR a separate `h.notificationsStore` field -- see Step 1 for the exact resolution.
- Produces: `(*Handler).GetNotifications`, `(*Handler).CreateNotificationWebhook`, `(*Handler).ListNotificationWebhooks`, `(*Handler).DeleteNotificationWebhook`.

- [ ] **Step 1: Add a `notificationsStore` field to `Handler` for direct read/config access**

`h.notifications` (the `*notifications.Service`) only exposes `Emit` -- reads and webhook config CRUD need the underlying `*notifications.Store` directly, same split `jobsStore`/`jobs.Dispatcher` already has (`Handler` holds `jobsStore *jobs.Store` separately from the `*jobs.Dispatcher` passed to `WithJobsDispatcher`). Add to `Handler` (`internal/api/handlers.go`, next to the `notifications` field added in Task 5):

```go
	notifications         *notifications.Service // nil when not loaded — Phase 7 job-event notifications
	notificationsStore    *notifications.Store    // nil when not loaded — direct read/config access for handlers
```

Update `WithNotifications` in `internal/api/notifications_dispatch.go` (Task 5) to also set it:

```go
func (h *Handler) WithNotifications(store *notifications.Store) *Handler {
	h.notificationsStore = store
	h.notifications = notifications.NewService(store, h.hub)
	return h
}
```

- [ ] **Step 2: Write the failing test**

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetNotifications_ReturnsFilteredList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gnl-a1', 'GNL-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"gnl-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		notifStore := notifications.NewStore(pool)
		notifStore.Insert(context.Background(), notifications.Event{
			Type: notifications.EventJobCompleted, JobID: job.ID, Severity: notifications.SeverityInfo,
			Message: "done", Timestamp: time.Now().UTC(),
		})

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)
		req := httptest.NewRequest(http.MethodGet, "/api/notifications?jobId="+job.ID, nil)
		w := httptest.NewRecorder()
		h.GetNotifications(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Notifications []notifications.Event `json:"notifications"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Notifications) != 1 || resp.Notifications[0].JobID != job.ID {
			t.Fatalf("got %+v, want exactly the one event for job %s", resp.Notifications, job.ID)
		}
	})
}

func TestNotificationWebhooks_CreateListDeleteRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithNotifications(notifStore)

		body, _ := json.Marshal(map[string]any{"name": "ops-slack", "url": "https://example.test/hook", "secret": "s3cret", "minSeverity": "warning", "enabled": true})
		req := httptest.NewRequest(http.MethodPost, "/api/notification-webhooks", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.CreateNotificationWebhook(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("create status = %d, body = %s", w.Code, w.Body.String())
		}
		var created struct{ ID string `json:"id"` }
		json.Unmarshal(w.Body.Bytes(), &created)
		if created.ID == "" {
			t.Fatal("CreateNotificationWebhook returned empty id")
		}

		w = httptest.NewRecorder()
		h.ListNotificationWebhooks(w, httptest.NewRequest(http.MethodGet, "/api/notification-webhooks", nil))
		var listed struct {
			Webhooks []map[string]any `json:"webhooks"`
		}
		json.Unmarshal(w.Body.Bytes(), &listed)
		if len(listed.Webhooks) != 1 || listed.Webhooks[0]["secret"] != "***" {
			t.Fatalf("listed = %+v, want 1 webhook with secret redacted to ***", listed.Webhooks)
		}

		req = withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID)
		w = httptest.NewRecorder()
		h.DeleteNotificationWebhook(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("delete status = %d, body = %s", w.Code, w.Body.String())
		}
		all, _ := notifStore.ListWebhooks(context.Background())
		if len(all) != 0 {
			t.Fatalf("webhooks after delete = %+v, want empty", all)
		}
	})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/api/... -run 'TestGetNotifications_ReturnsFilteredList|TestNotificationWebhooks_CreateListDeleteRoundTrip' -v`
Expected: FAIL — `h.GetNotifications undefined` etc.

- [ ] **Step 4: Write `notification_handlers.go`**

```go
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/notifications"
)

// GetNotifications returns notification history, most-recent first.
// Query params: limit (default 100, max 500), offset, jobId, severity, type.
// GET /api/notifications
func (h *Handler) GetNotifications(w http.ResponseWriter, r *http.Request) {
	if h.notificationsStore == nil {
		respond(w, map[string]any{"notifications": []any{}})
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	filter := notifications.ListFilter{
		JobID:    r.URL.Query().Get("jobId"),
		Severity: r.URL.Query().Get("severity"),
		Type:     r.URL.Query().Get("type"),
		Limit:    limit,
		Offset:   offset,
	}
	events, err := h.notificationsStore.List(r.Context(), filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"notifications": events})
}

// ── Webhook config CRUD (Admin only) ────────────────────────────────────────

// CreateNotificationWebhook creates a new outbound webhook config.
// POST /api/notification-webhooks  body: {name, url, secret, minSeverity, enabled}
func (h *Handler) CreateNotificationWebhook(w http.ResponseWriter, r *http.Request) {
	if h.notificationsStore == nil {
		jsonError(w, "notifications not loaded", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Secret      string `json:"secret"`
		MinSeverity string `json:"minSeverity"`
		Enabled     bool   `json:"enabled"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" || req.URL == "" {
		jsonError(w, "name and url are required", http.StatusBadRequest)
		return
	}
	validSev := map[string]bool{"info": true, "warning": true, "error": true, "critical": true}
	if req.MinSeverity == "" {
		req.MinSeverity = "warning"
	}
	if !validSev[req.MinSeverity] {
		jsonError(w, "minSeverity must be info | warning | error | critical", http.StatusBadRequest)
		return
	}
	id, err := h.notificationsStore.CreateWebhook(r.Context(), notifications.Webhook{
		Name: req.Name, URL: req.URL, Secret: req.Secret, MinSeverity: req.MinSeverity, Enabled: req.Enabled,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "notifications.webhook_created", id, map[string]any{"name": req.Name}, "ok")
	respond(w, map[string]any{"id": id})
}

// ListNotificationWebhooks lists all configured webhooks with secrets redacted.
// GET /api/notification-webhooks
func (h *Handler) ListNotificationWebhooks(w http.ResponseWriter, r *http.Request) {
	if h.notificationsStore == nil {
		respond(w, map[string]any{"webhooks": []any{}})
		return
	}
	hooks, err := h.notificationsStore.ListWebhooks(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(hooks))
	for _, hook := range hooks {
		secret := ""
		if hook.Secret != "" {
			secret = "***"
		}
		out = append(out, map[string]any{
			"id": hook.ID, "name": hook.Name, "url": hook.URL, "secret": secret,
			"minSeverity": hook.MinSeverity, "enabled": hook.Enabled, "createdAt": hook.CreatedAt,
		})
	}
	respond(w, map[string]any{"webhooks": out})
}

// DeleteNotificationWebhook deletes a webhook config.
// DELETE /api/notification-webhooks/{id}
func (h *Handler) DeleteNotificationWebhook(w http.ResponseWriter, r *http.Request) {
	if h.notificationsStore == nil {
		jsonError(w, "notifications not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.notificationsStore.DeleteWebhook(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "notifications.webhook_deleted", id, nil, "ok")
	respond(w, map[string]any{"id": id, "deleted": true})
}
```

- [ ] **Step 5: Register the 3 routes**

In `internal/api/routes.go`, add after the existing `maintenance-freezes` routes (currently lines 504-506):

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/notifications", h.GetNotifications)
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Post("/api/notification-webhooks", h.CreateNotificationWebhook)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/notification-webhooks", h.ListNotificationWebhooks)
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Delete("/api/notification-webhooks/{id}", h.DeleteNotificationWebhook)
```

(`ListNotificationWebhooks` uses `CanExecuteRemediation` — read-only, no secret exposed since it's redacted — matching `ListAgentFreezes`'s same read/write RBAC split.)

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/api/... -run 'TestGetNotifications_ReturnsFilteredList|TestNotificationWebhooks_CreateListDeleteRoundTrip' -v`
Expected: PASS

- [ ] **Step 7: Add RBAC matrix rows**

In `internal/api/rbac_matrix_test.go`, add after the existing `maintenance-freezes` rows (currently lines 273-275):

```go
	{http.MethodGet, "/api/notifications", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/notification-webhooks", tierPermission, auth.CanApproveRemediation},
	{http.MethodGet, "/api/notification-webhooks", tierPermission, auth.CanExecuteRemediation},
	{http.MethodDelete, "/api/notification-webhooks/{id}", tierPermission, auth.CanApproveRemediation},
```

Run: `go test ./internal/api/... -run TestRBACMatrix -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/api/notification_handlers.go internal/api/notification_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/handlers.go internal/api/notifications_dispatch.go
git commit -m "feat(api): add GET /api/notifications and notification-webhooks config CRUD"
git push
```

---

### Task 7: Wire into `main.go` and run the full suite

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `notifications.NewStore` (Task 2), `(*Handler).WithNotifications` (Task 5).

- [ ] **Step 1: Add the wiring**

In `cmd/server/main.go`, add near the Fleet Job Engine setup (currently lines 419-425, right after `jobsScheduler := exercise.NewPollScheduler(5 * time.Second)`):

```go
	// Phase 7 -- Job-Event Notifications. No separate ticker: events are
	// emitted synchronously from jobsDispatcher.Tick() and CancelJob via
	// the NotifyFn hook wired in WithJobsDispatcher/WithNotifications below.
	notificationsStore := notifications.NewStore(pool)
```

Add `.WithNotifications(notificationsStore)` to the handler chain (currently lines 428-451), placed right after `.WithJobsDispatcher(jobsStore, jobsDispatcher).` (line 440):

```go
		WithJobsDispatcher(jobsStore, jobsDispatcher).
		WithNotifications(notificationsStore).
```

Add the import `"github.com/audspect/bas/internal/notifications"` to `main.go`'s import block.

- [ ] **Step 2: Build the full binary**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 3: Run the full test suite**

Run: `go test ./... 2>&1 | tail -100`
Expected: no `FAIL` lines. If a package fails, re-run that specific package alone (`go test ./internal/X/... -v`) before concluding it's a real regression — this codebase has twice seen full-suite-only failures from Docker/testcontainer resource contention across ~50 concurrent packages (see the `project_endpoint_health_remediation` memory's recurring-gotchas section); a package that passes clean in isolation was contention, not a bug.

- [ ] **Step 4: Commit**

```bash
git add cmd/server/main.go
git commit -m "feat(server): wire Job-Event Notifications into main.go"
git push
```

---

## Self-Review Notes (fixed inline, listed here for the executing engineer's awareness)

- **Spec coverage:** All 7 spec sections (event model, persistence, emission hooks, delivery, API surface, testing, dependencies) map onto Tasks 1-7. The 2 grounding fixes made to the spec during plan-writing (2nd `TargetFailed` call site at `dispatch.go:110`; explicit nil-guard requirement) are both reflected in Task 4/5's code.
- **Nil-guard consistency:** Task 4 guards `d.notify != nil` in `internal/jobs` (protects that package's own tests, which never call `SetNotify`). Task 5 guards `h.notifications != nil` in `internal/api` (protects every pre-existing `Handler` built without `.WithNotifications(...)`, e.g. `TestCancelJob_CancelsPendingTargetsAndJob`). Task 5 Step 3 clarifies `WithJobsDispatcher` always calls `SetNotify`, so the `internal/jobs`-level guard and the `internal/api`-level guard protect two different scenarios, not a redundant double-check.
- **Type consistency check:** `jobs.NotifyEvent.Type`/`.Severity` (plain strings) are populated in Task 4 using `notifyType*`/`notifySeverity*` local constants; Task 5's `dispatchJobNotify` casts them to `notifications.EventType(evt.Type)` / `notifications.Severity(evt.Severity)`. Verified the string literals match exactly between `internal/jobs/notify.go` (Task 4) and `internal/notifications/types.go` (Task 1): `"job_started"`, `"job_completed"`, `"job_partially_completed"`, `"job_failed"`, `"target_failed"`, `"target_deferred"`, `"info"`, `"warning"`, `"error"`, `"critical"` — all identical.
- **`AgentFreeze` API name correction:** memory of Sub-project 7 initially suggested a `CreateAgentFreeze(ctx, agentID, from, to, reason, createdBy)` free-args signature; a fresh read of `internal/jobs/freeze.go` during plan self-review found the real API is `CreateFreeze(ctx context.Context, f AgentFreeze) (AgentFreeze, error)` taking the `AgentFreeze{AgentID, FromAt, ToAt, Reason, CreatedBy}` struct. Task 4 Step 6's test uses the verified real signature.
- **`itoa` helper (Task 2):** initially drafted as a hand-rolled function, then corrected in the same step to use `strconv.Itoa` instead, matching `internal/api/audit.go`'s existing identical pattern — left the correction inline rather than silently writing it right, so the executing engineer sees the reasoning.
