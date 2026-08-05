package notifications

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExecNotif(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("mustExecNotif: %v\nsql: %s", err, sql)
	}
}

func TestInsertAndList_RoundTripsEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, created_by, state)
			VALUES ('job-store-1', 'batch_remediation', '{}', 'user-1', 'requested')`)
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
		mustExecNotif(t, pool, `INSERT INTO jobs (id, type, payload, created_by, state)
			VALUES ('job-store-2', 'batch_remediation', '{}', 'user-1', 'requested')`)
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
