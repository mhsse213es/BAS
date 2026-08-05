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
		var created struct {
			ID string `json:"id"`
		}
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
