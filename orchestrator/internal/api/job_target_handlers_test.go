package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestAssignJobTarget_SetsOwnerAndEmitsNotification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ajt-a1', 'AJT-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"ajt-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := jobsStore.ListTargets(context.Background(), job.ID)

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithNotifications(notifStore)

		body, _ := json.Marshal(map[string]string{"ownerId": "user-99"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "targetId", targets[0].ID)
		w := httptest.NewRecorder()
		h.AssignJobTarget(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		got, err := jobsStore.ListTargets(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("ListTargets: %v", err)
		}
		if got[0].OwnerID != "user-99" || got[0].AssignedAt == nil {
			t.Fatalf("got = %+v, want OwnerID=user-99 AssignedAt set", got[0])
		}

		events, err := notifStore.List(context.Background(), notifications.ListFilter{JobID: job.ID, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 1 || events[0].Type != notifications.EventTargetAssigned {
			t.Fatalf("events = %+v, want exactly one target_assigned event", events)
		}
	})
}

func TestAssignJobTarget_ClearingOwnerEmitsNoNotification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('ajt-a2', 'AJT-A2')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"ajt-a2"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := jobsStore.ListTargets(context.Background(), job.ID)
		if _, err := jobsStore.SetTargetOwner(context.Background(), targets[0].ID, "user-99"); err != nil {
			t.Fatalf("SetTargetOwner: %v", err)
		}

		notifStore := notifications.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore)).
			WithNotifications(notifStore)

		body, _ := json.Marshal(map[string]string{"ownerId": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "targetId", targets[0].ID)
		w := httptest.NewRecorder()
		h.AssignJobTarget(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		events, err := notifStore.List(context.Background(), notifications.ListFilter{JobID: job.ID, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("events = %+v, want none for a clear-ownership action", events)
		}
	})
}

func TestAssignJobTarget_NotFound_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		body, _ := json.Marshal(map[string]string{"ownerId": "user-1"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "targetId", "no-such-target")
		w := httptest.NewRecorder()
		h.AssignJobTarget(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestGetJobTargetsByOwner_ReturnsAcrossJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('gjt-a1', 'GJT-A1')`)
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(context.Background(), "batch_remediation", payload, "user-1", []string{"gjt-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		targets, _ := jobsStore.ListTargets(context.Background(), job.ID)
		if _, err := jobsStore.SetTargetOwner(context.Background(), targets[0].ID, "owner-q"); err != nil {
			t.Fatalf("SetTargetOwner: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := httptest.NewRequest(http.MethodGet, "/api/job-targets?ownerId=owner-q", nil)
		w := httptest.NewRecorder()
		h.GetJobTargetsByOwner(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Targets []jobs.JobTarget `json:"targets"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Targets) != 1 || resp.Targets[0].OwnerID != "owner-q" {
			t.Fatalf("got %+v, want exactly the one owned target", resp.Targets)
		}
	})
}

func TestGetJobTargetsByOwner_MissingOwnerId_400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := httptest.NewRequest(http.MethodGet, "/api/job-targets", nil)
		w := httptest.NewRecorder()
		h.GetJobTargetsByOwner(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})
}
