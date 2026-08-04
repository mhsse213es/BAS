package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCreateJobSchedule_ContinuousValidation_ThreadsIntoPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId":        "enable_windows_firewall",
			"reason":               "test",
			"agentIds":             []string{"sh-cv1"},
			"dayOfWeek":            1,
			"timeOfDay":            "09:00",
			"continuousValidation": true,
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateJobSchedule(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ScheduleID string `json:"scheduleId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)

		var raw []byte
		if err := pool.QueryRow(context.Background(), `SELECT payload FROM job_schedules WHERE id=$1`, resp.ScheduleID).Scan(&raw); err != nil {
			t.Fatalf("query schedule: %v", err)
		}
		var payload batchRemediationPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if !payload.ContinuousValidation {
			t.Error("payload.ContinuousValidation = false, want true")
		}
	})
}

func TestCreateJobSchedule_CreatesEnabledSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "weekly hardening",
			"agentIds":      []string{"sch-a1", "sch-a2"},
			"dayOfWeek":     5,
			"timeOfDay":     "23:00",
			"timezone":      "Asia/Kolkata",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateJobSchedule(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ScheduleID string `json:"scheduleId"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got, err := jobsStore.GetSchedule(context.Background(), resp.ScheduleID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if !got.Enabled || got.DayOfWeek != 5 || got.TimeOfDay != "23:00" || got.Timezone != "Asia/Kolkata" || len(got.AgentIDs) != 2 {
			t.Errorf("got = %+v, want Enabled=true DayOfWeek=5 TimeOfDay=23:00 Timezone=Asia/Kolkata 2 AgentIDs", got)
		}
	})
}

func TestCreateJobSchedule_Tier2WithoutApprovePermission_Forbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId": "disable_windows_smbv1", // Tier 2
			"reason":        "test",
			"agentIds":      []string{"sch-a3"},
			"dayOfWeek":     5,
			"timeOfDay":     "23:00",
			"timezone":      "UTC",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateJobSchedule(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})
}

func TestCreateJobSchedule_InvalidTimezone_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithRemediationCatalog(cat).
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"remediationId": "enable_windows_firewall",
			"reason":        "test",
			"agentIds":      []string{"sch-a4"},
			"dayOfWeek":     5,
			"timeOfDay":     "23:00",
			"timezone":      "Not/A_Real_Zone",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "user-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateJobSchedule(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for an invalid timezone", w.Code)
		}
	})
}

func TestListJobSchedules_ReturnsCreatedSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		h.ListJobSchedules(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Schedules []jobs.Schedule `json:"schedules"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		found := false
		for _, sch := range resp.Schedules {
			if sch.ID == created.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("ListJobSchedules() did not include %s", created.ID)
		}
	})
}

func TestCancelJobSchedule_Disables(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		created, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "scheduleId", created.ID)
		w := httptest.NewRecorder()
		h.CancelJobSchedule(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.Enabled {
			t.Error("Enabled = true, want false after cancel")
		}
	})
}
