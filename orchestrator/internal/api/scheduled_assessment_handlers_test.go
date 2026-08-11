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

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCreateScheduledAssessment_Posture_AnalystAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-h1"},
			"recurrenceType": "weekly", "dayOfWeek": 1, "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ScheduleID string `json:"scheduleId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		got, err := jobsStore.GetSchedule(context.Background(), resp.ScheduleID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.Mode != "posture" || got.ApprovedBy != "" || got.ApprovalVersion != 0 {
			t.Errorf("posture schedule should have no authorization captured, got Mode=%q ApprovedBy=%q ApprovalVersion=%d", got.Mode, got.ApprovedBy, got.ApprovalVersion)
		}
	})
}

func TestCreateScheduledAssessment_Telemetry_AnalystForbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-h2"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC", "reason": "test",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestCreateScheduledAssessment_Telemetry_AdminWithReason_CapturesAuthorization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-h3"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
			"reason": "quarterly detection validation, approved by CISO",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			ScheduleID string `json:"scheduleId"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		got, err := jobsStore.GetSchedule(context.Background(), resp.ScheduleID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.ApprovedBy != "admin-1" || got.ApprovalVersion != 1 || got.ApprovedAt == nil || got.Reason == "" {
			t.Errorf("got = %+v, want ApprovedBy=admin-1 ApprovalVersion=1 ApprovedAt=non-nil Reason=non-empty", got)
		}
	})
}

func TestCreateScheduledAssessment_TelemetryWithoutReason_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-h4"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestCreateScheduledAssessment_LabMode_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "lab", "agentIds": []string{"sa-h5"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateScheduledAssessment(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (lab mode must never be schedulable), body = %s", w.Code, w.Body.String())
		}
	})
}

func TestListScheduledAssessments_OnlyReturnsScheduledAssessmentType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		if _, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "batch_remediation", Payload: json.RawMessage(`{}`), AgentIDs: []string{"x"},
			DayOfWeek: 1, TimeOfDay: "02:00", Timezone: "UTC", Enabled: true,
		}); err != nil {
			t.Fatalf("seed batch_remediation schedule: %v", err)
		}
		if _, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"y"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "posture",
		}); err != nil {
			t.Fatalf("seed scheduled_assessment schedule: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		w := httptest.NewRecorder()
		h.ListScheduledAssessments(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Schedules []jobs.Schedule `json:"schedules"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, sch := range resp.Schedules {
			if sch.Type != "scheduled_assessment" {
				t.Errorf("got a %q schedule in the list, want only scheduled_assessment", sch.Type)
			}
		}
		if len(resp.Schedules) < 1 {
			t.Error("expected at least the one scheduled_assessment schedule seeded above")
		}
	})
}

func TestCancelScheduledAssessment_Disables(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"z"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "posture",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.CancelScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.Enabled {
			t.Error("schedule still enabled after cancel")
		}
	})
}

func TestUpdateScheduledAssessment_Posture_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{"scenarioId":"fixture-scenario","mode":"posture"}`),
			AgentIDs: []string{"sa-u1"}, RecurrenceType: "weekly", DayOfWeek: 1, TimeOfDay: "02:00",
			Timezone: "UTC", Enabled: true, Mode: "posture",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-u1", "sa-u2"},
			"recurrenceType": "daily", "timeOfDay": "03:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if len(got.AgentIDs) != 2 || got.RecurrenceType != "daily" || got.TimeOfDay != "03:00" {
			t.Errorf("got = %+v, want AgentIDs len 2, RecurrenceType=daily, TimeOfDay=03:00", got)
		}
	})
}

func TestUpdateScheduledAssessment_Telemetry_AnalystForbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-u3"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "posture",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-u3"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC", "reason": "test",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
		}
	})
}

func TestUpdateScheduledAssessment_Telemetry_AdminWithReason_ReapprovesAndIncrementsVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		approvedAt := time.Now().Add(-24 * time.Hour)
		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-u4"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "telemetry",
			ApprovedBy: "admin-0", ApprovedAt: &approvedAt, ApprovalVersion: 1, Reason: "original reason",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "telemetry", "agentIds": []string{"sa-u4"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
			"reason": "re-approved after target change",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.ApprovedBy != "admin-1" || got.ApprovalVersion != 2 || got.Reason != "re-approved after target change" {
			t.Errorf("got = %+v, want ApprovedBy=admin-1 ApprovalVersion=2 Reason='re-approved after target change'", got)
		}
		if got.ApprovedAt == nil || !got.ApprovedAt.After(approvedAt) {
			t.Errorf("ApprovedAt = %v, want non-nil and after the original %v", got.ApprovedAt, approvedAt)
		}
	})
}

func TestUpdateScheduledAssessment_ModeChangeToPosture_ClearsApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		approvedAt := time.Now()
		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-u5"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "telemetry",
			ApprovedBy: "admin-0", ApprovedAt: &approvedAt, ApprovalVersion: 1, Reason: "original reason",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-u5"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.ApprovedBy != "" || got.ApprovedAt != nil || got.ApprovalVersion != 0 || got.Reason != "" {
			t.Errorf("got = %+v, want approval fields cleared after mode change to posture", got)
		}
	})
}

func TestUpdateScheduledAssessment_RevivesCancelledSchedule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		sch, err := jobsStore.CreateSchedule(context.Background(), jobs.Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-u6"},
			RecurrenceType: "daily", TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, Mode: "posture",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		if err := jobsStore.DisableSchedule(context.Background(), sch.ID); err != nil {
			t.Fatalf("DisableSchedule: %v", err)
		}

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-u6"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", sch.ID)
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		got, err := jobsStore.GetSchedule(context.Background(), sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if !got.Enabled {
			t.Error("schedule should be re-enabled after edit, still disabled")
		}
	})
}

func TestUpdateScheduledAssessment_UnknownID_404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "fixture-check")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), eng, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		body, _ := json.Marshal(map[string]any{
			"scenarioId": "fixture-scenario", "mode": "posture", "agentIds": []string{"sa-u7"},
			"recurrenceType": "daily", "timeOfDay": "02:00", "timezone": "UTC",
		})
		req := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "analyst-1", Role: auth.RoleAnalyst}))
		req = withURLParam(req, "id", "does-not-exist")
		w := httptest.NewRecorder()
		h.UpdateScheduledAssessment(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body = %s", w.Code, w.Body.String())
		}
	})
}
