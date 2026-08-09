package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
)

// POST /api/scheduled-assessments
// Mode-conditional permission: posture needs CanExecuteRemediation (the
// same tier as batch remediation); telemetry needs CanApproveRemediation
// (Admin-only) PLUS a non-empty reason -- together these ARE the Scheduled
// Execution Authorization (see the design spec's "Execution mode and
// authorization" section). Lab mode is rejected outright: it can never be
// scheduled. Schedules are immutable -- there is no update endpoint;
// changing anything means cancelling this one and creating a new one,
// which is always freshly authorized by construction.
func (h *Handler) CreateScheduledAssessment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScenarioID       string     `json:"scenarioId"`
		Mode             string     `json:"mode"`
		Techniques       []string   `json:"techniques"`
		Steps            []int      `json:"steps"`
		AgentIDs         []string   `json:"agentIds"`
		GroupIDs         []int64    `json:"groupIds"`
		RecurrenceType   string     `json:"recurrenceType"`
		RunAt            *time.Time `json:"runAt"`
		DayOfWeek        int        `json:"dayOfWeek"`
		DayOfMonth       int        `json:"dayOfMonth"`
		TimeOfDay        string     `json:"timeOfDay"`
		Timezone         string     `json:"timezone"`
		EndDate          *time.Time `json:"endDate"`
		ConcurrencyLimit int        `json:"concurrencyLimit"`
		Reason           string     `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.ScenarioID == "" {
		jsonError(w, "scenarioId is required", http.StatusBadRequest)
		return
	}
	if req.Mode != "posture" && req.Mode != "telemetry" {
		jsonError(w, "mode must be posture or telemetry -- lab mode cannot be scheduled", http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 && len(req.GroupIDs) == 0 {
		jsonError(w, "at least one agentId or groupId is required", http.StatusBadRequest)
		return
	}
	switch req.RecurrenceType {
	case "once":
		if req.RunAt == nil {
			jsonError(w, "runAt is required for a once schedule", http.StatusBadRequest)
			return
		}
	case "daily":
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	case "weekly":
		if req.DayOfWeek < 0 || req.DayOfWeek > 6 {
			jsonError(w, "dayOfWeek must be 0-6", http.StatusBadRequest)
			return
		}
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	case "monthly":
		if req.DayOfMonth < 1 || req.DayOfMonth > 28 {
			jsonError(w, "dayOfMonth must be 1-28 (29-31 excluded -- not every month has them)", http.StatusBadRequest)
			return
		}
		if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
			jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
			return
		}
	default:
		jsonError(w, "recurrenceType must be once, daily, weekly, or monthly", http.StatusBadRequest)
		return
	}
	tz := req.Timezone
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		jsonError(w, "timezone is not a valid IANA name", http.StatusBadRequest)
		return
	}
	if h.engine == nil {
		jsonError(w, "scenario engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if _, ok := h.engine.Get(req.ScenarioID); !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}

	claims, _ := auth.ClaimsFrom(r.Context())
	var approvedBy string
	var approvedAt *time.Time
	approvalVersion := 0
	if req.Mode == "telemetry" {
		if claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation) {
			jsonError(w, "scheduling a telemetry-mode assessment requires an Administrator's standing authorization", http.StatusForbidden)
			return
		}
		if req.Reason == "" {
			jsonError(w, "reason is required to authorize a telemetry-mode schedule", http.StatusBadRequest)
			return
		}
		now := time.Now()
		approvedAt = &now
		approvalVersion = 1
		approvedBy = claims.UserID
	}

	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}

	payload, err := json.Marshal(scheduledAssessmentPayload{
		ScenarioID: req.ScenarioID, Mode: req.Mode, Techniques: req.Techniques, Steps: req.Steps,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sch, err := h.jobsStore.CreateSchedule(r.Context(), jobs.Schedule{
		Type: "scheduled_assessment", Payload: payload, AgentIDs: req.AgentIDs, GroupIDs: req.GroupIDs,
		RecurrenceType: req.RecurrenceType, RunAt: req.RunAt, DayOfWeek: req.DayOfWeek, DayOfMonth: req.DayOfMonth,
		TimeOfDay: req.TimeOfDay, Timezone: tz, EndDate: req.EndDate, ConcurrencyLimit: req.ConcurrencyLimit,
		Enabled: true, CreatedBy: actorID, Mode: req.Mode, ApprovedBy: approvedBy, ApprovedAt: approvedAt,
		ApprovalVersion: approvalVersion, Reason: req.Reason,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.create", sch.ID, map[string]any{
		"scenarioId": req.ScenarioID, "mode": req.Mode, "recurrenceType": req.RecurrenceType,
		"agentCount": len(req.AgentIDs), "groupCount": len(req.GroupIDs), "approvedBy": approvedBy,
	}, "created")
	respond(w, map[string]any{"scheduleId": sch.ID})
}

// GET /api/scheduled-assessments
func (h *Handler) ListScheduledAssessments(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	all, err := h.jobsStore.ListSchedules(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]jobs.Schedule, 0, len(all))
	for _, sch := range all {
		if sch.Type == "scheduled_assessment" {
			out = append(out, sch)
		}
	}
	respond(w, map[string]any{"schedules": out})
}

// POST /api/scheduled-assessments/{id}/cancel
func (h *Handler) CancelScheduledAssessment(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "id")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	sch, err := h.jobsStore.GetSchedule(r.Context(), scheduleID)
	if err != nil {
		jsonError(w, "schedule not found", http.StatusNotFound)
		return
	}
	if sch.Type != "scheduled_assessment" {
		jsonError(w, "not a scheduled assessment", http.StatusNotFound)
		return
	}
	if err := h.jobsStore.DisableSchedule(r.Context(), scheduleID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.cancel", scheduleID, nil, "cancelled")
	respond(w, map[string]any{"scheduleId": scheduleID, "enabled": false})
}
