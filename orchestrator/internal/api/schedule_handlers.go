package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
)

// POST /api/job-schedules
// Same tier-gated permission logic as CreateBatchRemediationJob -- a
// schedule is "create this batch job, but recurring."
func (h *Handler) CreateJobSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RemediationID        string   `json:"remediationId"`
		Reason               string   `json:"reason"`
		AgentIDs             []string `json:"agentIds"`
		DayOfWeek            int      `json:"dayOfWeek"`
		TimeOfDay            string   `json:"timeOfDay"`
		Timezone             string   `json:"timezone"`
		ContinuousValidation bool     `json:"continuousValidation"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.RemediationID == "" {
		jsonError(w, "remediationId is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 {
		jsonError(w, "agentIds must contain at least one agent", http.StatusBadRequest)
		return
	}
	if req.DayOfWeek < 0 || req.DayOfWeek > 6 {
		jsonError(w, "dayOfWeek must be 0-6", http.StatusBadRequest)
		return
	}
	if _, _, err := parseTimeOfDayForAPI(req.TimeOfDay); err != nil {
		jsonError(w, "timeOfDay must be HH:MM (24h)", http.StatusBadRequest)
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
	if h.remediationCatalog == nil {
		jsonError(w, "remediation catalog not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := h.remediationCatalog.ByID(req.RemediationID)
	if !ok {
		jsonError(w, "unknown remediationId", http.StatusNotFound)
		return
	}
	if entry.Tier == remediation.TierManualGuidance {
		jsonError(w, "this remediation is manual guidance only -- no automatic execution", http.StatusUnprocessableEntity)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	if entry.Tier == remediation.TierConfirmRequired && (claims == nil || !auth.HasPermission(claims.Role, auth.CanApproveRemediation)) {
		jsonError(w, "this remediation requires an Administrator", http.StatusForbidden)
		return
	}
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}

	actorID := ""
	if claims != nil {
		actorID = claims.UserID
	}
	payload, err := json.Marshal(batchRemediationPayload{RemediationID: entry.ID, Reason: req.Reason, ContinuousValidation: req.ContinuousValidation})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sch, err := h.jobsStore.CreateSchedule(r.Context(), jobs.Schedule{
		Type: "batch_remediation", Payload: payload, AgentIDs: req.AgentIDs,
		DayOfWeek: req.DayOfWeek, TimeOfDay: req.TimeOfDay, Timezone: tz, Enabled: true, CreatedBy: actorID,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.create", sch.ID,
		map[string]any{"remediationId": entry.ID, "agentCount": len(req.AgentIDs), "dayOfWeek": req.DayOfWeek, "timeOfDay": req.TimeOfDay, "timezone": tz}, "created")
	respond(w, map[string]any{"scheduleId": sch.ID})
}

// GET /api/job-schedules
func (h *Handler) ListJobSchedules(w http.ResponseWriter, r *http.Request) {
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	schedules, err := h.jobsStore.ListSchedules(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"schedules": schedules})
}

// POST /api/job-schedules/{scheduleId}/cancel
func (h *Handler) CancelJobSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "scheduleId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	if _, err := h.jobsStore.GetSchedule(r.Context(), scheduleID); err != nil {
		jsonError(w, "schedule not found", http.StatusNotFound)
		return
	}
	if err := h.jobsStore.DisableSchedule(r.Context(), scheduleID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "jobs.schedule.cancel", scheduleID, nil, "cancelled")
	respond(w, map[string]any{"scheduleId": scheduleID, "enabled": false})
}

// parseTimeOfDayForAPI validates "HH:MM" without importing internal/jobs'
// unexported parseTimeOfDay -- kept deliberately tiny and duplicated rather
// than exporting a package-internal helper solely for this one call site.
func parseTimeOfDayForAPI(s string) (hour, minute int, err error) {
	var h2, m2 int
	n, scanErr := fmt.Sscanf(s, "%d:%d", &h2, &m2)
	if scanErr != nil || n != 2 || h2 < 0 || h2 > 23 || m2 < 0 || m2 > 59 {
		return 0, 0, fmt.Errorf("invalid time-of-day %q", s)
	}
	return h2, m2, nil
}
