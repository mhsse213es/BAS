package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/slapolicy"
	"github.com/go-chi/chi/v5"
)

// TickSLABreaches scans finding_slas for active episodes whose deadline has
// been reached or passed, flips each to breached, and emits one
// notifications.Event per breach. Driven by a 5-minute exercise.PollScheduler
// registered in cmd/server/main.go, mirroring jobsDispatcher.Tick's pattern.
// Idempotent by construction: the UPDATE's own "AND status='active'" guard
// plus checking RowsAffected means a row can only ever be breached-and-
// notified once, even across concurrent or overlapping ticks.
func (h *Handler) TickSLABreaches(ctx context.Context) error {
	rows, err := h.db.Query(ctx,
		`SELECT fs.id, fs.deadline_at, pf.agent_id, pf.check_id, pf.title, pf.severity
		   FROM finding_slas fs
		   JOIN posture_findings pf ON pf.id = fs.posture_finding_id
		  WHERE fs.status = 'active' AND fs.deadline_at <= NOW()`)
	if err != nil {
		return err
	}
	type candidate struct {
		id, agentID, checkID, title, severity string
		deadlineAt                            time.Time
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if rows.Scan(&c.id, &c.deadlineAt, &c.agentID, &c.checkID, &c.title, &c.severity) != nil {
			continue
		}
		candidates = append(candidates, c)
	}
	rows.Close()

	for _, c := range candidates {
		if !slapolicy.EvaluateSLABreach(c.deadlineAt, time.Now()) {
			continue
		}
		tag, err := h.db.Exec(ctx,
			`UPDATE finding_slas SET status='breached', breached_at=NOW() WHERE id=$1 AND status='active'`, c.id)
		if err != nil || tag.RowsAffected() == 0 {
			continue // already handled (concurrent tick) or write failed -- next tick re-evaluates from the query above
		}
		if h.notifications == nil {
			continue
		}
		h.notifications.Emit(ctx, notifications.Event{
			Type:     notifications.EventSLABreached,
			AgentID:  c.agentID,
			Severity: slaNotifySeverity(c.severity),
			Message:  fmt.Sprintf("SLA breached: %s (%s) on %s", c.title, c.checkID, c.agentID),
			Metadata: map[string]any{
				"findingSlaId": c.id, "checkId": c.checkID, "severity": c.severity, "deadlineAt": c.deadlineAt,
			},
		})
	}
	return nil
}

var validSLASeverities = map[string]bool{"Critical": true, "High": true, "Medium": true, "Low": true}

// ListSLAPolicies returns all 4 severity->deadline rows. GET /api/sla/policies
func (h *Handler) ListSLAPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `SELECT severity, duration_hours, updated_at, updated_by FROM sla_policy ORDER BY severity`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var severity, updatedBy string
		var durationHours int
		var updatedAt time.Time
		if rows.Scan(&severity, &durationHours, &updatedAt, &updatedBy) != nil {
			continue
		}
		out = append(out, map[string]any{
			"severity": severity, "durationHours": durationHours,
			"updatedAt": updatedAt, "updatedBy": updatedBy,
		})
	}
	respond(w, out)
}

// UpdateSLAPolicy sets one severity's durationHours. Only affects future
// finding_slas episodes -- an existing row's deadline_at was already
// computed and is never recomputed. PATCH /api/sla/policies/{severity}
func (h *Handler) UpdateSLAPolicy(w http.ResponseWriter, r *http.Request) {
	severity := chi.URLParam(r, "severity")
	if !validSLASeverities[severity] {
		jsonError(w, "unknown severity", http.StatusNotFound)
		return
	}
	var body struct {
		DurationHours int `json:"durationHours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "malformed JSON", http.StatusBadRequest)
		return
	}
	if body.DurationHours < 1 || body.DurationHours > 8760 {
		jsonError(w, "durationHours must be between 1 and 8760", http.StatusBadRequest)
		return
	}
	_, err := h.db.Exec(r.Context(),
		`UPDATE sla_policy SET duration_hours=$1, updated_at=NOW(), updated_by=$2 WHERE severity=$3`,
		body.DurationHours, actorID(r), severity)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"severity": severity, "durationHours": body.DurationHours})
}

// GetSLABreaches returns every currently-breached finding, oldest breach
// first. GET /api/sla/breaches
func (h *Handler) GetSLABreaches(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT pf.agent_id, pf.check_id, pf.title, pf.severity, pf.category, fs.breached_at, fs.deadline_at
		   FROM finding_slas fs
		   JOIN posture_findings pf ON pf.id = fs.posture_finding_id
		  WHERE fs.status = 'breached'
		  ORDER BY fs.breached_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var agentID, checkID, title, severity, category string
		var breachedAt, deadlineAt time.Time
		if rows.Scan(&agentID, &checkID, &title, &severity, &category, &breachedAt, &deadlineAt) != nil {
			continue
		}
		out = append(out, map[string]any{
			"agentId": agentID, "checkId": checkID, "title": title, "severity": severity,
			"category": category, "breachedAt": breachedAt, "deadlineAt": deadlineAt,
		})
	}
	respond(w, out)
}

// slaNotifySeverity maps a posture finding's severity to a notification
// severity -- Critical/High elevate to the notification system's two
// highest tiers since those are the findings whose breach is operationally
// urgent; Medium/Low map to warning/info.
func slaNotifySeverity(severity string) notifications.Severity {
	switch severity {
	case "Critical":
		return notifications.SeverityCritical
	case "High":
		return notifications.SeverityError
	case "Low":
		return notifications.SeverityInfo
	default:
		return notifications.SeverityWarning
	}
}
