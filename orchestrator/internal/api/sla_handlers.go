package api

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/slapolicy"
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
