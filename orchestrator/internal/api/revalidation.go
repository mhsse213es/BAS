package api

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

// revalidationInterval is how often the loop scans for ITSM-resolved tickets
// that need a BAS re-run. 2 minutes keeps latency low without hammering the DB.
const revalidationInterval = 2 * time.Minute

// revalidationBatchSize caps how many re-runs are dispatched per tick so a
// sudden flood of ticket closures doesn't saturate all agents at once.
const revalidationBatchSize = 10

// StartRevalidationLoop starts the auto-revalidation background goroutine.
// When an ITSM ticket is resolved (via the inbound webhook), its finding is
// flagged revalidation_required=true. This loop detects those flags and
// auto-dispatches a targeted single-technique BAS re-run on the same agent,
// then clears the flag so the run is not dispatched twice.
//
// Each dispatched run is recorded in the audit log and broadcast to dashboard
// browsers via WebSocket so operators can see the automated activity without
// digging through logs.
func (h *Handler) StartRevalidationLoop(ctx context.Context) {
	ticker := time.NewTicker(revalidationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.runRevalidationTick(ctx)
		}
	}
}

type revalidationCandidate struct {
	ticketID       string
	findingID      string
	agentID        string
	techniqueID    string
	techniqueName  string
	lastScenarioID string
}

func (h *Handler) runRevalidationTick(ctx context.Context) {
	rows, err := h.db.Query(ctx, `
		SELECT ft.id, ft.finding_id,
		       f.agent_id, f.technique_id, f.technique_name,
		       COALESCE(sr.scenario_id, '') AS last_scenario_id
		  FROM finding_tickets ft
		  JOIN findings f ON f.id = ft.finding_id
		  LEFT JOIN scenario_runs sr ON sr.id = f.last_run_id
		 WHERE ft.revalidation_required = true
		   AND ft.status = 'resolved'
		   AND ft.revalidation_dispatched_at IS NULL
		   AND f.status != 'resolved'
		 ORDER BY ft.last_synced_at ASC
		 LIMIT $1`, revalidationBatchSize)
	if err != nil {
		log.Printf("[reval] query: %v", err)
		return
	}
	var candidates []revalidationCandidate
	for rows.Next() {
		var c revalidationCandidate
		if err := rows.Scan(&c.ticketID, &c.findingID, &c.agentID,
			&c.techniqueID, &c.techniqueName, &c.lastScenarioID); err != nil {
			continue
		}
		candidates = append(candidates, c)
	}
	rows.Close()

	for _, c := range candidates {
		h.dispatchRevalidation(ctx, c)
	}
}

func (h *Handler) dispatchRevalidation(ctx context.Context, c revalidationCandidate) {
	// Mark as dispatched immediately (before the actual dispatch) so a failure
	// mid-way doesn't trigger repeated re-dispatch on the next tick. A failed
	// dispatch is surfaced in logs; the operator can re-trigger manually.
	if _, err := h.db.Exec(ctx,
		`UPDATE finding_tickets SET revalidation_dispatched_at = NOW() WHERE id = $1`,
		c.ticketID,
	); err != nil {
		log.Printf("[reval] mark dispatched (finding %s): %v", c.findingID, err)
		return
	}

	sc := h.resolveRevalidationScenario(c.lastScenarioID, c.techniqueID)
	if sc == nil {
		log.Printf("[reval] no scenario found for technique %s (finding %s) — skipping auto-dispatch",
			c.techniqueID, c.findingID)
		h.hub.BroadcastBrowsers(models.WSMessage{
			Type:    models.MsgRevalidationStarted,
			AgentID: c.agentID,
			Data: map[string]any{
				"findingId":   c.findingID,
				"techniqueId": c.techniqueID,
				"status":      "no_scenario",
				"message":     "No scenario found for " + c.techniqueID + " — trigger re-validation manually",
			},
		})
		return
	}

	sysUser := "system"
	runID, skip, err := h.dispatchRun(ctx, sc, c.agentID, dispatchOpts{
		Mode:        "posture",
		Techniques:  []string{c.techniqueID},
		Reason:      "Auto-revalidation — ITSM ticket resolved for " + c.techniqueID,
		InitiatedBy: &sysUser,
	})
	if err != nil {
		log.Printf("[reval] dispatch failed (finding %s technique %s): %v", c.findingID, c.techniqueID, err)
		return
	}
	if skip != "" {
		log.Printf("[reval] dispatch skipped (finding %s technique %s): %s — will retry next tick",
			c.findingID, c.techniqueID, skip)
		// Agent busy or offline — reset so the loop retries on the next tick.
		h.db.Exec(ctx,
			`UPDATE finding_tickets SET revalidation_dispatched_at = NULL WHERE id = $1`,
			c.ticketID)
		return
	}

	log.Printf("[reval] auto-dispatched run %s for technique %s on agent %s (finding %s)",
		runID, c.techniqueID, c.agentID, c.findingID)

	// Audit trail — appears in Administration → Audit Logs as the system actor.
	h.db.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
		 VALUES ('system', 'revalidation.auto_dispatched', $1,
		         jsonb_build_object('findingId', $2::text, 'techniqueId', $3::text, 'runId', $4::text, 'agentId', $5::text),
		         'internal', 'ok')`,
		c.findingID, c.findingID, c.techniqueID, runID, c.agentID,
	)

	h.hub.BroadcastBrowsers(models.WSMessage{
		Type:    models.MsgRevalidationStarted,
		AgentID: c.agentID,
		Data: map[string]any{
			"findingId":     c.findingID,
			"techniqueId":   c.techniqueID,
			"techniqueName": c.techniqueName,
			"runId":         runID,
			"agentId":       c.agentID,
			"status":        "dispatched",
			"message":       "Auto-revalidating " + c.techniqueID + " — ITSM ticket was resolved",
		},
	})
}

// resolveRevalidationScenario returns the best scenario to re-run for a technique.
// Priority: (1) the original scenario that generated the finding; (2) any loaded
// ART scenario that lists the technique in its ArtTechniques field.
func (h *Handler) resolveRevalidationScenario(lastScenarioID, techniqueID string) *scenario.Scenario {
	if lastScenarioID != "" {
		if s, ok := h.engine.Get(lastScenarioID); ok {
			return s
		}
	}
	// Fall back: scan all scenarios for one that covers this technique.
	techUp := strings.ToUpper(techniqueID)
	for _, s := range h.engine.List() {
		for _, t := range s.ARTTechniques {
			if strings.ToUpper(t) == techUp {
				return s
			}
		}
	}
	return nil
}
