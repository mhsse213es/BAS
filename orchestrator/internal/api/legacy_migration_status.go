package api

import (
	"net/http"
	"time"
)

type legacyMigrationBlockingAgent struct {
	AgentID  string    `json:"agentId"`
	Hostname string    `json:"hostname"`
	LastSeen time.Time `json:"lastSeen"`
}

type legacyMigrationUnattributed struct {
	LastSeen time.Time `json:"lastSeen"`
	Count    int       `json:"count"`
}

type legacyMigrationStatusResponse struct {
	Eligible             bool                           `json:"eligible"`
	LastLegacySeenAt     *time.Time                     `json:"lastLegacySeenAt"`
	DaysClean            int                            `json:"daysClean"`
	DaysRequired         int                            `json:"daysRequired"`
	BlockingAgents       []legacyMigrationBlockingAgent `json:"blockingAgents"`
	UnattributedRequests *legacyMigrationUnattributed   `json:"unattributedRequests"`
}

const legacyRetirementWindowDays = 30

// GetLegacyMigrationStatus is GET /api/agents/legacy-migration-status.
// Eligibility is computed live from MAX(last_seen_at) across BOTH the
// attributed and unattributed tables at query time -- never cached or
// frozen at the moment it first became eligible -- so a legacy request
// arriving after an operator's review but before they act on it correctly
// flips this back to false on the very next check. See the spec's
// "Retirement procedure" section's race-guard explanation.
func (h *Handler) GetLegacyMigrationStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var lastAttributed, lastUnattributed *time.Time
	_ = h.db.QueryRow(ctx, `SELECT MAX(last_seen_at) FROM legacy_transport_log`).Scan(&lastAttributed)
	_ = h.db.QueryRow(ctx, `SELECT MAX(last_seen_at) FROM legacy_transport_unattributed`).Scan(&lastUnattributed)

	lastSeen := latestNonNil(lastAttributed, lastUnattributed)

	eligible := true
	daysClean := legacyRetirementWindowDays
	if lastSeen != nil {
		elapsed := time.Since(*lastSeen)
		eligible = elapsed >= legacyRetirementWindowDays*24*time.Hour
		daysClean = int(elapsed.Hours() / 24)
		if daysClean > legacyRetirementWindowDays {
			daysClean = legacyRetirementWindowDays
		}
	}

	blocking := []legacyMigrationBlockingAgent{}
	if !eligible {
		rows, err := h.db.Query(ctx, `
			SELECT l.agent_id, COALESCE(a.hostname, ''), MAX(l.last_seen_at) AS last_seen
			FROM legacy_transport_log l
			LEFT JOIN agents a ON a.agent_id = l.agent_id
			WHERE l.last_seen_at >= NOW() - ($1 * INTERVAL '1 day')
			GROUP BY l.agent_id, a.hostname
			ORDER BY last_seen DESC`, legacyRetirementWindowDays)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var b legacyMigrationBlockingAgent
				if rows.Scan(&b.AgentID, &b.Hostname, &b.LastSeen) == nil {
					blocking = append(blocking, b)
				}
			}
		}
	}

	var unattributed *legacyMigrationUnattributed
	if lastUnattributed != nil && time.Since(*lastUnattributed) < legacyRetirementWindowDays*24*time.Hour {
		var count int
		_ = h.db.QueryRow(ctx,
			`SELECT COALESCE(SUM(request_count), 0) FROM legacy_transport_unattributed
			 WHERE last_seen_at >= NOW() - ($1 * INTERVAL '1 day')`, legacyRetirementWindowDays,
		).Scan(&count)
		unattributed = &legacyMigrationUnattributed{LastSeen: *lastUnattributed, Count: count}
	}

	respond(w, legacyMigrationStatusResponse{
		Eligible:             eligible,
		LastLegacySeenAt:     lastSeen,
		DaysClean:            daysClean,
		DaysRequired:         legacyRetirementWindowDays,
		BlockingAgents:       blocking,
		UnattributedRequests: unattributed,
	})
}

func latestNonNil(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.After(*b) {
		return a
	}
	return b
}
