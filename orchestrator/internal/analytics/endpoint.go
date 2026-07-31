package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

// EndpointPosture is the fleet-wide endpoint health summary: agent
// connectivity/lifecycle/binary-trust state plus derived EPP isolation
// state (there is no stored "currently isolated" flag -- it's computed
// from the latest completed isolate/release action_requests row per host).
type EndpointPostureSummary struct {
	TotalAgents          int `json:"totalAgents"`
	OnlineAgents         int `json:"onlineAgents"`
	OfflineAgents        int `json:"offlineAgents"`
	ActiveAgents         int `json:"activeAgents"`
	RestrictedAgents     int `json:"restrictedAgents"`
	QuarantinedAgents    int `json:"quarantinedAgents"`
	RetiredAgents        int `json:"retiredAgents"`
	UntrustedBinaryCount int `json:"untrustedBinaryCount"`
	CurrentlyIsolated    int `json:"currentlyIsolated"`
}

// EndpointPosture computes the fleet-wide endpoint posture summary.
func EndpointPosture(ctx context.Context, pool *pgxpool.Pool) (EndpointPostureSummary, error) {
	rows, err := pool.Query(ctx, `SELECT status, state, binary_trusted, last_update FROM agents`)
	if err != nil {
		return EndpointPostureSummary{}, err
	}
	defer rows.Close()

	var p EndpointPostureSummary
	now := time.Now()
	for rows.Next() {
		var status, state string
		var binaryTrusted bool
		var lastUpdate time.Time
		if err := rows.Scan(&status, &state, &binaryTrusted, &lastUpdate); err != nil {
			return EndpointPostureSummary{}, err
		}
		p.TotalAgents++
		if models.EffectiveAgentStatus(status, lastUpdate, now) == "offline" {
			p.OfflineAgents++
		} else {
			p.OnlineAgents++
		}
		switch models.AgentState(state) {
		case models.AgentStateActive:
			p.ActiveAgents++
		case models.AgentStateRestricted:
			p.RestrictedAgents++
		case models.AgentStateQuarantined:
			p.QuarantinedAgents++
		case models.AgentStateRetired:
			p.RetiredAgents++
		}
		if !binaryTrusted {
			p.UntrustedBinaryCount++
		}
	}
	if err := rows.Err(); err != nil {
		return EndpointPostureSummary{}, err
	}

	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT DISTINCT ON (target_identifier) type
			FROM action_requests
			WHERE target_type = 'hostname'
			  AND type IN ('endpoint.isolate', 'endpoint.release')
			  AND status = 'completed'
			ORDER BY target_identifier, requested_at DESC
		) latest
		WHERE latest.type = 'endpoint.isolate'`,
	).Scan(&p.CurrentlyIsolated)
	if err != nil {
		return EndpointPostureSummary{}, err
	}

	return p, nil
}
