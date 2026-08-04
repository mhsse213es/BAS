package api

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/driftanalytics"
)

// normalizeVerificationStatus maps a technique_verification_runs.status
// value to driftanalytics' binary "pass"/"fail". Only ever called with
// "pass"/"blocked"/"fail" -- callers filter error/skipped out in SQL
// before this function is reached. blocked normalizes to pass, matching
// the "pass, blocked" success bucket used everywhere else in this
// codebase (the control prevented the technique from running).
func normalizeVerificationStatus(status string) string {
	if status == "fail" {
		return "fail"
	}
	return "pass"
}

// verificationOutcomesForPair returns one control's full pooled history
// across every remediation request ever made for it (agentID, checkID),
// ordered oldest-first.
func (h *Handler) verificationOutcomesForPair(ctx context.Context, agentID, checkID string) ([]driftanalytics.VerificationOutcome, error) {
	rows, err := h.db.Query(ctx,
		`SELECT status, completed_at FROM technique_verification_runs
		 WHERE agent_id=$1 AND check_id=$2 AND completed_at IS NOT NULL AND status IN ('pass','blocked','fail')
		 ORDER BY completed_at ASC`, agentID, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var outcomes []driftanalytics.VerificationOutcome
	for rows.Next() {
		var status string
		var at time.Time
		if err := rows.Scan(&status, &at); err != nil {
			return nil, err
		}
		outcomes = append(outcomes, driftanalytics.VerificationOutcome{Result: normalizeVerificationStatus(status), At: at})
	}
	return outcomes, rows.Err()
}

// verificationOutcomesByCheckForAgent groups one agent's full history by
// check_id in a single query, avoiding one round-trip per check.
func (h *Handler) verificationOutcomesByCheckForAgent(ctx context.Context, agentID string) (map[string][]driftanalytics.VerificationOutcome, error) {
	rows, err := h.db.Query(ctx,
		`SELECT check_id, status, completed_at FROM technique_verification_runs
		 WHERE agent_id=$1 AND completed_at IS NOT NULL AND status IN ('pass','blocked','fail')
		 ORDER BY check_id, completed_at ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grouped := map[string][]driftanalytics.VerificationOutcome{}
	for rows.Next() {
		var checkID, status string
		var at time.Time
		if err := rows.Scan(&checkID, &status, &at); err != nil {
			return nil, err
		}
		grouped[checkID] = append(grouped[checkID], driftanalytics.VerificationOutcome{Result: normalizeVerificationStatus(status), At: at})
	}
	return grouped, rows.Err()
}

// driftPairKey identifies one control on one endpoint.
type driftPairKey struct {
	AgentID string
	CheckID string
}

// verificationOutcomesByPairFleetWide groups every control's full history
// by (agent_id, check_id) across the whole fleet in a single query.
func (h *Handler) verificationOutcomesByPairFleetWide(ctx context.Context) (map[driftPairKey][]driftanalytics.VerificationOutcome, error) {
	rows, err := h.db.Query(ctx,
		`SELECT agent_id, check_id, status, completed_at FROM technique_verification_runs
		 WHERE completed_at IS NOT NULL AND status IN ('pass','blocked','fail')
		 ORDER BY agent_id, check_id, completed_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grouped := map[driftPairKey][]driftanalytics.VerificationOutcome{}
	for rows.Next() {
		var agentID, checkID, status string
		var at time.Time
		if err := rows.Scan(&agentID, &checkID, &status, &at); err != nil {
			return nil, err
		}
		key := driftPairKey{AgentID: agentID, CheckID: checkID}
		grouped[key] = append(grouped[key], driftanalytics.VerificationOutcome{Result: normalizeVerificationStatus(status), At: at})
	}
	return grouped, rows.Err()
}
