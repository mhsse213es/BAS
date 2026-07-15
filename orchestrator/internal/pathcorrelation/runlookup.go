package pathcorrelation

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
)

// SQLRunLookup is the production RunLookup: it queries verification_history
// directly (Record already denormalizes technique_id onto every row, so no
// join through internal/scenario's step/expectation resolution is needed).
type SQLRunLookup struct {
	db *pgxpool.Pool
}

// NewSQLRunLookup returns a RunLookup backed by db.
func NewSQLRunLookup(db *pgxpool.Pool) *SQLRunLookup {
	return &SQLRunLookup{db: db}
}

type verifiedRow struct {
	RunID      string
	Hostname   string
	Provider   string
	AlertID    string
	VerifiedAt time.Time
}

// VerifiedDetection reports whether techniqueID has ever been verified as
// Detected+Approved. A row whose run's agent hostname matches hostname
// (normalized) wins with ConfidenceHost even if it is not the newest row
// overall; otherwise the most recent row anywhere is returned with
// ConfidenceEnvironment. hostname == "" always yields the most recent row
// (ConfidenceEnvironment).
func (l *SQLRunLookup) VerifiedDetection(ctx context.Context, techniqueID, hostname string) (VerificationResult, bool, error) {
	rows, err := l.db.Query(ctx, `
		SELECT sr.id, COALESCE(a.hostname, ''), vh.provider, COALESCE(vh.alert_id, ''), vh.verified_at
		FROM verification_history vh
		JOIN scenario_runs sr ON sr.id = vh.run_id
		LEFT JOIN agents a ON a.agent_id = sr.agent_id
		WHERE vh.active
		  AND vh.technique_id = $1
		  AND vh.result = 'Detected'
		  AND vh.workflow_state = 'Approved'
		ORDER BY vh.verified_at DESC
		LIMIT 200`, techniqueID)
	if err != nil {
		return VerificationResult{}, false, err
	}
	defer rows.Close()

	var all []verifiedRow
	target := attackpath.NormalizeHostKey(hostname)
	for rows.Next() {
		var v verifiedRow
		if err := rows.Scan(&v.RunID, &v.Hostname, &v.Provider, &v.AlertID, &v.VerifiedAt); err != nil {
			return VerificationResult{}, false, err
		}
		all = append(all, v)
	}
	if err := rows.Err(); err != nil {
		return VerificationResult{}, false, err
	}
	if len(all) == 0 {
		return VerificationResult{}, false, nil
	}

	if target != "" {
		for _, v := range all {
			if attackpath.NormalizeHostKey(v.Hostname) == target {
				return resultFrom(v, ConfidenceHost), true, nil
			}
		}
	}
	return resultFrom(all[0], ConfidenceEnvironment), true, nil
}

func resultFrom(v verifiedRow, confidence VerificationConfidence) VerificationResult {
	ev := Evidence{
		RunID:    v.RunID,
		Provider: v.Provider,
	}
	if v.AlertID != "" {
		ev.AlertIDs = []string{v.AlertID}
	}
	verifiedAt := v.VerifiedAt
	ev.VerifiedAt = &verifiedAt
	return VerificationResult{Confidence: confidence, Evidence: ev}
}
