package jobs

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// List returns Jobs, newest first, optionally filtered by initiative_id.
// initiativeID == nil means no filter (every job); a non-nil pointer to ""
// filters to unassigned jobs; a non-nil pointer to a real ID filters to
// that Initiative's jobs. General-purpose (not Initiative-feature-specific
// despite the one filter dimension it currently has) -- the caller decides
// what filter, if any, to apply.
func (s *Store) List(ctx context.Context, initiativeID *string) ([]Job, error) {
	var rows pgx.Rows
	var err error
	const cols = `id, type, state, payload, created_by, created_at, started_at, completed_at, scheduled_at, concurrency_limit, initiative_id`
	if initiativeID == nil {
		rows, err = s.pool.Query(ctx, `SELECT `+cols+` FROM jobs ORDER BY created_at DESC`)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT `+cols+` FROM jobs WHERE initiative_id=$1 ORDER BY created_at DESC`, *initiativeID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Type, &j.State, &j.Payload, &j.CreatedBy, &j.CreatedAt, &j.StartedAt, &j.CompletedAt, &j.ScheduledAt, &j.ConcurrencyLimit, &j.InitiativeID); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
