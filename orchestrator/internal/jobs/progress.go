package jobs

import "context"

// JobProgress is a computed summary of one job's target-state
// distribution -- never persisted, always derived fresh from job_targets.
type JobProgress struct {
	Total           int
	Pending         int
	Dispatched      int
	Completed       int
	Failed          int
	Cancelled       int
	Deferred        int
	PercentComplete float64 // (Completed+Failed+Cancelled) / Total * 100; 0 if Total == 0
}

// ComputeProgress derives one job's JobProgress via a grouped count over
// job_targets -- at most 6 rows regardless of target count, never fetches
// individual target rows.
func (s *Store) ComputeProgress(ctx context.Context, jobID string) (JobProgress, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT state, COUNT(*) FROM job_targets WHERE job_id=$1 GROUP BY state`, jobID)
	if err != nil {
		return JobProgress{}, err
	}
	defer rows.Close()

	var p JobProgress
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return JobProgress{}, err
		}
		switch state {
		case TargetStatePending:
			p.Pending = count
		case TargetStateDispatched:
			p.Dispatched = count
		case TargetStateCompleted:
			p.Completed = count
		case TargetStateFailed:
			p.Failed = count
		case TargetStateCancelled:
			p.Cancelled = count
		case TargetStateDeferred:
			p.Deferred = count
		}
		p.Total += count
	}
	if err := rows.Err(); err != nil {
		return JobProgress{}, err
	}
	if p.Total > 0 {
		terminal := p.Completed + p.Failed + p.Cancelled
		p.PercentComplete = float64(terminal) / float64(p.Total) * 100
	}
	return p, nil
}
