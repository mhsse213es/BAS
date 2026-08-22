package initiatives

import "context"

// Progress is a computed summary of one Initiative's member-Job state
// distribution -- never persisted, always derived fresh from jobs.
type Progress struct {
	Total           int
	Requested       int
	Running         int
	Completed       int
	Partial         int
	Failed          int
	Cancelled       int
	PercentComplete float64 // (Completed+Partial+Failed+Cancelled) / Total * 100; 0 if Total == 0
}

// ComputeProgress derives one Initiative's Progress via a grouped count
// over jobs -- at most 6 rows regardless of member-job count.
func (s *Store) ComputeProgress(ctx context.Context, initiativeID string) (Progress, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT state, COUNT(*) FROM jobs WHERE initiative_id=$1 GROUP BY state`, initiativeID)
	if err != nil {
		return Progress{}, err
	}
	defer rows.Close()

	var p Progress
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return Progress{}, err
		}
		switch state {
		case "requested":
			p.Requested = count
		case "running":
			p.Running = count
		case "completed":
			p.Completed = count
		case "partial":
			p.Partial = count
		case "failed":
			p.Failed = count
		case "cancelled":
			p.Cancelled = count
		}
		p.Total += count
	}
	if err := rows.Err(); err != nil {
		return Progress{}, err
	}
	if p.Total > 0 {
		terminal := p.Completed + p.Partial + p.Failed + p.Cancelled
		p.PercentComplete = float64(terminal) / float64(p.Total) * 100
	}
	return p, nil
}
