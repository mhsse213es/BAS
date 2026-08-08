package jobs

import "context"

// ResolveGroupAgentIDs returns every distinct agent_id belonging to any of
// groupIDs or their descendant groups -- the same recursive membership rule
// GET /api/agents?groupId= already applies (selecting a parent group
// surfaces agents in its children too). Called fresh at every schedule
// spawn (see spawnDueSchedules), never cached, so group-membership changes
// are picked up automatically without editing the schedule. Empty input
// returns an empty, non-nil slice.
func (s *Store) ResolveGroupAgentIDs(ctx context.Context, groupIDs []int64) ([]string, error) {
	if len(groupIDs) == 0 {
		return []string{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`WITH RECURSIVE descendants(id) AS (
			SELECT id FROM agent_groups WHERE id = ANY($1)
			UNION ALL
			SELECT gr.id FROM agent_groups gr JOIN descendants d ON gr.parent_id = d.id
		)
		SELECT DISTINCT agent_id FROM agents WHERE group_id IN (SELECT id FROM descendants)`,
		groupIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var agentID string
		if err := rows.Scan(&agentID); err != nil {
			return nil, err
		}
		out = append(out, agentID)
	}
	return out, rows.Err()
}
