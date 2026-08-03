package jobs

import (
	"context"
	"time"
)

// AgentFreeze is a one-shot absolute freeze window for one agent -- while
// active, Dispatcher.Tick defers rather than dispatches any pending target
// for this agent.
type AgentFreeze struct {
	ID        string
	AgentID   string
	FromAt    time.Time
	ToAt      time.Time
	Reason    string
	CreatedBy string
	CreatedAt time.Time
}

func (s *Store) CreateFreeze(ctx context.Context, f AgentFreeze) (AgentFreeze, error) {
	var id string
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_maintenance_freezes (agent_id, from_at, to_at, reason, created_by)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		f.AgentID, f.FromAt, f.ToAt, f.Reason, f.CreatedBy,
	).Scan(&id); err != nil {
		return AgentFreeze{}, err
	}
	return s.getFreeze(ctx, id)
}

func (s *Store) getFreeze(ctx context.Context, id string) (AgentFreeze, error) {
	var f AgentFreeze
	err := s.pool.QueryRow(ctx,
		`SELECT id, agent_id, from_at, to_at, reason, created_by, created_at FROM agent_maintenance_freezes WHERE id=$1`, id,
	).Scan(&f.ID, &f.AgentID, &f.FromAt, &f.ToAt, &f.Reason, &f.CreatedBy, &f.CreatedAt)
	return f, err
}

func (s *Store) ListFreezesForAgent(ctx context.Context, agentID string) ([]AgentFreeze, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent_id, from_at, to_at, reason, created_by, created_at
		   FROM agent_maintenance_freezes WHERE agent_id=$1 ORDER BY from_at DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentFreeze
	for rows.Next() {
		var f AgentFreeze
		if err := rows.Scan(&f.ID, &f.AgentID, &f.FromAt, &f.ToAt, &f.Reason, &f.CreatedBy, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) DeleteFreeze(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM agent_maintenance_freezes WHERE id=$1`, id)
	return err
}

// IsAgentFrozen reports whether agentID has a currently-active freeze
// window. Overlapping freezes for the same agent are allowed at creation --
// this only cares whether any one of them is active right now, taking the
// most recently created if several overlap.
func (s *Store) IsAgentFrozen(ctx context.Context, agentID string) (frozen bool, reason string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT reason FROM agent_maintenance_freezes
		  WHERE agent_id=$1 AND from_at <= NOW() AND to_at >= NOW()
		  ORDER BY created_at DESC LIMIT 1`, agentID,
	).Scan(&reason)
	if err != nil {
		return false, "", nil // no rows is the common, non-error case
	}
	return true, reason, nil
}
