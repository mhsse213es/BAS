package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/k8sscenario"
)

// ensureK8sControlledSwitchSchema creates the global Controlled switch table. One row holds the state. It is absent
// until first set, and an absent row means the switch is off.
const k8sControlledSwitchSchema = `CREATE TABLE IF NOT EXISTS k8s_controlled_switch (
	id          integer     PRIMARY KEY CHECK (id = 1),
	enabled     boolean     NOT NULL,
	changed_by  text        NOT NULL,
	changed_at  timestamptz NOT NULL
)`

// K8sControlledSwitchStore holds the global kill switch for Controlled execution.
type K8sControlledSwitchStore struct {
	pool *pgxpool.Pool
}

// NewK8sControlledSwitchStore returns a store over the pool.
func NewK8sControlledSwitchStore(pool *pgxpool.Pool) *K8sControlledSwitchStore {
	return &K8sControlledSwitchStore{pool: pool}
}

// Enabled reports whether Controlled execution is switched on. No row means off.
func (s *K8sControlledSwitchStore) Enabled(ctx context.Context) (bool, error) {
	var on bool
	err := s.pool.QueryRow(ctx, `SELECT enabled FROM k8s_controlled_switch WHERE id = 1`).Scan(&on)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return on, nil
}

// Set changes the switch and writes its audit event in one transaction. If the audit cannot be written, the switch
// does not change.
func (s *K8sControlledSwitchStore) Set(ctx context.Context, enabled bool, actor string, at time.Time, ev k8sscenario.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO k8s_controlled_switch (id, enabled, changed_by, changed_at) VALUES (1, $1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, changed_by = EXCLUDED.changed_by,
			changed_at = EXCLUDED.changed_at`, enabled, actor, at.UTC()); err != nil {
		return err
	}
	if err := writeScenarioAuditRow(ctx, tx, ev); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
