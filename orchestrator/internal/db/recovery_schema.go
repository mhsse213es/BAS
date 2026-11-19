package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureRecoverySchema creates the single-row table holding the hash of the console recovery passphrase (the value an
// operator sets as RECOVERY_PASSPHRASE in setup.conf) and the failed-attempt counters that rate-limit its use.
// Idempotent. Only a hash is ever stored.
func EnsureRecoverySchema(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS recovery_passphrase (
			id              integer     PRIMARY KEY CHECK (id = 1),
			hash            text        NOT NULL,
			set_at          timestamptz NOT NULL DEFAULT now(),
			failed_attempts integer     NOT NULL DEFAULT 0,
			locked_until    timestamptz
		)`); err != nil {
		return fmt.Errorf("recovery schema: %w", err)
	}
	return nil
}
