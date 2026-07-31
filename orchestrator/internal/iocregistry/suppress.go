package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SetSuppressed sets or clears an IOC's suppression state. reason is stored verbatim when
// suppressing; cleared (empty string) when un-suppressing, regardless of what's passed --
// a reason only makes sense while actually suppressed.
func SetSuppressed(ctx context.Context, pool *pgxpool.Pool, iocID string, suppressed bool, reason string) error {
	if !suppressed {
		reason = ""
	}
	_, err := pool.Exec(ctx,
		`UPDATE iocs SET suppressed = $1, suppression_reason = $2 WHERE id = $3`,
		suppressed, reason, iocID)
	return err
}
