package migrate

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// adopt is implemented in Task 6.
func adopt(ctx context.Context, conn *pgx.Conn, opt Options, r *Result) error {
	return errors.New("adoption not implemented")
}

// ensureRole is implemented in Task 7.
func ensureRole(ctx context.Context, conn *pgx.Conn, password string) (string, error) {
	return "", nil
}
