package migrate

import (
	"context"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DownOne rolls back one migration (tests only; production rollback is the
// upgrade snapshot).
func DownOne(ctx context.Context, adminDSN string, src fs.FS) error {
	pool, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	m, err := newMigrator(pool, src)
	if err != nil {
		return err
	}
	defer m.Close()
	return m.Steps(-1)
}
