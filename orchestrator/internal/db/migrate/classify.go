package migrate

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db/migrations"
)

// State is what a database looks like to migrate up (H1 spec 4.3).
type State int

const (
	Fresh        State = iota // no user tables in public
	PreH1                     // Audspect sentinel tables, no schema_migrations
	Managed                   // schema_migrations present, clean, not ahead of this release
	Dirty                     // a migration failed part-way
	Newer                     // recorded version is ahead of this release
	Unrecognised              // tables that are not an Audspect schema
)

func (s State) String() string {
	return [...]string{"fresh", "pre-H1", "managed", "dirty", "newer", "unrecognised"}[s]
}

// sentinels are present in every Audspect schema since before H1.
var sentinels = []string{"tenants", "agents", "scenario_runs"}

// Classify inspects public; the uint is the recorded schema version (0 if none).
func Classify(ctx context.Context, conn *pgx.Conn) (State, uint, error) {
	var hasTable bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&hasTable); err != nil {
		return 0, 0, err
	}
	if hasTable {
		var version int64
		var dirty bool
		err := conn.QueryRow(ctx, `SELECT version, dirty FROM public.schema_migrations LIMIT 1`).Scan(&version, &dirty)
		if err == pgx.ErrNoRows {
			// golang-migrate created the table but recorded nothing yet.
			return Managed, 0, nil
		}
		if err != nil {
			return 0, 0, err
		}
		latest, err := migrations.Latest()
		if err != nil {
			return 0, 0, err
		}
		switch {
		case dirty:
			return Dirty, uint(version), nil
		case uint(version) > latest:
			return Newer, uint(version), nil
		}
		return Managed, uint(version), nil
	}
	var sentinel, user int
	if err := conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE tablename = ANY($1)), count(*)
		FROM pg_tables WHERE schemaname = 'public'`, sentinels).Scan(&sentinel, &user); err != nil {
		return 0, 0, err
	}
	switch {
	case sentinel == len(sentinels):
		return PreH1, 0, nil
	case user == 0:
		return Fresh, 0, nil
	}
	return Unrecognised, 0, nil
}
