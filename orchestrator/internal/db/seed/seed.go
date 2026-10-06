// Package seed is the reference-data seed (H1 spec 3/4.3): numbered SQL files
// NNNN_name.sql, each applied exactly once, versioned in reference_data_version
// separately from schema_migrations. Shipped files never change; new or
// corrected reference data ships as a new file. Seed statements must never
// overwrite operator-controlled state.
package seed

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"

	"github.com/jackc/pgx/v5"
)

//go:embed *.sql
var files embed.FS

var name = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

// Querier is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type file struct {
	version int
	name    string
}

func list(fsys fs.FS) ([]file, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []file
	seen := map[int]string{}
	for _, e := range entries {
		m := name.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("seed: bad file name %q (want NNNN_name.sql)", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		if prev, ok := seen[v]; ok {
			return nil, fmt.Errorf("seed: duplicate version %d (%s, %s)", v, prev, e.Name())
		}
		seen[v] = e.Name()
		out = append(out, file{v, e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Version is the highest embedded seed version.
func Version() (int, error) {
	fl, err := list(files)
	if err != nil || len(fl) == 0 {
		return 0, err
	}
	return fl[len(fl)-1].version, nil
}

// Current is the applied seed version (0 when none, or before migration 000002).
func Current(ctx context.Context, q Querier) (int, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('reference_data_version') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var v int
	err := q.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM reference_data_version`).Scan(&v)
	return v, err
}

// Apply runs every embedded seed file newer than Current, in order, inside tx.
func Apply(ctx context.Context, tx pgx.Tx) error {
	return ApplyFS(ctx, tx, files)
}

// ApplyFS is Apply over fsys (tests).
func ApplyFS(ctx context.Context, tx pgx.Tx, fsys fs.FS) error {
	fl, err := list(fsys)
	if err != nil {
		return err
	}
	cur, err := Current(ctx, tx)
	if err != nil {
		return err
	}
	for _, f := range fl {
		if f.version <= cur {
			continue
		}
		sql, err := fs.ReadFile(fsys, f.name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("seed %s: %w", f.name, err)
		}
		if err := Mark(ctx, tx, f.version); err != nil {
			return err
		}
	}
	return nil
}

// Mark records version as applied (adoption marks 1: the legacy chain wrote
// seed 0001's rows).
func Mark(ctx context.Context, tx pgx.Tx, version int) error {
	_, err := tx.Exec(ctx, `INSERT INTO reference_data_version (id, version, applied_at) VALUES (1, $1, now())
		ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version, applied_at = EXCLUDED.applied_at`, version)
	return err
}
