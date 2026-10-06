package migrate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db/legacy"
	"github.com/audspect/bas/internal/db/migrations"
	"github.com/audspect/bas/internal/db/schemacheck"
	"github.com/audspect/bas/internal/db/seed"
)

// ErrAdoptionMismatch: a pre-H1 database cannot be brought to the baseline.
var ErrAdoptionMismatch = errors.New("pre-H1 database does not match the 000001 baseline")

// adopt brings a pre-H1 install to 000001_baseline (H1 spec 4.3) in one
// transaction: re-run the frozen legacy chain (older releases lack recent
// objects), compare the result with the baseline, and only on a match record
// version 1. On any mismatch nothing is written.
func adopt(ctx context.Context, conn *pgx.Conn, opt Options) ([]schemacheck.Object, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	if err := legacy.EnsureAll(ctx, tx); err != nil {
		return nil, fmt.Errorf("adoption: legacy chain: %w", err)
	}
	baseline, err := migrations.FS.ReadFile("000001_baseline.up.sql")
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `CREATE SCHEMA h1_fp; SET LOCAL search_path TO h1_fp, public`); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, string(baseline)); err != nil {
		return nil, fmt.Errorf("adoption: build reference baseline: %w", err)
	}
	want, err := schemacheck.Take(ctx, tx, "h1_fp")
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SET LOCAL search_path TO public; DROP SCHEMA h1_fp CASCADE`); err != nil {
		return nil, err
	}
	got, err := schemacheck.Take(ctx, tx, "public")
	if err != nil {
		return nil, err
	}
	missing, different, extra := schemacheck.Diff(want, got)
	if len(missing)+len(different) > 0 {
		var b strings.Builder
		for _, o := range missing {
			fmt.Fprintf(&b, "\n  missing   %s/%s", o.Kind, o.Name)
		}
		for _, o := range different {
			fmt.Fprintf(&b, "\n  different %s/%s (found %s)", o.Kind, o.Name, o.Detail)
		}
		return nil, fmt.Errorf("%w; nothing was changed; the server stays on its current release. Objects the baseline needs:%s", ErrAdoptionMismatch, b.String())
	}
	// golang-migrate's table, exactly as its pgx5 driver creates it.
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL);
		INSERT INTO schema_migrations (version, dirty) VALUES (1, false)`); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	for _, o := range extra {
		opt.printf("migrate: adoption: extra %s/%s kept (not part of the baseline)", o.Kind, o.Name)
	}
	return extra, nil
}

// finishAdoption runs after migrations 2..N: records the extras (000003) and
// marks reference data version 1, because the legacy chain already wrote seed
// 0001's rows (re-applying it would resurrect operator-deleted rows).
func finishAdoption(ctx context.Context, conn *pgx.Conn, extra []schemacheck.Object) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	for _, o := range extra {
		if _, err := tx.Exec(ctx, `INSERT INTO h1_adoption_report (object, kind, detail) VALUES ($1, $2, $3)`, o.Name, o.Kind, o.Detail); err != nil {
			return err
		}
	}
	if cur, err := seed.Current(ctx, tx); err != nil {
		return err
	} else if cur < 1 {
		if err := seed.Mark(ctx, tx, 1); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
