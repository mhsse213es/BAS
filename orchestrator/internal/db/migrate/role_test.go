package migrate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db/migrate"
	"github.com/audspect/bas/internal/db/pgtest"
)

// roleDSN is a fresh database whose test drops the cluster-wide bas_app role
// afterwards, so every role test starts without it.
func roleDSN(t *testing.T) string {
	t.Helper()
	dsn := pgtest.NewDatabase(t)
	t.Cleanup(func() {
		ctx := context.Background()
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Errorf("cleanup connect: %v", err)
			return
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, `DO $$ BEGIN
			IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bas_app') THEN
				DROP OWNED BY bas_app; DROP ROLE bas_app;
			END IF; END $$`); err != nil {
			t.Errorf("cleanup drop bas_app: %v", err)
		}
	})
	return dsn
}

func tryConnect(ctx context.Context, dsn, user, password string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.User, cfg.Password = user, password
	return pgx.ConnectConfig(ctx, cfg)
}

func connectAs(t *testing.T, dsn, user, password string) *pgx.Conn {
	t.Helper()
	c, err := tryConnect(context.Background(), dsn, user, password)
	if err != nil {
		t.Fatalf("connect as %s: %v", user, err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func TestRole_CreatedWithDMLOnly(t *testing.T) { // H1-T1 (role part), H1-T8
	ctx := context.Background()
	dsn := roleDSN(t)
	r, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1"})
	if err != nil || r.Role != "bas_app created" {
		t.Fatalf("%+v %v", r, err)
	}
	app := connectAs(t, dsn, "bas_app", "p1")
	if _, err := app.Exec(ctx, `CREATE TABLE x (id int)`); err == nil {
		t.Fatal("bas_app could run DDL")
	}
	if _, err := app.Exec(ctx, `SELECT count(*) FROM agents`); err != nil {
		t.Fatalf("bas_app cannot read: %v", err)
	}
	if _, err := app.Exec(ctx, `DELETE FROM audit_logs`); err == nil {
		t.Fatal("bas_app may delete audit_logs")
	}
	if r2, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1"}); err != nil || r2.Role != "bas_app ok" {
		t.Fatalf("second run %+v %v", r2, err)
	}
}

func TestRole_EmptyPasswordRefused(t *testing.T) {
	dsn := roleDSN(t)
	if _, err := migrate.Up(context.Background(), dsn, migrate.Options{}); err == nil {
		t.Fatal("Up without AppPassword accepted")
	}
}

func TestRole_WrongConfiguredPasswordStopsAndLeavesPassword(t *testing.T) { // Review Focus 3
	ctx := context.Background()
	dsn := roleDSN(t)
	if _, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1"}); err != nil {
		t.Fatal(err)
	}
	_, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "edited-in-env"})
	if !errors.Is(err, migrate.ErrAppPasswordMismatch) {
		t.Fatalf("err = %v", err)
	}
	connectAs(t, dsn, "bas_app", "p1") // still the old password
}

func TestRotateAppPassword(t *testing.T) {
	ctx := context.Background()
	dsn := roleDSN(t)
	if _, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1"}); err != nil {
		t.Fatal(err)
	}
	if err := migrate.RotateAppPassword(ctx, dsn, "p2"); err != nil {
		t.Fatal(err)
	}
	connectAs(t, dsn, "bas_app", "p2")
	if c, err := tryConnect(ctx, dsn, "bas_app", "p1"); err == nil {
		c.Close(ctx)
		t.Fatal("old password still works")
	}
	if r, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p2"}); err != nil || r.Role != "bas_app ok" {
		t.Fatalf("%+v %v", r, err)
	}
	if err := migrate.RotateAppPassword(ctx, dsn, ""); err == nil {
		t.Fatal("empty rotation accepted")
	}
}

func TestRole_GrantsCoverTablesCreatedByLaterMigrations(t *testing.T) {
	ctx := context.Background()
	dsn := roleDSN(t)
	if _, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1"}); err != nil {
		t.Fatal(err)
	}
	src, _ := withExtra(t, "later", "CREATE TABLE h1_later (id int);", "DROP TABLE h1_later;")
	if _, err := migrate.Up(ctx, dsn, migrate.Options{AppPassword: "p1", Source: src}); err != nil {
		t.Fatal(err)
	}
	app := connectAs(t, dsn, "bas_app", "p1")
	if _, err := app.Exec(ctx, `INSERT INTO h1_later VALUES (1)`); err != nil {
		t.Fatalf("bas_app cannot write a table from a later migration: %v", err)
	}
}
