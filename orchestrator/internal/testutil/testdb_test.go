package testutil

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

var sharedDB *TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestNewTestDB_SchemaApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	var count int
	err := sharedDB.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_name = 'users'`).Scan(&count)
	if err != nil {
		t.Fatalf("query users table: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected users table to exist, count=%d", count)
	}
}

func TestTestDB_RunInTx_RollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunInTx(t, func(tx pgx.Tx) {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO users (username, password_hash, role) VALUES ('rollback-test', 'x', 'viewer')`)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	})

	var count int
	err := sharedDB.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE username = 'rollback-test'`).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected rollback, but row persisted (count=%d)", count)
	}
}
