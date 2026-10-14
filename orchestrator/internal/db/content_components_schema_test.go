package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureContentComponentsSchema_CreatesTables(t *testing.T) {
	pool := sharedDB.Pool
	if err := db.EnsureContentComponentsSchema(context.Background(), pool); err != nil {
		t.Fatalf("EnsureContentComponentsSchema: %v", err)
	}
	if err := db.EnsureContentComponentsSchema(context.Background(), pool); err != nil {
		t.Fatalf("second EnsureContentComponentsSchema: %v", err)
	}
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('content_components','content_version_components')`).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected both tables to exist, found %d", n)
	}
}

func TestEnsureContentComponentsSchema_KindCheckConstraintEnforced(t *testing.T) {
	pool := sharedDB.Pool
	if err := db.EnsureContentComponentsSchema(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(context.Background(), `INSERT INTO content_components
		(kind, technique_id, title, promoted_by) VALUES ('internal', 'T1059', 'bad row', 'test')`)
	if err == nil {
		t.Fatal("expected the CHECK constraint to reject an internal component with no origin/snapshot")
	}
}
