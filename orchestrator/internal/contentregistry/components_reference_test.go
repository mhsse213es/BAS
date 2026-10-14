package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegisterExternalComponent_CreatesExternalRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, nil)
		id, err := reg.RegisterExternalComponent(context.Background(), "art", "T1059", "ART T1059 test", "", "", 5, "v1.2.3", []string{"windows"}, "admin-test")
		if err != nil {
			t.Fatalf("RegisterExternalComponent: %v", err)
		}
		var kind, framework string
		var testIndex int
		if err := pool.QueryRow(context.Background(),
			`SELECT kind, framework, test_index FROM content_components WHERE id = $1`, id).Scan(&kind, &framework, &testIndex); err != nil {
			t.Fatal(err)
		}
		if kind != "external" || framework != "art" || testIndex != 5 {
			t.Fatalf("expected kind=external framework=art test_index=5, got kind=%s framework=%s test_index=%d", kind, framework, testIndex)
		}
	})
}

func TestRegisterExternalComponent_RequiresFramework(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, nil)
		_, err := reg.RegisterExternalComponent(context.Background(), "", "T1059", "bad", "", "", 0, "v1", nil, "admin-test")
		if err == nil {
			t.Fatal("expected an empty framework to be refused")
		}
	})
}
