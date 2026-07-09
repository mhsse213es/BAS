package testutil

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
)

func TestUserBuilder_Build(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		id := NewUser().WithUsername("alice").WithRole(auth.RoleAdmin).Build(t, pool)
		if id == "" {
			t.Fatal("expected non-empty id")
		}

		var role string
		err := pool.QueryRow(context.Background(),
			`SELECT role FROM users WHERE id = $1`, id).Scan(&role)
		if err != nil {
			t.Fatalf("query role: %v", err)
		}
		if role != "admin" {
			t.Fatalf("role = %q, want admin", role)
		}
	})
}

func TestUserBuilder_DefaultsAreUnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		id1 := NewUser().Build(t, pool)
		id2 := NewUser().Build(t, pool)
		if id1 == id2 {
			t.Fatal("expected distinct ids for distinct default usernames")
		}
	})
}
