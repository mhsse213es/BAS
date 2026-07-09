package testutil

import (
	"context"
	"math/rand/v2"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
)

// UserBuilder builds a users row with sensible defaults, overridden via
// chained With* calls. This is the reference pattern for entity builders
// added in later phases — small, composable Go functions instead of
// fixture files.
type UserBuilder struct {
	username string
	password string
	role     auth.Role
}

// NewUser starts a builder for a users row with defaults: a unique
// username, password "test-password", role viewer.
func NewUser() *UserBuilder {
	return &UserBuilder{
		username: "test-user-" + randSuffix(),
		password: "test-password",
		role:     auth.RoleViewer,
	}
}

// WithUsername overrides the default generated username.
func (b *UserBuilder) WithUsername(username string) *UserBuilder {
	b.username = username
	return b
}

// WithRole overrides the default viewer role.
func (b *UserBuilder) WithRole(role auth.Role) *UserBuilder {
	b.role = role
	return b
}

// Build inserts the user and returns its generated id.
func (b *UserBuilder) Build(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	hash, err := auth.HashPassword(b.password)
	if err != nil {
		t.Fatalf("testutil: hash password: %v", err)
	}
	var id string
	err = pool.QueryRow(context.Background(),
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id`,
		b.username, hash, string(b.role)).Scan(&id)
	if err != nil {
		t.Fatalf("testutil: insert user: %v", err)
	}
	return id
}

func randSuffix() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[rand.IntN(len(chars))]
	}
	return string(b)
}
