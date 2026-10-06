package threatidentity

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// seedProfile inserts a legacy actor row directly (the resolver would merge
// two actors sharing an alias, so conflicting legacy data must be seeded).
func seedProfile(t *testing.T, pool *pgxpool.Pool, name string, aliases ...string) string {
	t.Helper()
	if aliases == nil {
		aliases = []string{}
	}
	var id string
	if err := pool.QueryRow(context.Background(), `INSERT INTO threat_actor_profiles (name, aliases) VALUES ($1, $2) RETURNING id`,
		name, aliases).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
