package testutil

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/audspect/bas/internal/db"
)

// TestDB is a live Postgres instance backing one or more tests.
type TestDB struct {
	Pool      *pgxpool.Pool
	Container testcontainers.Container
	Cleanup   func()
}

// newTestDB starts a postgres:16-alpine container (matching production —
// see packaging/compose/docker-compose.yml), applies the real schema via
// db.EnsureSchema + db.EnsureContentSchema + db.EnsureExerciseSchema, and returns a ready harness.
func newTestDB(ctx context.Context) (*TestDB, error) {
	// Bounded so a Docker/WSL2 networking stall during container startup or
	// the initial connection fails fast with a clear error instead of
	// hanging the test process indefinitely at near-zero CPU -- observed
	// repeatedly under heavy Docker Desktop memory pressure. The container's
	// own wait strategy below already caps log-wait at 60s, but everything
	// after that (connection string, pool connect, ping, schema setup) ran
	// under the caller's unbounded context with nothing to time it out.
	// 3 minutes is generous headroom over normal setup (seconds to low tens
	// of seconds) while still failing far faster than a silent 10+ minute hang.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("bas_test"),
		tcpostgres.WithUsername("bas_test"),
		tcpostgres.WithPassword("bas_test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("testutil: start postgres container: %w", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		// A fresh background context for cleanup, not the (possibly already
		// expired) bounded ctx above -- otherwise the same timeout that
		// caused this failure would also block Terminate, leaking the
		// container instead of cleaning it up.
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: get connection string: %w", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: connect pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: ping pool: %w", err)
	}

	if err := db.EnsureSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureSchema: %w", err)
	}
	if err := db.EnsureContentSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureContentSchema: %w", err)
	}
	if err := db.EnsureExerciseSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureExerciseSchema: %w", err)
	}
	if err := db.EnsureIOCSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureIOCSchema: %w", err)
	}
	if err := db.EnsureIOCEnrichmentSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureIOCEnrichmentSchema: %w", err)
	}
	if err := db.EnsureAgentGroupSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureAgentGroupSchema: %w", err)
	}
	if err := db.EnsureAgentUninstallSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureAgentUninstallSchema: %w", err)
	}

	return &TestDB{
		Pool:      pool,
		Container: container,
		Cleanup: func() {
			pool.Close()
			_ = container.Terminate(context.Background())
		},
	}, nil
}

// NewTestDB starts a fresh container scoped to t — terminated automatically
// via t.Cleanup when t finishes. Use for a single test function or a small
// package where sharing a container isn't worth the TestMain boilerplate.
func NewTestDB(t *testing.T) *TestDB {
	t.Helper()
	tdb, err := newTestDB(context.Background())
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Cleanup(tdb.Cleanup)
	return tdb
}

// MustSharedTestDB starts a container meant to be reused by every test in a
// package's test binary. Call from TestMain — there is no *testing.T
// available there to register cleanup automatically:
//
//	var sharedDB *testutil.TestDB
//
//	func TestMain(m *testing.M) {
//	    sharedDB = testutil.MustSharedTestDB()
//	    code := m.Run()
//	    sharedDB.Cleanup()
//	    os.Exit(code)
//	}
//
// Individual tests should isolate their writes with RunInTx or RunWithPool
// rather than relying on container-per-test isolation.
func MustSharedTestDB() *TestDB {
	tdb, err := newTestDB(context.Background())
	if err != nil {
		panic(err)
	}
	return tdb
}

// RunInTx runs fn inside a transaction that is always rolled back after fn
// returns, isolating the test from any writes it makes. Use for repository
// code that accepts a pgx.Tx.
func (d *TestDB) RunInTx(t *testing.T, fn func(tx pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("testutil: begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fn(tx)
}

// RunWithPool runs fn with the raw pool, for code that manages its own
// transactions internally and can't accept an injected pgx.Tx. Truncates
// all public-schema tables after fn returns so the next test starts clean.
// The truncate is deferred (not a plain trailing call) so it still runs when
// fn fails via t.Fatal/t.Fatalf — that unwinds the goroutine with
// runtime.Goexit, which skips everything after fn's call site but still runs
// deferred functions. Without this, a failing fn would leak its DB state into
// every subsequent test in the same run.
func (d *TestDB) RunWithPool(t *testing.T, fn func(pool *pgxpool.Pool)) {
	t.Helper()
	defer truncateAll(t, d.Pool)
	fn(d.Pool)
}

func truncateAll(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		t.Fatalf("testutil: list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("testutil: scan table name: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	for _, name := range tables {
		if _, err := pool.Exec(ctx, `TRUNCATE TABLE "`+name+`" CASCADE`); err != nil {
			t.Fatalf("testutil: truncate %s: %v", name, err)
		}
	}
	// Truncation wiped the tenants bootstrap row. Restore the invariant
	// EnsureSchema establishes ("a 'default' tenant always exists") so
	// users.tenant_id's FK and its DEFAULT 'default' keep working for every
	// subsequent test in the shared container.
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, slug, status)
		VALUES ('default', 'Default Tenant', 'default', 'active')
		ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("testutil: reseed default tenant: %v", err)
	}
}
