// Package pgtest gives H1 database tests fresh, EMPTY databases (no schema):
// one postgres:16-alpine container per test binary, one new database per call.
// It imports nothing from internal/db so every db package can use it.
//
//	func TestMain(m *testing.M) { os.Exit(pgtest.Run(m)) }
package pgtest

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	once      sync.Once
	container *tcpostgres.PostgresContainer
	adminDSN  string
	startErr  error
	counter   atomic.Int64
)

// Run runs the package's tests and terminates the shared container afterwards.
func Run(m *testing.M) int {
	code := m.Run()
	if container != nil {
		_ = container.Terminate(context.Background())
	}
	return code
}

func start() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	container, startErr = tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("postgres"),
		tcpostgres.WithUsername("bas_user"),
		tcpostgres.WithPassword("bas_user"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if startErr != nil {
		return
	}
	adminDSN, startErr = container.ConnectionString(ctx, "sslmode=disable")
}

// NewDatabase creates a fresh empty database and returns a superuser DSN for it.
func NewDatabase(t *testing.T) string {
	t.Helper()
	once.Do(start)
	if startErr != nil {
		t.Fatalf("pgtest: start postgres: %v", startErr)
	}
	ctx := context.Background()
	name := fmt.Sprintf("h1_%d_%d", time.Now().UnixNano()%1e9, counter.Add(1))
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("pgtest: connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("pgtest: create database: %v", err)
	}
	return WithDatabase(t, adminDSN, name)
}

// WithDatabase returns dsn pointing at database name.
func WithDatabase(t *testing.T, dsn, name string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("pgtest: parse dsn: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// WithUser returns dsn with different credentials.
func WithUser(t *testing.T, dsn, user, password string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("pgtest: parse dsn: %v", err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

// NewPool returns a pool on a fresh empty database, closed at test end.
func NewPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return PoolFor(t, NewDatabase(t))
}

// PoolFor opens a pool on dsn, closed at test end.
func PoolFor(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgtest: pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// NewConn returns a connection on a fresh empty database, closed at test end.
func NewConn(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), NewDatabase(t))
	if err != nil {
		t.Fatalf("pgtest: connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// Execer is satisfied by *pgx.Conn, *pgxpool.Pool and pgx.Tx.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Exec runs sql (may contain several statements) or fails the test.
func Exec(t *testing.T, q Execer, sql string) {
	t.Helper()
	if _, err := q.Exec(context.Background(), sql); err != nil {
		t.Fatalf("pgtest: exec %.80q: %v", sql, err)
	}
}
