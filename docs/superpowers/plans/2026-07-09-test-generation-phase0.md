# Test Generation — Phase 0 (Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared test infrastructure (`internal/testutil`: real-Postgres harness, entity builders, determinism helpers, auth helpers, golden-file support, mocks/extension-point scaffolding), a coverage-summary tool, and a GitHub Actions CI workflow — the foundation every later package-testing phase (verification, relationships, exercise, api, ...) builds on.

**Architecture:** One new package, `internal/testutil`, wraps `testcontainers-go`'s Postgres module around the orchestrator's real `db.EnsureSchema`/`db.EnsureContentSchema` migrations so tests run against a schema that's byte-for-byte what production runs, isolated per-test via transaction rollback. A separate `scripts/coveragesummary` command turns a raw `go test -coverprofile` file into a per-package percentage table. A new `.github/workflows/test.yml` runs the whole verification chain (fmt, vet, staticcheck, build, race-enabled tests, coverage) on every push/PR.

**Tech Stack:** Go 1.26, `github.com/testcontainers/testcontainers-go` + its `postgres` module, `golang.org/x/tools/cover`, `postgres:16-alpine` (matches `packaging/compose/docker-compose.yml`), GitHub Actions (`ubuntu-latest`, Docker preinstalled).

## Global Constraints

- Postgres version in tests is pinned to `postgres:16-alpine` — must match production (`packaging/compose/docker-compose.yml:10`). Never use `postgres:latest`.
- No build tag (`-tags=integration`) gates DB-backed tests — they run as part of plain `go test ./...`. Revisit only if suite wall-clock time becomes a real problem later.
- No third-party coverage SaaS (Codecov etc.) — coverage artifacts are local files uploaded as CI artifacts only, consistent with the product's on-prem/air-gapped posture.
- Fixtures are Go builder functions, never YAML/JSON fixture files.
- Determinism helpers (clock/UUID/rand) are only useful where production code accepts an injected source — Phase 0 does not retrofit production packages to add that seam; that's called out per-package in later phases.
- `internal/testutil/mocks` gets a scaffold only in this phase — `siem`, `ticketing`, `connector` currently have no interfaces to mock against; extracting those interfaces is Phase 4's job.
- Every task ends with `gofmt -l .` clean and `go build ./...` / `go vet ./...` passing from the `orchestrator/` directory.

---

### Task 1: Package skeleton + testcontainers-go dependency

**Files:**
- Create: `orchestrator/internal/testutil/doc.go`
- Modify: `orchestrator/go.mod`, `orchestrator/go.sum` (via `go get`/`go mod tidy`)

**Interfaces:**
- Produces: package `github.com/audspect/bas/internal/testutil` exists and compiles (empty except for doc comment). No exported symbols yet.

- [ ] **Step 1: Add the testcontainers-go Postgres module dependency**

Run from `orchestrator/`:
```bash
go get github.com/testcontainers/testcontainers-go/modules/postgres@latest
```
Expected: `go.mod`/`go.sum` gain `github.com/testcontainers/testcontainers-go` and its `modules/postgres` submodule plus transitive deps (Docker client libs, etc.). No errors.

- [ ] **Step 2: Create the package doc file**

`orchestrator/internal/testutil/doc.go`:
```go
// Package testutil provides shared test infrastructure for the orchestrator
// module: a real-Postgres test harness (TestDB, backed by testcontainers-go
// and the project's actual EnsureSchema/EnsureContentSchema migrations),
// entity builders, determinism helpers (frozen clock, sequential ids,
// seeded rand), JWT/auth test helpers, and golden-file regression test
// support.
//
// See docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md
// for the full test generation strategy this package is the foundation of.
package testutil
```

- [ ] **Step 3: Verify it builds**

Run: `go build ./... && go vet ./...` (from `orchestrator/`)
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/testutil/doc.go orchestrator/go.mod orchestrator/go.sum
git commit -m "chore(testutil): add package skeleton + testcontainers-go dependency"
```

---

### Task 2: TestDB — real-Postgres harness

**Files:**
- Create: `orchestrator/internal/testutil/testdb.go`
- Create: `orchestrator/internal/testutil/testdb_test.go`

**Interfaces:**
- Consumes: `db.EnsureSchema(ctx, pool)`, `db.EnsureContentSchema(ctx, pool)` (`orchestrator/internal/db/postgres.go:26`, `orchestrator/internal/db/content_schema.go:24`), both `func(context.Context, *pgxpool.Pool) error`.
- Produces:
  - `type TestDB struct { Pool *pgxpool.Pool; Container testcontainers.Container; Cleanup func() }`
  - `func NewTestDB(t *testing.T) *TestDB` — container scoped to `t`, auto-terminated via `t.Cleanup`.
  - `func MustSharedTestDB() *TestDB` — container for a whole package's `TestMain`, caller must call `.Cleanup()` manually.
  - `func (d *TestDB) RunInTx(t *testing.T, fn func(tx pgx.Tx))`
  - `func (d *TestDB) RunWithPool(t *testing.T, fn func(pool *pgxpool.Pool))`
  - Package-level `var sharedDB *TestDB` and a `TestMain` in `testdb_test.go`, reused by every later task's tests in this package.

- [ ] **Step 1: Write the harness**

`orchestrator/internal/testutil/testdb.go`:
```go
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
// db.EnsureSchema + db.EnsureContentSchema, and returns a ready harness.
func newTestDB(ctx context.Context) (*TestDB, error) {
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
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: get connection string: %w", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: connect pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: ping pool: %w", err)
	}

	if err := db.EnsureSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureSchema: %w", err)
	}
	if err := db.EnsureContentSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureContentSchema: %w", err)
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
func (d *TestDB) RunWithPool(t *testing.T, fn func(pool *pgxpool.Pool)) {
	t.Helper()
	fn(d.Pool)
	truncateAll(t, d.Pool)
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
}
```

- [ ] **Step 2: Write the package TestMain + smoke tests**

`orchestrator/internal/testutil/testdb_test.go`:
```go
package testutil

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

var sharedDB *TestDB

func TestMain(m *testing.M) {
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
```

- [ ] **Step 3: Run the tests (requires Docker Desktop running)**

Run: `go test ./internal/testutil/... -v -run 'TestNewTestDB_SchemaApplied|TestTestDB_RunInTx_RollsBack'` (from `orchestrator/`)
Expected: both tests PASS. First run pulls the `postgres:16-alpine` image (needs internet access) and takes longer; subsequent runs are fast since the image is cached locally.

- [ ] **Step 4: Confirm -short mode skips cleanly (no Docker needed)**

Run: `go test ./internal/testutil/... -short -v`
Expected: both tests report `SKIP`, exit 0, no container starts.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/testutil/testdb.go orchestrator/internal/testutil/testdb_test.go
git commit -m "feat(testutil): add real-Postgres TestDB harness"
```

---

### Task 3: Determinism helpers

**Files:**
- Create: `orchestrator/internal/testutil/determinism.go`
- Create: `orchestrator/internal/testutil/determinism_test.go`

**Interfaces:**
- Produces:
  - `type FrozenClock struct{...}`, `func NewFrozenClock(t time.Time) *FrozenClock`, `func (c *FrozenClock) Now() time.Time`, `func (c *FrozenClock) Advance(d time.Duration)`
  - `type SeqUUID struct{...}`, `func NewSeqUUID(prefix string, seed uint64) *SeqUUID`, `func (g *SeqUUID) Next() string`
  - `func SeededRand(seed int64) *rand.Rand`

- [ ] **Step 1: Write the failing tests**

`orchestrator/internal/testutil/determinism_test.go`:
```go
package testutil

import (
	"testing"
	"time"
)

func TestFrozenClock_AdvanceMovesTime(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := NewFrozenClock(start)

	if !clock.Now().Equal(start) {
		t.Fatalf("Now() = %v, want %v", clock.Now(), start)
	}

	clock.Advance(24 * time.Hour)
	want := start.Add(24 * time.Hour)
	if !clock.Now().Equal(want) {
		t.Fatalf("after Advance, Now() = %v, want %v", clock.Now(), want)
	}
}

func TestSeqUUID_Deterministic(t *testing.T) {
	g := NewSeqUUID("test", 0)
	first := g.Next()
	second := g.Next()
	if first == second {
		t.Fatal("expected distinct sequential ids")
	}

	g2 := NewSeqUUID("test", 0)
	got := g2.Next()
	if got != first {
		t.Fatalf("same seed should reproduce same first id: got %q, want %q", got, first)
	}
}

func TestSeededRand_SameSeedSameSequence(t *testing.T) {
	r1 := SeededRand(42)
	r2 := SeededRand(42)

	for i := 0; i < 5; i++ {
		v1 := r1.Int63()
		v2 := r2.Int63()
		if v1 != v2 {
			t.Fatalf("iteration %d: r1=%d r2=%d, want equal", i, v1, v2)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/testutil/... -run TestFrozenClock -short`
Expected: FAIL — `undefined: NewFrozenClock` (compile error).

- [ ] **Step 3: Write the implementation**

`orchestrator/internal/testutil/determinism.go`:
```go
package testutil

import (
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"
)

// FrozenClock is an injectable time source for tests that need
// deterministic timestamps. Production code must accept a func() time.Time
// (or equivalent) rather than calling time.Now() directly for this to
// apply — Phase 0 does not retrofit production code with that seam.
type FrozenClock struct {
	now atomic.Int64 // unix nanos
}

// NewFrozenClock returns a clock fixed at t.
func NewFrozenClock(t time.Time) *FrozenClock {
	c := &FrozenClock{}
	c.now.Store(t.UnixNano())
	return c
}

// Now returns the clock's current fixed time.
func (c *FrozenClock) Now() time.Time {
	return time.Unix(0, c.now.Load())
}

// Advance moves the clock forward by d.
func (c *FrozenClock) Advance(d time.Duration) {
	c.now.Add(int64(d))
}

// SeqUUID is a deterministic, seedable stand-in for uuid generation in
// tests — produces predictable ids like "test-000000000001" instead of
// random ones, so assertions and golden files stay stable.
type SeqUUID struct {
	prefix string
	n      atomic.Uint64
}

// NewSeqUUID returns a generator whose Next() calls produce
// "<prefix>-<12-digit sequence>" starting after seed.
func NewSeqUUID(prefix string, seed uint64) *SeqUUID {
	g := &SeqUUID{prefix: prefix}
	g.n.Store(seed)
	return g
}

// Next returns the next id in sequence.
func (g *SeqUUID) Next() string {
	n := g.n.Add(1)
	return fmt.Sprintf("%s-%012d", g.prefix, n)
}

// SeededRand returns a math/rand source seeded deterministically, for
// property-based tests that need a reproducible "random" input on failure.
func SeededRand(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/testutil/... -run 'TestFrozenClock|TestSeqUUID|TestSeededRand' -v -short`
Expected: all three PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/testutil/determinism.go orchestrator/internal/testutil/determinism_test.go
git commit -m "feat(testutil): add frozen clock, sequential id, and seeded rand helpers"
```

---

### Task 4: User builder (proves the fixture-builder pattern)

**Files:**
- Create: `orchestrator/internal/testutil/builders.go`
- Create: `orchestrator/internal/testutil/builders_test.go`

**Interfaces:**
- Consumes: `TestDB.RunWithPool` (Task 2), `auth.HashPassword(password string) (string, error)` (`orchestrator/internal/auth/password.go:45`), `auth.Role` + `auth.RoleAdmin`/`RoleViewer` (`orchestrator/internal/auth/jwt.go`), the `users` table (`orchestrator/internal/db/postgres.go:30-39`).
- Produces: `type UserBuilder struct{...}`, `func NewUser() *UserBuilder`, `func (b *UserBuilder) WithUsername(string) *UserBuilder`, `func (b *UserBuilder) WithRole(auth.Role) *UserBuilder`, `func (b *UserBuilder) Build(t *testing.T, pool *pgxpool.Pool) string` (returns the new user's id).

- [ ] **Step 1: Write the failing test**

`orchestrator/internal/testutil/builders_test.go`:
```go
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/testutil/... -run TestUserBuilder`
Expected: FAIL — `undefined: NewUser` (compile error).

- [ ] **Step 3: Write the implementation**

`orchestrator/internal/testutil/builders.go`:
```go
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/testutil/... -run TestUserBuilder -v`
Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/testutil/builders.go orchestrator/internal/testutil/builders_test.go
git commit -m "feat(testutil): add UserBuilder, the reference entity-builder pattern"
```

---

### Task 5: Auth test helpers

**Files:**
- Create: `orchestrator/internal/testutil/auth_helpers.go`
- Create: `orchestrator/internal/testutil/auth_helpers_test.go`

**Interfaces:**
- Consumes: `auth.GenerateToken(userID string, role auth.Role, secret string, ttl time.Duration) (string, error)` and `auth.ValidateToken(tokenStr, secret string) (*auth.Claims, error)` (`orchestrator/internal/auth/jwt.go:27,41`).
- Produces: `const TestJWTSecret`, `func TestToken(t testing.TB, userID string, role auth.Role) string`, `func AuthedRequest(t testing.TB, req *http.Request, userID string, role auth.Role) *http.Request`.

- [ ] **Step 1: Write the failing tests**

`orchestrator/internal/testutil/auth_helpers_test.go`:
```go
package testutil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/auth"
)

func TestTestToken_ValidatesWithSameSecret(t *testing.T) {
	tok := TestToken(t, "user-1", auth.RoleAnalyst)

	claims, err := auth.ValidateToken(tok, TestJWTSecret)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Fatalf("UserID = %q, want user-1", claims.UserID)
	}
	if claims.Role != auth.RoleAnalyst {
		t.Fatalf("Role = %q, want analyst", claims.Role)
	}
}

func TestAuthedRequest_SetsAuthorizationHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	req = AuthedRequest(t, req, "user-2", auth.RoleAdmin)

	header := req.Header.Get("Authorization")
	if header == "" {
		t.Fatal("expected Authorization header to be set")
	}

	claims, err := auth.ValidateToken(header[len("Bearer "):], TestJWTSecret)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Role != auth.RoleAdmin {
		t.Fatalf("Role = %q, want admin", claims.Role)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/testutil/... -run 'TestTestToken|TestAuthedRequest' -short`
Expected: FAIL — `undefined: TestToken` (compile error).

- [ ] **Step 3: Write the implementation**

`orchestrator/internal/testutil/auth_helpers.go`:
```go
package testutil

import (
	"net/http"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
)

// TestJWTSecret is the fixed HMAC secret used to sign tokens minted by
// TestToken. Tests that validate a token must use this same secret.
const TestJWTSecret = "testutil-fixed-secret-do-not-use-in-prod"

// TestToken mints a signed JWT for role, valid for 1 hour, signed with
// TestJWTSecret. Use for handler tests that need a real Authorization
// header without going through the login endpoint.
func TestToken(t testing.TB, userID string, role auth.Role) string {
	t.Helper()
	tok, err := auth.GenerateToken(userID, role, TestJWTSecret, time.Hour)
	if err != nil {
		t.Fatalf("testutil: generate token: %v", err)
	}
	return tok
}

// AuthedRequest returns req with an Authorization: Bearer header set to a
// freshly minted token for role.
func AuthedRequest(t testing.TB, req *http.Request, userID string, role auth.Role) *http.Request {
	t.Helper()
	req.Header.Set("Authorization", "Bearer "+TestToken(t, userID, role))
	return req
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/testutil/... -run 'TestTestToken|TestAuthedRequest' -v -short`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/testutil/auth_helpers.go orchestrator/internal/testutil/auth_helpers_test.go
git commit -m "feat(testutil): add JWT auth test helpers"
```

---

### Task 6: Golden-file regression test support

**Files:**
- Create: `orchestrator/internal/testutil/golden.go`
- Create: `orchestrator/internal/testutil/golden_test.go`
- Create: `orchestrator/internal/testutil/testdata/golden/example.json`

**Interfaces:**
- Produces: `func AssertGoldenBytes(t *testing.T, name string, got []byte)` — compares against `testdata/golden/<name>` in the calling package; regenerates when run with `-update`.

- [ ] **Step 1: Write the implementation first (flag-driven, test-the-flag-off-path)**

`orchestrator/internal/testutil/golden.go`:
```go
package testutil

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update", false, "update golden files instead of comparing against them")

// AssertGoldenBytes compares got against testdata/golden/<name> relative to
// the calling test's package directory. Run with
// `go test ./... -run TestGolden -update` to regenerate golden files from
// current output.
func AssertGoldenBytes(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("testutil: create golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("testutil: write golden file: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("testutil: read golden file %s (run with -update to create it): %v", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}
```

- [ ] **Step 2: Commit the example golden fixture**

`orchestrator/internal/testutil/testdata/golden/example.json`:
```json
{"hello":"world"}
```
(File contents must end with a single trailing newline, matching what `os.WriteFile` with the test's `got` below produces.)

- [ ] **Step 3: Write the test that proves the pattern**

`orchestrator/internal/testutil/golden_test.go`:
```go
package testutil

import "testing"

func TestAssertGoldenBytes_MatchesFile(t *testing.T) {
	AssertGoldenBytes(t, "example.json", []byte("{\"hello\":\"world\"}\n"))
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/testutil/... -run TestAssertGoldenBytes -v -short`
Expected: PASS.

- [ ] **Step 5: Verify the -update path regenerates identical content**

Run: `go test ./internal/testutil/... -run TestAssertGoldenBytes -update -short && git diff --stat orchestrator/internal/testutil/testdata/golden/example.json`
Expected: test passes, and `git diff --stat` shows **no changes** (the regenerated file matches the committed one byte-for-byte) — this is the actual proof that `-update` and the comparison path agree.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/testutil/golden.go orchestrator/internal/testutil/golden_test.go orchestrator/internal/testutil/testdata/golden/example.json
git commit -m "feat(testutil): add golden-file regression test support"
```

---

### Task 7: Mocks scaffold + Phase 5 extension-point stubs

**Files:**
- Create: `orchestrator/internal/testutil/mocks/doc.go`
- Create: `orchestrator/internal/testutil/bench.go`
- Create: `orchestrator/internal/testutil/fuzz.go`
- Create: `orchestrator/internal/testutil/property.go`
- Create: `orchestrator/internal/testutil/concurrency.go`

**Interfaces:**
- Produces: an empty, compiling `github.com/audspect/bas/internal/testutil/mocks` package. No new symbols in `testutil` itself — these are doc-only placeholder files.

This task is pure scaffolding with no logic, so it has no test-first cycle — verification is that everything still builds and vets clean.

- [ ] **Step 1: Create the mocks package scaffold**

`orchestrator/internal/testutil/mocks/doc.go`:
```go
// Package mocks holds hand-written fakes for external systems consumed by
// the orchestrator: SIEM providers, ticketing systems, detection
// connectors, agents, notifiers, and storage backends.
//
// As of Phase 0, internal/siem, internal/ticketing, and internal/connector
// expose concrete structs with no interface to mock against. Extracting the
// minimal interface each package needs, and adding the corresponding mock
// here, is in scope for Phase 4 — see
// docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md.
package mocks
```

- [ ] **Step 2: Create the extension-point stub files**

`orchestrator/internal/testutil/bench.go`:
```go
package testutil

// Benchmark helpers (Phase 5 — cross-cutting quality work) will live here:
// shared b.ResetTimer/b.ReportAllocs wrappers and standard dataset sizes
// for scoring/reporting benchmarks. Not implemented in Phase 0 — see
// docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md.
```

`orchestrator/internal/testutil/fuzz.go`:
```go
package testutil

// Fuzz-test helpers (Phase 5) will live here: seed corpora and generators
// for UUIDs, JSON/YAML payloads, SQL filter strings, and search queries.
// Not implemented in Phase 0 — see
// docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md.
```

`orchestrator/internal/testutil/property.go`:
```go
package testutil

// Property-based test helpers (Phase 5) will live here: generators and
// shrinkers for scoring-math invariants (e.g. Priority Score bounds under
// arbitrary KEV/EPSS/confidence combinations). Not implemented in Phase 0 —
// see docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md.
```

`orchestrator/internal/testutil/concurrency.go`:
```go
package testutil

// Concurrency-stress helpers (Phase 2 exercise workflows, Phase 5
// cross-cutting) will live here: goroutine-fan-out harnesses for exercising
// concurrent updates against TestDB. Not implemented in Phase 0 — see
// docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md.
```

- [ ] **Step 3: Verify everything builds and vets clean**

Run: `gofmt -l . && go build ./... && go vet ./...` (from `orchestrator/`)
Expected: `gofmt -l .` prints nothing (all clean), `go build`/`go vet` exit 0.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/testutil/mocks/doc.go orchestrator/internal/testutil/bench.go orchestrator/internal/testutil/fuzz.go orchestrator/internal/testutil/property.go orchestrator/internal/testutil/concurrency.go
git commit -m "chore(testutil): scaffold mocks package and Phase 5 extension-point stubs"
```

---

### Task 8: Coverage summary tool

**Files:**
- Create: `orchestrator/scripts/coveragesummary/main.go`
- Create: `orchestrator/scripts/coveragesummary/main_test.go`
- Modify: `orchestrator/go.mod`, `orchestrator/go.sum` (via `go get`)

**Interfaces:**
- Consumes: `golang.org/x/tools/cover.ParseProfiles(path string) ([]*cover.Profile, error)`, `cover.Profile{FileName string; Blocks []cover.ProfileBlock}`, `cover.ProfileBlock{StartLine, StartCol, EndLine, EndCol, NumStmt, Count int}`.
- Produces (package `main` in `scripts/coveragesummary`):
  - `type PackageCoverage struct { Package string; Covered, Total int }`
  - `func (p PackageCoverage) Percent() float64`
  - `func Summarize(profiles []*cover.Profile) []PackageCoverage`
  - `func PrintSummary(w io.Writer, summary []PackageCoverage)`

- [ ] **Step 1: Add the golang.org/x/tools dependency**

Run from `orchestrator/`:
```bash
go get golang.org/x/tools@latest
```
Expected: `go.mod`/`go.sum` gain `golang.org/x/tools`.

- [ ] **Step 2: Write the failing tests**

`orchestrator/scripts/coveragesummary/main_test.go`:
```go
package main

import (
	"bytes"
	"testing"

	"golang.org/x/tools/cover"
)

func TestSummarize_AggregatesPerPackage(t *testing.T) {
	profiles := []*cover.Profile{
		{
			FileName: "github.com/audspect/bas/internal/relationships/store.go",
			Blocks: []cover.ProfileBlock{
				{NumStmt: 10, Count: 10},
				{NumStmt: 5, Count: 0},
			},
		},
		{
			FileName: "github.com/audspect/bas/internal/relationships/handlers.go",
			Blocks: []cover.ProfileBlock{
				{NumStmt: 5, Count: 5},
			},
		},
		{
			FileName: "github.com/audspect/bas/internal/api/routes.go",
			Blocks: []cover.ProfileBlock{
				{NumStmt: 4, Count: 0},
			},
		},
	}

	got := Summarize(profiles)
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(got))
	}

	byPkg := map[string]PackageCoverage{}
	for _, pc := range got {
		byPkg[pc.Package] = pc
	}

	rel := byPkg["github.com/audspect/bas/internal/relationships"]
	if rel.Covered != 15 || rel.Total != 20 {
		t.Fatalf("relationships: covered=%d total=%d, want 15/20", rel.Covered, rel.Total)
	}

	api := byPkg["github.com/audspect/bas/internal/api"]
	if api.Covered != 0 || api.Total != 4 {
		t.Fatalf("api: covered=%d total=%d, want 0/4", api.Covered, api.Total)
	}
}

func TestPackageCoverage_Percent(t *testing.T) {
	pc := PackageCoverage{Covered: 15, Total: 20}
	if got := pc.Percent(); got != 75.0 {
		t.Fatalf("Percent() = %v, want 75.0", got)
	}
}

func TestPackageCoverage_Percent_ZeroTotal(t *testing.T) {
	pc := PackageCoverage{Covered: 0, Total: 0}
	if got := pc.Percent(); got != 0 {
		t.Fatalf("Percent() = %v, want 0", got)
	}
}

func TestPrintSummary_FormatsAlignedTable(t *testing.T) {
	var buf bytes.Buffer
	PrintSummary(&buf, []PackageCoverage{
		{Package: "api", Covered: 92, Total: 100},
		{Package: "verification", Covered: 98, Total: 100},
	})

	got := buf.String()
	if !bytes.Contains([]byte(got), []byte("92.0%")) {
		t.Fatalf("expected output to contain api coverage, got:\n%s", got)
	}
	if !bytes.Contains([]byte(got), []byte("98.0%")) {
		t.Fatalf("expected output to contain verification coverage, got:\n%s", got)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./scripts/coveragesummary/... -v`
Expected: FAIL — `undefined: Summarize` (compile error; `main.go` doesn't exist yet).

- [ ] **Step 4: Write the implementation**

`orchestrator/scripts/coveragesummary/main.go`:
```go
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/tools/cover"
)

func main() {
	profilePath := flag.String("profile", "coverage.out", "path to a go test -coverprofile output file")
	flag.Parse()

	profiles, err := cover.ParseProfiles(*profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coveragesummary: parse %s: %v\n", *profilePath, err)
		os.Exit(1)
	}

	PrintSummary(os.Stdout, Summarize(profiles))
}

// PackageCoverage holds aggregated statement coverage for one Go package.
type PackageCoverage struct {
	Package string
	Covered int
	Total   int
}

// Percent returns covered/total as a percentage, 0 if Total is 0.
func (p PackageCoverage) Percent() float64 {
	if p.Total == 0 {
		return 0
	}
	return float64(p.Covered) / float64(p.Total) * 100
}

// Summarize aggregates per-file profile blocks into per-package totals,
// weighted by statement count (matching go tool cover's own methodology).
func Summarize(profiles []*cover.Profile) []PackageCoverage {
	totals := map[string]*PackageCoverage{}
	for _, p := range profiles {
		pkg := path.Dir(p.FileName)
		pc, ok := totals[pkg]
		if !ok {
			pc = &PackageCoverage{Package: pkg}
			totals[pkg] = pc
		}
		for _, b := range p.Blocks {
			pc.Total += b.NumStmt
			if b.Count > 0 {
				pc.Covered += b.NumStmt
			}
		}
	}

	result := make([]PackageCoverage, 0, len(totals))
	for _, pc := range totals {
		result = append(result, *pc)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Package < result[j].Package })
	return result
}

// PrintSummary writes an aligned "pkg ... NN.N%" table to w.
func PrintSummary(w io.Writer, summary []PackageCoverage) {
	maxLen := 0
	for _, pc := range summary {
		if len(pc.Package) > maxLen {
			maxLen = len(pc.Package)
		}
	}
	for _, pc := range summary {
		dots := strings.Repeat(".", maxLen-len(pc.Package)+3)
		fmt.Fprintf(w, "%s %s %.1f%%\n", pc.Package, dots, pc.Percent())
	}
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./scripts/coveragesummary/... -v`
Expected: all 4 tests PASS.

- [ ] **Step 6: Smoke-test against a real coverage profile**

Run (from `orchestrator/`):
```bash
go test ./internal/testutil/... -short -coverprofile=/tmp/smoke-coverage.out
go run ./scripts/coveragesummary -profile=/tmp/smoke-coverage.out
```
Expected: prints a line for `github.com/audspect/bas/internal/testutil` with a coverage percentage (exact number will be low since `-short` skipped the DB-backed tests — that's fine, this step only proves the tool runs end-to-end against real output).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/scripts/coveragesummary/main.go orchestrator/scripts/coveragesummary/main_test.go orchestrator/go.mod orchestrator/go.sum
git commit -m "feat(scripts): add per-package coverage summary tool"
```

---

### Task 9: GitHub Actions CI workflow

**Files:**
- Create: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: all of Tasks 1-8 (`internal/testutil` build/tests, `scripts/coveragesummary`).
- Produces: a CI job named `test` that runs on push/PR to `main`.

- [ ] **Step 1: Write the workflow**

`.github/workflows/test.yml`:
```yaml
name: Test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: orchestrator
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: orchestrator/go.mod

      - name: gofmt check
        run: |
          fmt_out=$(gofmt -l .)
          if [ -n "$fmt_out" ]; then
            echo "The following files are not gofmt'd:"
            echo "$fmt_out"
            exit 1
          fi

      - name: go vet
        run: go vet ./...

      - name: install staticcheck
        run: go install honnef.co/go/tools/cmd/staticcheck@latest

      - name: staticcheck
        run: staticcheck ./...

      - name: go build
        env:
          CGO_ENABLED: "0"
        run: go build ./...

      - name: go test (race + coverage)
        run: go test ./... -race -coverprofile=coverage.out

      - name: coverage HTML report
        run: go tool cover -html=coverage.out -o coverage.html

      - name: coverage package summary
        run: go run ./scripts/coveragesummary -profile=coverage.out | tee coverage-summary.txt

      - uses: actions/upload-artifact@v4
        with:
          name: coverage-reports
          path: |
            orchestrator/coverage.out
            orchestrator/coverage.html
            orchestrator/coverage-summary.txt
```

- [ ] **Step 2: Verify the YAML is syntactically valid**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/test.yml')); print('valid')"` (from repo root)
Expected: prints `valid`, exit 0.

- [ ] **Step 3: Verify every command the workflow runs actually succeeds locally**

Run from `orchestrator/` (mirrors the workflow step-by-step, since no local Actions runner like `act`/`actionlint` is available on this host):
```bash
gofmt -l .
go vet ./...
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...
go build ./...
go test ./... -race -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
go run ./scripts/coveragesummary -profile=coverage.out
```
Expected: every command exits 0. `gofmt -l .` prints nothing. The coverage summary prints one line per package with a `NN.N%` figure, including the new `internal/testutil` and `scripts/coveragesummary` packages.

Note: `go test ./...` without `-short` runs the container-backed `internal/testutil` tests too — Docker Desktop must be running locally for this to pass, same as it will need to work when this later runs on `ubuntu-latest` (Docker preinstalled there).

- [ ] **Step 4: Clean up local coverage artifacts (not committed)**

Run (from `orchestrator/`): `rm -f coverage.out coverage.html coverage-summary.txt`

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: add GitHub Actions workflow (fmt, vet, staticcheck, build, race tests, coverage)"
```

---

## Final Verification

- [ ] **Run the full suite one more time end-to-end**

From `orchestrator/`:
```bash
gofmt -l .
go build ./...
go vet ./...
go test ./... -race
```
Expected: `gofmt -l .` empty, everything else exits 0, no test failures anywhere in the module (this also re-confirms Phase 0's changes didn't break any of the existing ~40 pre-existing test files).

- [ ] **Push**

```bash
git push
```

(Per standing instruction: push immediately after committing so the VM/deploy host can pull.)

## What's Explicitly Not in This Plan

Phases 1-5 (actual tests for `verification`, `relationships`, `exercise`, `api`, `integrity`, scoring, `siem`, `connector`, `ticketing`, and cross-cutting fuzz/property/concurrency work) are **not** part of Phase 0. Each gets its own brainstorming → spec → plan cycle, per `docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md`'s phased rollout table. Phase 1 (`verification` + `relationships`) is next.
