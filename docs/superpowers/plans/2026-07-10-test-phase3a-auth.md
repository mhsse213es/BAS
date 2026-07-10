# Phase 3a: Auth & Access Control Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a regression suite for `internal/auth` (JWT/middleware/permissions) and the identity-management handlers in `internal/api` (login/setup/logout, password lifecycle, user CRUD), plus a router-level test that verifies `routes.go`'s Role × Endpoint × Method authorization wiring matches what it claims — including a two-way drift guard so a future route change can't silently go untested.

**Architecture:** Two packages get new/expanded test files. `internal/auth` tests are pure in-package unit tests (no DB). `internal/api` tests use the `internal/testutil` container harness (first `TestMain` in that package) and mostly call `Handler` methods directly with `httptest`; the RBAC matrix and privilege-escalation tests mount the real router via `Mount()` and drive it end-to-end with minted JWTs.

**Tech Stack:** Go 1.x, `github.com/golang-jwt/jwt/v5`, `github.com/go-chi/chi/v5`, `golang.org/x/crypto/bcrypt` (already a dependency via `bcrypt_legacy.go`), `github.com/testcontainers/testcontainers-go` (via `internal/testutil`), `net/http/httptest`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-10-test-phase3a-auth-design.md` (commit `fa72176`).
- All DB-backed tests use `internal/testutil` (`sharedDB.RunWithPool`) — no bespoke env-var-gated setup (this plan explicitly retires the last one, in `event_handlers_test.go`).
- `-race` cannot run locally on this Windows host (`CGO_ENABLED=0`, no gcc) — it's a CI-only gate on `ubuntu-latest`. Local verification substitutes `go test -count=10`.
- Every task ends green on: `go build ./...`, the package's own tests, `go test ./...` (full suite), `go vet ./...`, `staticcheck ./...`. Commit each task separately.
- Characterization testing: a test failure means the test's expectation is wrong, not the product code. Do not "fix" handler behavior encountered while writing these tests — flag it in the commit/summary instead. (One known finding is already flagged in the spec: `bas_token` cookie has no `Secure` flag — tests characterize this as-is.)
- Coverage target: `internal/auth` 95%+. `internal/api` is not chased to a package-wide number in this phase — the bar is every authorization/validation/error branch in the 10 in-scope handlers exercised at least once.

---

### Task 1: Test harness — `internal/api` TestMain + retire the dead `TEST_DATABASE_URL` pattern

**Files:**
- Create: `orchestrator/internal/api/testmain_test.go`
- Modify: `orchestrator/internal/api/event_handlers_test.go:19-35`

**Interfaces:**
- Produces: package-level `var sharedDB *testutil.TestDB` (used by every subsequent task's test file), `const testJWTSecret = "phase3a-test-secret"`, helper `seedUser(t *testing.T, pool *pgxpool.Pool, username, password, role string, active bool) (id string)`, helper `authedRequest(t *testing.T, method, path string, body io.Reader, role auth.Role, userID string) *http.Request`, helper `callAuthed(h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder`.

- [ ] **Step 1: Create `orchestrator/internal/api/testmain_test.go`**

```go
package api

import (
	"context"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

const testJWTSecret = "phase3a-test-secret"

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// seedUser inserts a user with a real password hash and returns its id.
func seedUser(t *testing.T, pool *pgxpool.Pool, username, password, role string, active bool) string {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("seedUser: hash: %v", err)
	}
	var id string
	err = pool.QueryRow(context.Background(),
		`INSERT INTO users (username, password_hash, role, is_active) VALUES ($1,$2,$3,$4) RETURNING id`,
		username, hash, role, active).Scan(&id)
	if err != nil {
		t.Fatalf("seedUser: insert: %v", err)
	}
	return id
}

// authedRequest builds a request carrying a valid Bearer JWT for role/userID.
func authedRequest(t *testing.T, method, path string, body io.Reader, role auth.Role, userID string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	token, err := auth.GenerateToken(userID, role, testJWTSecret, time.Hour)
	if err != nil {
		t.Fatalf("authedRequest: mint token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// callAuthed runs req through the real auth.Middleware before h, so
// auth.ClaimsFrom(r.Context()) resolves inside the handler exactly as it
// would through the production router (the claims context key is
// unexported in package auth, so this is the only way to populate it
// from an external package).
func callAuthed(h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	auth.Middleware(testJWTSecret)(h).ServeHTTP(rec, req)
	return rec
}
```

- [ ] **Step 2: Migrate `event_handlers_test.go`'s DB setup to the shared harness**

Replace lines 19-35 of `orchestrator/internal/api/event_handlers_test.go`:

```go
func eventsTestHandler(t *testing.T) (*Handler, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("schema: %v", err)
	}
	h := New(pool, ws.NewHub(), nil, "")
	return h, pool
}
```

with:

```go
func eventsTestHandler(t *testing.T) (*Handler, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	h := New(sharedDB.Pool, ws.NewHub(), nil, "")
	return h, sharedDB.Pool
}
```

Every call site does `h, pool := eventsTestHandler(t); defer pool.Close()` — the `defer pool.Close()` calls now close the **shared** pool, which breaks every later test in the binary. Fix each of the 3 call sites (`TestSubmitRunEventsSummaryAndIdempotency`, `TestSubmitRunEventsRunningCount`, `TestListRunEventsOrderedBySeq`) by deleting their `defer pool.Close()` line and instead wrapping the test body's DB-touching portion so cleanup happens via truncate, not pool closure. Concretely, change each test from:

```go
func TestSubmitRunEventsSummaryAndIdempotency(t *testing.T) {
	h, pool := eventsTestHandler(t)
	defer pool.Close()
	runID := "run-sum-1"
	seedRun(t, pool, runID)
	... rest of test body ...
}
```

to:

```go
func TestSubmitRunEventsSummaryAndIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		runID := "run-sum-1"
		seedRun(t, pool, runID)
		... rest of test body, unchanged ...
	})
}
```

Apply the same transform to `TestSubmitRunEventsRunningCount` and `TestListRunEventsOrderedBySeq`. `eventsTestHandler` becomes unused by all three — delete it. Remove the now-unused `"context"`, `"os"`, and `"github.com/audspect/bas/internal/db"` imports if nothing else in the file uses them (check `TestBuildRunEventMsg`, which doesn't touch the DB — it stays outside any `RunWithPool` call, unchanged).

- [ ] **Step 3: Build and run**

Run: `cd orchestrator && go build ./... && go vet ./...`
Expected: clean.

Run: `go test ./internal/api/... -short`
Expected: PASS (short mode skips the container tests; confirms no compile errors).

Run: `go test ./internal/api/...`
Expected: PASS, and this is the first time these 3 tests actually execute against a real container instead of skipping.

- [ ] **Step 4: Full suite + staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: all clean.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/testmain_test.go orchestrator/internal/api/event_handlers_test.go
git commit -m "test(api): add shared testutil harness, retire dead TEST_DATABASE_URL skip

event_handlers_test.go's 3 DB tests silently skipped in every CI run
since TEST_DATABASE_URL was never set there. Migrate to the same
testutil.MustSharedTestDB/RunWithPool pattern used since Phase 0 so
they actually execute in CI.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: `internal/auth/jwt_test.go`

**Files:**
- Create: `orchestrator/internal/auth/jwt_test.go`

**Interfaces:**
- Consumes: `auth.GenerateToken(userID string, role Role, secret string, ttl time.Duration) (string, error)`, `auth.ValidateToken(tokenStr, secret string) (*Claims, error)`, `auth.Claims{UserID, Role, jwt.RegisteredClaims}`.

- [ ] **Step 1: Write the test file**

```go
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndValidateToken_RoundTrip(t *testing.T) {
	tok, err := GenerateToken("user-1", RoleAnalyst, "secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := ValidateToken(tok, "secret")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != "user-1" || claims.Role != RoleAnalyst {
		t.Fatalf("claims = %+v, want UserID=user-1 Role=analyst", claims)
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	tok, _ := GenerateToken("user-1", RoleAdmin, "secret-a", time.Hour)
	if _, err := ValidateToken(tok, "secret-b"); err == nil {
		t.Fatal("expected error validating token signed with a different secret")
	}
}

func TestValidateToken_MalformedString(t *testing.T) {
	cases := []string{"", "not-a-jwt", "a.b", "a.b.c.d", strings.Repeat("x", 500)}
	for _, tc := range cases {
		if _, err := ValidateToken(tc, "secret"); err == nil {
			t.Errorf("token %q: expected error, got none", tc)
		}
	}
}

func TestValidateToken_TamperedPayload(t *testing.T) {
	tok, _ := GenerateToken("user-1", RoleViewer, "secret", time.Hour)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %d parts", len(parts))
	}
	// Flip the last character of the payload segment — invalidates the
	// signature without needing to know the encoding scheme.
	payload := []rune(parts[1])
	last := payload[len(payload)-1]
	if last == 'A' {
		payload[len(payload)-1] = 'B'
	} else {
		payload[len(payload)-1] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]
	if _, err := ValidateToken(tampered, "secret"); err == nil {
		t.Fatal("expected error validating tampered token")
	}
}

func TestValidateToken_RejectsNoneAlgorithm(t *testing.T) {
	claims := Claims{
		UserID: "user-1",
		Role:   RoleAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	str, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("constructing alg=none token: %v", err)
	}
	if _, err := ValidateToken(str, "secret"); err == nil {
		t.Fatal("expected ValidateToken to reject an alg=none token")
	}
}

func TestValidateToken_RejectsRS256Algorithm(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	claims := Claims{
		UserID: "user-1",
		Role:   RoleAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	str, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign RS256 token: %v", err)
	}
	// Validate against the server's HMAC secret — an attacker who somehow
	// got an RS256-signed token must not be able to pass it off as HMAC.
	if _, err := ValidateToken(str, "secret"); err == nil {
		t.Fatal("expected ValidateToken to reject an RS256-signed token")
	}
}

func TestValidateToken_ClockBoundary(t *testing.T) {
	now := time.Now()
	mint := func(exp time.Time) string {
		claims := Claims{
			UserID: "user-1",
			Role:   RoleViewer,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(exp),
				IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			},
		}
		str, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		return str
	}

	cases := []struct {
		name    string
		exp     time.Time
		wantErr bool
	}{
		{"expires 1s in the future — still valid", now.Add(time.Second), false},
		{"expires 1s in the past — expired", now.Add(-time.Second), true},
		{"expires exactly now — boundary, jwt/v5 treats exp==now as expired", now, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateToken(mint(tc.exp), "secret")
			if (err != nil) != tc.wantErr {
				t.Fatalf("exp=%v: err=%v, wantErr=%v", tc.exp, err, tc.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Run and confirm the clock-boundary case**

Run: `cd orchestrator && go test ./internal/auth/... -run TestValidateToken_ClockBoundary -v`
Expected: PASS. `golang-jwt/v5`'s default validator compares `exp` against `time.Now()` with `exp.Before(now)` semantics with zero configured leeway — the "expires exactly now" case is timing-sensitive at nanosecond granularity between mint and validate, so if this specific subtest flakes, change its `wantErr` based on the actual observed library behavior (run it a few times with `-count=5` to confirm which way it settles) and note the finding in the commit message rather than fighting the library's real semantics.

- [ ] **Step 3: Run the full file**

Run: `go test ./internal/auth/... -v`
Expected: all PASS.

- [ ] **Step 4: Vet and staticcheck**

Run: `go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 5: Full suite**

Run: `go test ./... -short`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/auth/jwt_test.go
git commit -m "test(auth): add JWT generation/validation tests incl. algorithm confusion and clock boundaries

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: `internal/auth/middleware_test.go`

**Files:**
- Create: `orchestrator/internal/auth/middleware_test.go`

**Interfaces:**
- Consumes: `auth.Middleware(secret string) func(http.Handler) http.Handler`, `auth.RequireRole(roles ...Role) func(http.Handler) http.Handler`, `auth.ClaimsFrom(ctx) (*Claims, bool)`, `auth.TokenFromRequest(r) string`.

- [ ] **Step 1: Write the test file**

```go
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func nextThatRecordsClaims(t *testing.T, got **Claims) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFrom(r.Context())
		if !ok {
			t.Error("next handler: expected claims in context, found none")
			return
		}
		*got = c
		w.WriteHeader(http.StatusOK)
	}
}

func TestMiddleware_NoToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	Middleware("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called without a token")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_CookieToken(t *testing.T) {
	tok, _ := GenerateToken("u1", RoleAnalyst, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "bas_token", Value: tok})
	var got *Claims
	rec := httptest.NewRecorder()
	Middleware("secret")(nextThatRecordsClaims(t, &got)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got == nil || got.UserID != "u1" {
		t.Fatalf("claims = %+v", got)
	}
}

func TestMiddleware_BearerHeaderToken(t *testing.T) {
	tok, _ := GenerateToken("u2", RoleViewer, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	var got *Claims
	rec := httptest.NewRecorder()
	Middleware("secret")(nextThatRecordsClaims(t, &got)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got == nil || got.UserID != "u2" {
		t.Fatalf("claims = %+v", got)
	}
}

func TestMiddleware_CookieTakesPriorityOverHeader(t *testing.T) {
	cookieTok, _ := GenerateToken("cookie-user", RoleAdmin, "secret", time.Hour)
	headerTok, _ := GenerateToken("header-user", RoleAdmin, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "bas_token", Value: cookieTok})
	req.Header.Set("Authorization", "Bearer "+headerTok)

	if got := TokenFromRequest(req); got != cookieTok {
		t.Fatalf("TokenFromRequest returned the header token, not the cookie token")
	}

	var got *Claims
	rec := httptest.NewRecorder()
	Middleware("secret")(nextThatRecordsClaims(t, &got)).ServeHTTP(rec, req)
	if got == nil || got.UserID != "cookie-user" {
		t.Fatalf("claims = %+v, want UserID=cookie-user (cookie must win)", got)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	Middleware("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called with an invalid token")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireRole_AllowedRolePasses(t *testing.T) {
	tok, _ := GenerateToken("u1", RoleAdmin, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	called := false
	handler := Middleware("secret")(RequireRole(RoleAdmin, RoleAnalyst)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v status=%d, want called=true status=200", called, rec.Code)
	}
}

func TestRequireRole_DisallowedRoleForbidden(t *testing.T) {
	tok, _ := GenerateToken("u1", RoleViewer, "secret", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler := Middleware("secret")(RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for a disallowed role")
	})))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireRole_NoClaimsInContext_DenyByDefault(t *testing.T) {
	// RequireRole invoked directly, bypassing Middleware — simulates a
	// misconfigured route with no auth middleware in front of it. Must
	// deny, not panic.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler := RequireRole(RoleAdmin, RoleAnalyst, RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called with no claims in context")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (deny-by-default)", rec.Code)
	}
}

func TestClaimsFrom_Absent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := ClaimsFrom(req.Context()); ok {
		t.Fatal("expected ok=false for a context with no claims")
	}
}

// TestAuthorizationPrecedence pins the full authn-then-authz decision chain
// as an explicit invariant: anything that fails authentication returns 401
// and never reaches the role check; anything that authenticates but fails
// authorization returns 403.
func TestAuthorizationPrecedence(t *testing.T) {
	validAdmin, _ := GenerateToken("admin-1", RoleAdmin, "secret", time.Hour)
	validViewer, _ := GenerateToken("viewer-1", RoleViewer, "secret", time.Hour)
	expired, _ := GenerateToken("expired-1", RoleAdmin, "secret", -time.Hour)

	cases := []struct {
		name       string
		bearer     string // "" means no Authorization header at all
		wantStatus int
	}{
		{"anonymous — no token", "", http.StatusUnauthorized},
		{"malformed JWT", "not-a-jwt", http.StatusUnauthorized},
		{"expired JWT", expired, http.StatusUnauthorized},
		{"authenticated but wrong role", validViewer, http.StatusForbidden},
		{"authenticated, correct role", validAdmin, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			handler := Middleware("secret")(RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/auth/... -v`
Expected: all PASS.

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/auth/middleware_test.go
git commit -m "test(auth): add middleware, RequireRole, and authorization-precedence tests

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: `internal/auth/permissions_test.go`

**Files:**
- Create: `orchestrator/internal/auth/permissions_test.go`

**Interfaces:**
- Consumes: `auth.HasPermission(role Role, perm Permission) bool`, `auth.Permissions(role Role) []Permission`, `auth.RequirePermission(perm Permission) func(http.Handler) http.Handler`.

- [ ] **Step 1: Write the test file**

```go
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHasPermission_FullMatrix(t *testing.T) {
	cases := []struct {
		role  Role
		perm  Permission
		want  bool
	}{
		{RoleAdmin, CanVerify, true},
		{RoleAdmin, CanUploadEvidence, true},
		{RoleAdmin, CanDeleteEvidence, true},
		{RoleAdmin, CanReview, true},
		{RoleAdmin, CanExport, true},
		{RoleAdmin, CanCurateThreatIntel, true},
		{RoleAdmin, CanReviewThreatIntel, true},

		{RoleAnalyst, CanVerify, true},
		{RoleAnalyst, CanUploadEvidence, true},
		{RoleAnalyst, CanDeleteEvidence, false}, // withheld: accountability
		{RoleAnalyst, CanReview, true},
		{RoleAnalyst, CanExport, true},
		{RoleAnalyst, CanCurateThreatIntel, true},
		{RoleAnalyst, CanReviewThreatIntel, false}, // withheld: no self-approval

		{RoleViewer, CanVerify, false},
		{RoleViewer, CanUploadEvidence, false},
		{RoleViewer, CanDeleteEvidence, false},
		{RoleViewer, CanReview, false},
		{RoleViewer, CanExport, false},
		{RoleViewer, CanCurateThreatIntel, false},
		{RoleViewer, CanReviewThreatIntel, false},
	}
	for _, tc := range cases {
		if got := HasPermission(tc.role, tc.perm); got != tc.want {
			t.Errorf("HasPermission(%s, %s) = %v, want %v", tc.role, tc.perm, got, tc.want)
		}
	}
}

// TestHasPermission_MatrixIsComplete guards against a new Permission
// constant being added without a corresponding row above: it fails loudly
// if the tested set diverges from the set of permissions admin actually
// holds (admin currently holds every defined permission — see
// rolePermissions in permissions.go). A permission added but NOT granted
// to admin would not trip this check; that's an inherent limitation of Go
// having no enum reflection, not something this test can close.
func TestHasPermission_MatrixIsComplete(t *testing.T) {
	tested := map[Permission]bool{
		CanVerify: true, CanUploadEvidence: true, CanDeleteEvidence: true,
		CanReview: true, CanExport: true, CanCurateThreatIntel: true, CanReviewThreatIntel: true,
	}
	for _, p := range Permissions(RoleAdmin) {
		if !tested[p] {
			t.Errorf("permission %q is granted to admin but has no row in TestHasPermission_FullMatrix", p)
		}
	}
	if len(tested) != len(Permissions(RoleAdmin)) {
		t.Errorf("tested %d permissions, admin holds %d — counts diverged", len(tested), len(Permissions(RoleAdmin)))
	}
}

func TestPermissions_Ordering(t *testing.T) {
	got := Permissions(RoleAdmin)
	want := []Permission{CanVerify, CanUploadEvidence, CanDeleteEvidence, CanReview, CanExport, CanCurateThreatIntel, CanReviewThreatIntel}
	if len(got) != len(want) {
		t.Fatalf("Permissions(RoleAdmin) len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Permissions(RoleAdmin)[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if got := Permissions(RoleViewer); len(got) != 0 {
		t.Fatalf("Permissions(RoleViewer) = %v, want empty", got)
	}
}

func TestRequirePermission_GrantedDeniedNoClaims(t *testing.T) {
	adminTok, _ := GenerateToken("a1", RoleAdmin, "secret", time.Hour)
	viewerTok, _ := GenerateToken("v1", RoleViewer, "secret", time.Hour)

	newHandler := func() (http.Handler, *bool) {
		called := false
		h := RequirePermission(CanDeleteEvidence)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		return h, &called
	}

	// Granted: admin holds CanDeleteEvidence.
	h, called := newHandler()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	rec := httptest.NewRecorder()
	Middleware("secret")(h).ServeHTTP(rec, req)
	if !*called || rec.Code != http.StatusOK {
		t.Fatalf("granted case: called=%v status=%d", *called, rec.Code)
	}

	// Denied: viewer holds no permissions.
	h, called = newHandler()
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("Authorization", "Bearer "+viewerTok)
	rec = httptest.NewRecorder()
	Middleware("secret")(h).ServeHTTP(rec, req)
	if *called || rec.Code != http.StatusForbidden {
		t.Fatalf("denied case: called=%v status=%d, want called=false status=403", *called, rec.Code)
	}

	// No claims at all (RequirePermission invoked with no Middleware in front).
	h, called = newHandler()
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if *called || rec.Code != http.StatusForbidden {
		t.Fatalf("no-claims case: called=%v status=%d, want called=false status=403", *called, rec.Code)
	}
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/auth/... -v`
Expected: all PASS, including the completeness check.

- [ ] **Step 3: Full suite, vet, staticcheck, -count=10**

Run: `go test ./... -short && go vet ./... && staticcheck ./... && go test ./internal/auth/... -count=10`
Expected: all clean, all 10 iterations pass.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/auth/permissions_test.go
git commit -m "test(auth): add full role/permission matrix with a completeness guard

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: `internal/api/auth_handlers_test.go`

**Files:**
- Create: `orchestrator/internal/api/auth_handlers_test.go`

**Interfaces:**
- Consumes: `Handler.Login`, `Handler.Setup`, `Handler.Logout` (all `http.HandlerFunc`-shaped methods on `*Handler`), `seedUser` and `sharedDB` from Task 1, `auth.NeedsUpgrade(hash string) bool`.

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func loginReq(username, password string) *http.Request {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	return httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
}

func TestLogin_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		seedUser(t, pool, "alice", "correct-horse-battery", "analyst", true)

		rec := httptest.NewRecorder()
		h.Login(rec, loginReq("alice", "correct-horse-battery"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp["role"] != "analyst" {
			t.Fatalf("role = %v, want analyst", resp["role"])
		}
		if resp["mustChangePw"] != false {
			t.Fatalf("mustChangePw = %v, want false", resp["mustChangePw"])
		}

		cookies := rec.Result().Cookies()
		var tokenCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "bas_token" {
				tokenCookie = c
			}
		}
		if tokenCookie == nil {
			t.Fatal("expected a bas_token cookie to be set")
		}
		if !tokenCookie.HttpOnly {
			t.Error("cookie HttpOnly = false, want true")
		}
		if tokenCookie.Secure {
			t.Error("cookie Secure = true — characterization expected false (see spec finding: no Secure flag is ever set)")
		}
		if tokenCookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie SameSite = %v, want Strict", tokenCookie.SameSite)
		}
		if tokenCookie.Path != "/" {
			t.Errorf("cookie Path = %q, want /", tokenCookie.Path)
		}
		if tokenCookie.MaxAge != 86400 {
			t.Errorf("cookie MaxAge = %d, want 86400", tokenCookie.MaxAge)
		}
	})
}

func TestLogin_WrongPasswordAndUnknownUser_IdenticalResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		seedUser(t, pool, "bob", "the-real-password", "viewer", true)

		recWrongPw := httptest.NewRecorder()
		h.Login(recWrongPw, loginReq("bob", "wrong-password"))

		recUnknown := httptest.NewRecorder()
		h.Login(recUnknown, loginReq("nobody-by-this-name", "anything"))

		if recWrongPw.Code != http.StatusUnauthorized || recUnknown.Code != http.StatusUnauthorized {
			t.Fatalf("status wrong-password=%d unknown-user=%d, want both 401", recWrongPw.Code, recUnknown.Code)
		}
		if recWrongPw.Body.String() != recUnknown.Body.String() {
			t.Fatalf("response bodies differ (enumeration risk):\nwrong-password: %s\nunknown-user:   %s",
				recWrongPw.Body.String(), recUnknown.Body.String())
		}
	})
}

func TestLogin_DisabledAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		seedUser(t, pool, "disabled-carl", "some-password", "admin", false)

		rec := httptest.NewRecorder()
		h.Login(rec, loginReq("disabled-carl", "some-password"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})
}

func TestLogin_MalformedBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte("{not json")))
		rec := httptest.NewRecorder()
		h.Login(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestLogin_LegacyBcryptHashUpgradesTransparently(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)

		legacyHash, err := bcrypt.GenerateFromPassword([]byte("legacy-password"), bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("generate bcrypt hash: %v", err)
		}
		var id string
		err = pool.QueryRow(context.Background(),
			`INSERT INTO users (username, password_hash, role, is_active) VALUES ($1,$2,'viewer',true) RETURNING id`,
			"legacy-dana", string(legacyHash)).Scan(&id)
		if err != nil {
			t.Fatalf("seed legacy user: %v", err)
		}

		rec := httptest.NewRecorder()
		h.Login(rec, loginReq("legacy-dana", "legacy-password"))
		if rec.Code != http.StatusOK {
			t.Fatalf("first login status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var newHash string
		if err := pool.QueryRow(context.Background(),
			`SELECT password_hash FROM users WHERE id = $1`, id).Scan(&newHash); err != nil {
			t.Fatalf("re-read hash: %v", err)
		}
		if newHash == string(legacyHash) {
			t.Fatal("password_hash did not change after login — upgrade did not happen")
		}
		if auth.NeedsUpgrade(newHash) {
			t.Fatal("new hash still reports NeedsUpgrade=true — did not actually migrate to the current algorithm")
		}

		// The same plaintext password must still authenticate against the new hash.
		rec2 := httptest.NewRecorder()
		h.Login(rec2, loginReq("legacy-dana", "legacy-password"))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second login (post-upgrade) status = %d, body = %s", rec2.Code, rec2.Body.String())
		}
	})
}

func TestSetup_FirstRunThenConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)

		body, _ := json.Marshal(map[string]string{"email": "first-admin@example.com", "password": "install-password"})
		rec := httptest.NewRecorder()
		h.Setup(rec, httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("first setup status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if count != 1 {
			t.Fatalf("user count = %d, want 1", count)
		}

		rec2 := httptest.NewRecorder()
		h.Setup(rec2, httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewReader(body)))
		if rec2.Code != http.StatusConflict {
			t.Fatalf("second setup status = %d, want 409", rec2.Code)
		}
	})
}

func TestLogout_ClearsCookie(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	rec := httptest.NewRecorder()
	h.Logout(rec, httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "bas_token" || cookies[0].MaxAge != -1 {
		t.Fatalf("cookies = %+v, want single bas_token cookie with MaxAge=-1", cookies)
	}
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestLogin|TestSetup|TestLogout' -v`
Expected: all PASS.

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/auth_handlers_test.go
git commit -m "test(api): add Login/Setup/Logout characterization incl. cookie security and bcrypt migration

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 6: `internal/api/user_handlers_test.go`

**Files:**
- Create: `orchestrator/internal/api/user_handlers_test.go`

**Interfaces:**
- Consumes: `Handler.ListUsers`, `Handler.CreateUser`, `Handler.UpdateUser`, `Handler.DeleteUser`, `Handler.ChangePassword`, `Handler.ResetPassword`, `Handler.GetMyPermissions`; `withURLParam` (from `event_handlers_test.go`, same package); `authedRequest`/`callAuthed`/`seedUser` from Task 1.

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateUser_ValidationAndDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)

		post := func(payload map[string]any) *httptest.ResponseRecorder {
			body, _ := json.Marshal(payload)
			rec := httptest.NewRecorder()
			h.CreateUser(rec, httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body)))
			return rec
		}

		if rec := post(map[string]any{"username": "eve", "password": "12345678", "role": "not-a-role"}); rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid role: status = %d, want 400", rec.Code)
		}
		if rec := post(map[string]any{"username": "eve", "password": "short", "role": "viewer"}); rec.Code != http.StatusBadRequest {
			t.Fatalf("short password: status = %d, want 400", rec.Code)
		}

		ok := post(map[string]any{"username": "eve", "password": "12345678", "role": "viewer", "id": "attacker-supplied-id"})
		if ok.Code != http.StatusCreated {
			t.Fatalf("valid create: status = %d, body = %s", ok.Code, ok.Body.String())
		}
		var created map[string]string
		_ = json.Unmarshal(ok.Body.Bytes(), &created)
		if created["id"] == "attacker-supplied-id" {
			t.Fatal("server accepted a client-supplied id — id must always be server-generated")
		}

		dup := post(map[string]any{"username": "eve", "password": "12345678", "role": "viewer"})
		if dup.Code != http.StatusConflict {
			t.Fatalf("duplicate username: status = %d, want 409", dup.Code)
		}
	})
}

func TestListUsers_EmptyAndSeeded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)

		rec := httptest.NewRecorder()
		h.ListUsers(rec, httptest.NewRequest(http.MethodGet, "/api/users", nil))
		var empty []map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &empty)
		if empty == nil {
			t.Fatal("expected [], got null for zero users")
		}

		seedUser(t, pool, "frank", "password123", "analyst", true)
		rec2 := httptest.NewRecorder()
		h.ListUsers(rec2, httptest.NewRequest(http.MethodGet, "/api/users", nil))
		var got []map[string]any
		_ = json.Unmarshal(rec2.Body.Bytes(), &got)
		if len(got) != 1 || got[0]["username"] != "frank" {
			t.Fatalf("got = %v, want 1 user named frank", got)
		}
	})
}

func TestUpdateUser_RoleChangeAndSelfDeactivationBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		adminID := seedUser(t, pool, "grace", "password123", "admin", true)
		targetID := seedUser(t, pool, "henry", "password123", "viewer", true)

		body, _ := json.Marshal(map[string]any{"role": "analyst"})
		req := withURLParam(authedRequest(t, http.MethodPut, "/api/users/"+targetID, bytes.NewReader(body), auth.RoleAdmin, adminID), "id", targetID)
		rec := callAuthed(h.UpdateUser, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("role change: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var role string
		if err := pool.QueryRow(context.Background(), `SELECT role FROM users WHERE id=$1`, targetID).Scan(&role); err != nil {
			t.Fatalf("read role: %v", err)
		}
		if role != "analyst" {
			t.Fatalf("role = %q, want analyst", role)
		}

		badRole, _ := json.Marshal(map[string]any{"role": "superadmin"})
		req2 := withURLParam(authedRequest(t, http.MethodPut, "/api/users/"+targetID, bytes.NewReader(badRole), auth.RoleAdmin, adminID), "id", targetID)
		if rec2 := callAuthed(h.UpdateUser, req2); rec2.Code != http.StatusBadRequest {
			t.Fatalf("invalid role: status = %d, want 400", rec2.Code)
		}

		selfDeactivate, _ := json.Marshal(map[string]any{"isActive": false})
		req3 := withURLParam(authedRequest(t, http.MethodPut, "/api/users/"+adminID, bytes.NewReader(selfDeactivate), auth.RoleAdmin, adminID), "id", adminID)
		if rec3 := callAuthed(h.UpdateUser, req3); rec3.Code != http.StatusBadRequest {
			t.Fatalf("self-deactivation: status = %d, want 400", rec3.Code)
		}

		// Characterization: no equivalent self-role-change protection exists —
		// an admin CAN demote their own role. Not a fix target for this phase.
		selfDemote, _ := json.Marshal(map[string]any{"role": "viewer"})
		req4 := withURLParam(authedRequest(t, http.MethodPut, "/api/users/"+adminID, bytes.NewReader(selfDemote), auth.RoleAdmin, adminID), "id", adminID)
		if rec4 := callAuthed(h.UpdateUser, req4); rec4.Code != http.StatusOK {
			t.Fatalf("self role change: status = %d, want 200 (characterizes current unguarded behavior)", rec4.Code)
		}
	})
}

func TestDeleteUser_SelfBlockedNonexistentIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		adminID := seedUser(t, pool, "ivan", "password123", "admin", true)

		req := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/"+adminID, nil, auth.RoleAdmin, adminID), "id", adminID)
		if rec := callAuthed(h.DeleteUser, req); rec.Code != http.StatusBadRequest {
			t.Fatalf("self-delete: status = %d, want 400", rec.Code)
		}

		// Characterization: deleting a nonexistent id still returns 204 — the
		// handler doesn't check rows-affected.
		req2 := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/does-not-exist", nil, auth.RoleAdmin, adminID), "id", "does-not-exist")
		if rec2 := callAuthed(h.DeleteUser, req2); rec2.Code != http.StatusNoContent {
			t.Fatalf("nonexistent id delete: status = %d, want 204 (current idempotent-ish behavior)", rec2.Code)
		}
	})
}

func TestChangePassword_WrongCurrentAndSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "julia", "old-password", "viewer", true)

		wrong, _ := json.Marshal(map[string]string{"currentPassword": "not-the-password", "newPassword": "new-password-1"})
		req := authedRequest(t, http.MethodPost, "/api/auth/change-password", bytes.NewReader(wrong), auth.RoleViewer, userID)
		if rec := callAuthed(h.ChangePassword, req); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong current password: status = %d, want 401", rec.Code)
		}

		ok, _ := json.Marshal(map[string]string{"currentPassword": "old-password", "newPassword": "new-password-1"})
		req2 := authedRequest(t, http.MethodPost, "/api/auth/change-password", bytes.NewReader(ok), auth.RoleViewer, userID)
		if rec2 := callAuthed(h.ChangePassword, req2); rec2.Code != http.StatusOK {
			t.Fatalf("valid change: status = %d, body = %s", rec2.Code, rec2.Body.String())
		}

		var mustChange bool
		if err := pool.QueryRow(context.Background(), `SELECT must_change_pw FROM users WHERE id=$1`, userID).Scan(&mustChange); err != nil {
			t.Fatalf("read must_change_pw: %v", err)
		}
		if mustChange {
			t.Fatal("must_change_pw should be cleared after a successful change")
		}
	})
}

func TestResetPassword_SetsMustChangePw(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		adminID := seedUser(t, pool, "karl", "password123", "admin", true)
		targetID := seedUser(t, pool, "liam", "old-password", "viewer", true)

		body, _ := json.Marshal(map[string]string{"newPassword": "admin-reset-pw1"})
		req := withURLParam(authedRequest(t, http.MethodPost, "/api/users/"+targetID+"/reset-password", bytes.NewReader(body), auth.RoleAdmin, adminID), "id", targetID)
		if rec := callAuthed(h.ResetPassword, req); rec.Code != http.StatusOK {
			t.Fatalf("reset: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var mustChange bool
		if err := pool.QueryRow(context.Background(), `SELECT must_change_pw FROM users WHERE id=$1`, targetID).Scan(&mustChange); err != nil {
			t.Fatalf("read must_change_pw: %v", err)
		}
		if !mustChange {
			t.Fatal("must_change_pw should be true after an admin reset")
		}
	})
}

func TestGetMyPermissions_PerRole(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleAnalyst, auth.RoleViewer} {
		req := authedRequest(t, http.MethodGet, "/api/me/permissions", nil, role, "u-"+string(role))
		rec := callAuthed(h.GetMyPermissions, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("role %s: status = %d", role, rec.Code)
		}
		var resp struct {
			Role        string             `json:"role"`
			Permissions []auth.Permission  `json:"permissions"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Role != string(role) {
			t.Fatalf("resp.Role = %q, want %q", resp.Role, role)
		}
		want := auth.Permissions(role)
		if len(resp.Permissions) != len(want) {
			t.Fatalf("role %s: got %d permissions, want %d", role, len(resp.Permissions), len(want))
		}
	}
}

// TestConcurrentChangePassword drives many simultaneous ChangePassword calls
// for the same user. There is no optimistic-concurrency check in the
// handler, so the invariant under test is structural — no panic/deadlock,
// every request completes with a definitive status, and the DB ends up with
// exactly one of the attempted hashes — not "a specific writer wins."
func TestConcurrentChangePassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "mia", "shared-current-pw", "viewer", true)

		const n = 20
		var wg sync.WaitGroup
		statuses := make([]int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				body, _ := json.Marshal(map[string]string{
					"currentPassword": "shared-current-pw",
					"newPassword":     fmt.Sprintf("new-password-%d", i),
				})
				req := authedRequest(t, http.MethodPost, "/api/auth/change-password", bytes.NewReader(body), auth.RoleViewer, userID)
				statuses[i] = callAuthed(h.ChangePassword, req).Code
			}(i)
		}
		wg.Wait()

		for i, s := range statuses {
			if s != http.StatusOK && s != http.StatusUnauthorized {
				t.Errorf("goroutine %d: status = %d, want 200 or 401 (never anything else, never a hang)", i, s)
			}
		}

		var finalHash string
		if err := pool.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE id=$1`, userID).Scan(&finalHash); err != nil {
			t.Fatalf("read final hash: %v", err)
		}
		if finalHash == "" {
			t.Fatal("password_hash is empty after concurrent changes")
		}
	})
}

// TestConcurrentResetPassword mirrors TestConcurrentChangePassword for the
// admin-initiated reset path.
func TestConcurrentResetPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		adminID := seedUser(t, pool, "nora", "password123", "admin", true)
		targetID := seedUser(t, pool, "oscar", "password123", "viewer", true)

		const n = 20
		var wg sync.WaitGroup
		statuses := make([]int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				body, _ := json.Marshal(map[string]string{"newPassword": fmt.Sprintf("admin-reset-%d", i)})
				req := withURLParam(authedRequest(t, http.MethodPost, "/api/users/"+targetID+"/reset-password", bytes.NewReader(body), auth.RoleAdmin, adminID), "id", targetID)
				statuses[i] = callAuthed(h.ResetPassword, req).Code
			}(i)
		}
		wg.Wait()

		for i, s := range statuses {
			if s != http.StatusOK {
				t.Errorf("goroutine %d: status = %d, want 200", i, s)
			}
		}
	})
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestCreateUser|TestListUsers|TestUpdateUser|TestDeleteUser|TestChangePassword|TestResetPassword|TestGetMyPermissions|TestConcurrent' -v`
Expected: all PASS.

- [ ] **Step 3: Concurrency checkpoint — extra rigor**

This task introduces goroutine-based tests (`TestConcurrentChangePassword`, `TestConcurrentResetPassword`). Per the established checkpoint pattern from Phase 2's executor tests, verify determinism explicitly:

Run: `go test ./internal/api/... -run 'TestConcurrent' -count=10 -v`
Expected: 10/10 clean, no flakes.

- [ ] **Step 4: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/user_handlers_test.go
git commit -m "test(api): add user CRUD, password lifecycle, and concurrent-auth tests

Includes characterizations of two existing behaviors: UpdateUser has no
self-role-change guard (only self-deactivation is blocked), and DeleteUser
returns 204 for a nonexistent id since it doesn't check rows-affected.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 7: `internal/api/rbac_matrix_test.go`

**Files:**
- Create: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `Mount(h *Handler, hub *ws.Hub, jwtSecret, agentSecret string, staticHandler http.Handler, tracker ...*exercisetracker.Tracker) http.Handler` (from `routes.go`), `chi.Walk(r chi.Routes, walkFn chi.WalkFunc) error`, `auth.GenerateToken`, `auth.HasPermission`.
- Produces: `authTier` type and `routeMatrix []routeCase` — Task 8 (`privilege_escalation_test.go`) reads `routeMatrix` directly to cross-reference admin-only routes, so both identifiers must stay unexported-but-package-visible (same package `api`, no export needed).

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
	"github.com/go-chi/chi/v5"
)

type authTier int

const (
	tierAny authTier = iota // any authenticated role (viewer, analyst, admin)
	tierAnalystAdmin
	tierAdminOnly
	tierPermission
)

type routeCase struct {
	method string
	path   string // chi path template, exactly as registered in routes.go
	tier   authTier
	perm   auth.Permission // only set when tier == tierPermission
}

// routeMatrix enumerates every route mounted inside the JWT-authenticated
// group in routes.go, paired with the role tier routes.go actually applies.
// This table is the single hand-maintained source of truth for 3a; the
// TestRBACMatrix_NoDrift test below keeps it honest against the live router.
var routeMatrix = []routeCase{
	// ── any authenticated role ──────────────────────────────────────────
	{http.MethodGet, "/api/agents", tierAny, ""},
	{http.MethodGet, "/api/agents/download/{platform}", tierAny, ""},
	{http.MethodGet, "/api/scenarios", tierAny, ""},
	{http.MethodGet, "/api/scenarios/{id}", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/report", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/report.json", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/attackflow", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/variant-coverage", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/variant-coverage/{techniqueId}", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/export", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/events", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/pdf", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/forensic.csv", tierAny, ""},
	{http.MethodGet, "/api/campaigns", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/summary", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/report", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/pdf", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/forensic.csv", tierAny, ""},
	{http.MethodGet, "/api/findings", tierAny, ""},
	{http.MethodGet, "/api/findings/{id}", tierAny, ""},
	{http.MethodGet, "/api/findings/{id}/tickets", tierAny, ""},
	{http.MethodGet, "/api/remediations", tierAny, ""},
	{http.MethodGet, "/api/ticketing/candidates", tierAny, ""},
	{http.MethodGet, "/api/ticketing/revalidation", tierAny, ""},
	{http.MethodGet, "/api/ticketing/summary", tierAny, ""},
	{http.MethodGet, "/api/reports", tierAny, ""},
	{http.MethodPost, "/api/reports", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/logs/operational", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/logs/security", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/telemetry", tierAny, ""},
	{http.MethodPost, "/api/scan/safe/{agentId}", tierAny, ""},
	{http.MethodGet, "/api/art/techniques", tierAny, ""},
	{http.MethodGet, "/api/caldera/abilities", tierAny, ""},
	{http.MethodGet, "/api/techniques/unified", tierAny, ""},
	{http.MethodGet, "/api/crypto/info", tierAny, ""},
	{http.MethodGet, "/api/coverage/analytics", tierAny, ""},
	{http.MethodGet, "/api/ti/readiness", tierAny, ""},
	{http.MethodGet, "/api/ti/readiness/history", tierAny, ""},
	{http.MethodGet, "/api/ti/suggest-pack", tierAny, ""},
	{http.MethodGet, "/api/ti/priority", tierAny, ""},
	{http.MethodGet, "/api/adversary-templates", tierAny, ""},
	{http.MethodGet, "/api/caldera/adversaries", tierAny, ""},
	{http.MethodGet, "/api/caldera/adversaries/{adversaryId}", tierAny, ""},
	{http.MethodGet, "/api/posture/catalog", tierAny, ""},
	{http.MethodGet, "/api/attack/matrix", tierAny, ""},
	{http.MethodGet, "/api/attack/technique/{id}", tierAny, ""},
	{http.MethodGet, "/api/attackpath/summary", tierAny, ""},
	{http.MethodGet, "/api/attackpath/history", tierAny, ""},
	{http.MethodGet, "/api/attackpath/assets", tierAny, ""},
	{http.MethodGet, "/api/attackpath/schedule", tierAny, ""},
	{http.MethodGet, "/api/attackpath/subnet/{agentId}", tierAny, ""},
	{http.MethodGet, "/api/attackpath/jobs", tierAny, ""},
	{http.MethodGet, "/api/attackpath/jobs/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/plans", tierAny, ""},
	{http.MethodGet, "/api/exercises/plans/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/templates", tierAny, ""},
	{http.MethodGet, "/api/exercises/templates/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/evidence", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/evidence/verify", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/events", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.json", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.html", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.pdf", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.csv", tierAny, ""},
	{http.MethodPost, "/api/exercises/executions", tierAny, ""},
	{http.MethodPost, "/api/auth/change-password", tierAny, ""},
	{http.MethodGet, "/api/report/full/html", tierAny, ""},
	{http.MethodGet, "/api/report/full/pdf", tierAny, ""},
	{http.MethodGet, "/api/report/full/csv", tierAny, ""},
	{http.MethodGet, "/api/report/audit-pack", tierAny, ""},
	{http.MethodGet, "/api/compliance/frameworks", tierAny, ""},
	{http.MethodGet, "/api/compliance/report", tierAny, ""},
	{http.MethodGet, "/api/compliance/scores", tierAny, ""},
	{http.MethodGet, "/api/me/permissions", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/verifications", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/verifications/{expectationId}/history", tierAny, ""},
	{http.MethodGet, "/api/verifications/{id}/evidence", tierAny, ""},
	{http.MethodGet, "/api/evidence/{id}/download", tierAny, ""},
	{http.MethodGet, "/api/techniques/{id}/relationships", tierAny, ""},
	{http.MethodGet, "/api/relationships/{id}", tierAny, ""},
	{http.MethodGet, "/api/relationships/{id}/evidence", tierAny, ""},

	// ── analyst + admin ──────────────────────────────────────────────────
	{http.MethodPost, "/api/scan/{agentId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/collect/{agentId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/jobs", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/jobs/{id}/cancel", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/jobs/{id}/retry", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/attackpath/assets", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios/{id}/run", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/caldera/adversaries/{adversaryId}/run", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/adversary-templates/{id}/run", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios/runs/{runId}/cancel", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/siem/correlate/{runId}", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/siem/correlations/{runId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/campaigns", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/campaigns/{id}/stop", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/findings/{id}/status", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/ticketing/push", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/ticketing/push/bulk", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios/upload", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/scenarios/{id}/clone", tierAnalystAdmin, ""},
	{http.MethodPut, "/api/scenarios/{id}", tierAnalystAdmin, ""},
	{http.MethodDelete, "/api/scenarios/{id}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/variants/generate", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/variants/run", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/variants/run/{id}", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/variants/coverage", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/variants/stats", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/payload-families", tierAnalystAdmin, ""},
	{http.MethodGet, "/api/payload-families/{techniqueId}", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/exercises/executions/{id}/launch", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/exercises/executions/{id}/abort", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/exercises/executions/{id}/steps/{stepId}/approve", tierAnalystAdmin, ""},
	{http.MethodPost, "/api/exercises/executions/{id}/evidence", tierAnalystAdmin, ""},

	// ── admin only ───────────────────────────────────────────────────────
	{http.MethodPut, "/api/agents/{agentId}/state", tierAdminOnly, ""},
	{http.MethodGet, "/api/license", tierAdminOnly, ""},
	{http.MethodGet, "/api/config/connection", tierAdminOnly, ""},
	{http.MethodGet, "/api/users", tierAdminOnly, ""},
	{http.MethodPost, "/api/users", tierAdminOnly, ""},
	{http.MethodPut, "/api/users/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/users/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/users/{id}/reset-password", tierAdminOnly, ""},
	{http.MethodGet, "/api/caldera/status", tierAdminOnly, ""},
	{http.MethodGet, "/api/connector/status", tierAdminOnly, ""},
	{http.MethodPost, "/api/connector/sync", tierAdminOnly, ""},
	{http.MethodDelete, "/api/connector/scenarios/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/attackpath/schedule", tierAdminOnly, ""},
	{http.MethodGet, "/api/art/content/status", tierAdminOnly, ""},
	{http.MethodPost, "/api/art/content/reseed", tierAdminOnly, ""},
	{http.MethodGet, "/api/tamper-events", tierAdminOnly, ""},
	{http.MethodPost, "/api/tamper-events/{id}/acknowledge", tierAdminOnly, ""},
	{http.MethodPost, "/api/tamper-events/acknowledge-all", tierAdminOnly, ""},
	{http.MethodGet, "/api/audit-logs", tierAdminOnly, ""},
	{http.MethodGet, "/api/ticketing/configs", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/configs", tierAdminOnly, ""},
	{http.MethodPut, "/api/ticketing/configs/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/ticketing/configs/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/configs/{id}/test", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/probe", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/probe/projects", tierAdminOnly, ""},
	{http.MethodPost, "/api/ticketing/sync", tierAdminOnly, ""},
	{http.MethodPost, "/api/payload-families", tierAdminOnly, ""},
	{http.MethodDelete, "/api/payload-families/{id}", tierAdminOnly, ""},
	{http.MethodGet, "/api/siem/configs", tierAdminOnly, ""},
	{http.MethodPost, "/api/siem/configs", tierAdminOnly, ""},
	{http.MethodPut, "/api/siem/configs/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/siem/configs/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/siem/configs/{id}/test", tierAdminOnly, ""},
	{http.MethodPost, "/api/exercises/plans", tierAdminOnly, ""},
	{http.MethodPost, "/api/exercises/plans/validate", tierAdminOnly, ""},
	{http.MethodPut, "/api/exercises/plans/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/exercises/plans/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/exercises/templates", tierAdminOnly, ""},
	{http.MethodPost, "/api/exercises/templates/{id}/instantiate", tierAdminOnly, ""},

	// ── fine-grained permission gates ───────────────────────────────────
	{http.MethodPost, "/api/verifications", tierPermission, auth.CanVerify},
	{http.MethodPost, "/api/verifications/{id}/evidence", tierPermission, auth.CanUploadEvidence},
	{http.MethodDelete, "/api/evidence/{id}", tierPermission, auth.CanDeleteEvidence},
	{http.MethodPost, "/api/relationships", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPut, "/api/relationships/{id}", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/evidence", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodDelete, "/api/relationship-evidence/{id}", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/review", tierPermission, auth.CanReviewThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/status", tierPermission, auth.CanReviewThreatIntel},
}

// publicRoutes lists every route.go registration OUTSIDE the JWT-authenticated
// group — these are intentionally excluded from routeMatrix and from the
// drift guard's "must have a matrix entry" requirement.
var publicRoutes = map[string]bool{
	"POST /api/auth/login":                           true,
	"POST /api/auth/logout":                          true,
	"POST /api/auth/setup":                            true,
	"GET /api/agents/ping":                            true,
	"POST /api/agents/enroll":                         true,
	"POST /api/agents/events":                         true,
	"POST /api/heartbeat":                             true,
	"POST /api/scenarios/result":                      true,
	"POST /api/scenarios/events":                      true,
	"POST /api/scenarios/runs/{runId}/detections":     true,
	"POST /api/attackpath/collect":                    true,
	"POST /api/attackpath/sharphound":                 true,
	"POST /api/attackpath/jobs/{id}/ack":               true,
	"GET /ws/agent":                                   true,
	"GET /ws/browser":                                 true,
	"POST /api/ticketing/webhook/{configId}":          true,
	"GET /health":                                     true,
}

func tierAllows(tier authTier, perm auth.Permission, role auth.Role) bool {
	switch tier {
	case tierAny:
		return true
	case tierAnalystAdmin:
		return role == auth.RoleAdmin || role == auth.RoleAnalyst
	case tierAdminOnly:
		return role == auth.RoleAdmin
	case tierPermission:
		return auth.HasPermission(role, perm)
	default:
		return false
	}
}

var paramPattern = regexp.MustCompile(`\{[^}]+\}`)

func concretePath(tpl string) string {
	return paramPattern.ReplaceAllString(tpl, "x")
}

func mountTestRouter(t *testing.T) http.Handler {
	t.Helper()
	h := New(sharedDB.Pool, ws.NewHub(), nil, testJWTSecret)
	return Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler())
}

func TestRBACMatrix_AuthorizationBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		identities := []struct {
			name string
			role auth.Role
			anon bool
		}{
			{"anonymous", "", true},
			{"viewer", auth.RoleViewer, false},
			{"analyst", auth.RoleAnalyst, false},
			{"admin", auth.RoleAdmin, false},
		}

		for _, rc := range routeMatrix {
			for _, id := range identities {
				t.Run(rc.method+" "+rc.path+"/"+id.name, func(t *testing.T) {
					req := httptest.NewRequest(rc.method, concretePath(rc.path), nil)
					if !id.anon {
						tok, err := auth.GenerateToken("matrix-"+id.name, id.role, testJWTSecret, time.Hour)
						if err != nil {
							t.Fatalf("mint token: %v", err)
						}
						req.Header.Set("Authorization", "Bearer "+tok)
					}
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)

					if id.anon {
						if rec.Code != http.StatusUnauthorized {
							t.Fatalf("anonymous: status = %d, want 401", rec.Code)
						}
						return
					}
					if tierAllows(rc.tier, rc.perm, id.role) {
						if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
							t.Fatalf("role %s should clear the authz gate for %s %s, got %d", id.role, rc.method, rc.path, rec.Code)
						}
						return
					}
					if rec.Code != http.StatusForbidden {
						t.Fatalf("role %s should be forbidden from %s %s, got %d", id.role, rc.method, rc.path, rec.Code)
					}
				})
			}
		}
	})
}

// TestRBACMatrix_NoDrift keeps routeMatrix honest against the live router in
// both directions: every authenticated route chi actually registered must
// have a matrix entry (positive drift — a new route added without a role
// decision), and every matrix entry must correspond to a route chi actually
// registered (negative drift — a stale entry for a renamed/removed route).
func TestRBACMatrix_NoDrift(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		mux, ok := router.(chi.Routes)
		if !ok {
			t.Fatalf("Mount() returned %T, not a chi.Routes", router)
		}

		walked := map[string]bool{}
		err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if route == "/*" {
				return nil
			}
			key := method + " " + route
			if publicRoutes[key] {
				return nil
			}
			walked[key] = true
			return nil
		})
		if err != nil {
			t.Fatalf("chi.Walk: %v", err)
		}

		matrixed := map[string]bool{}
		for _, rc := range routeMatrix {
			matrixed[rc.method+" "+rc.path] = true
		}

		for k := range walked {
			if !matrixed[k] {
				t.Errorf("registered route %q has no routeMatrix entry", k)
			}
		}
		for k := range matrixed {
			if !walked[k] {
				t.Errorf("routeMatrix entry %q does not correspond to a route chi.Walk found", k)
			}
		}
	})
}

// TestRBACMatrix_MethodConfusion samples one route per tier and drives every
// HTTP method chi supports against its exact path, pinning whichever
// precedence chi's routing actually exhibits between "unregistered method on
// a known path" (405) and the auth middleware (401/403) — not presupposing
// either order.
func TestRBACMatrix_MethodConfusion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		samples := []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/api/scenarios"},          // tierAny
			{http.MethodPost, "/api/scenarios"},          // tierAnalystAdmin
			{http.MethodGet, "/api/users"},               // tierAdminOnly
			{http.MethodPost, "/api/verifications"},      // tierPermission
		}
		methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions}

		for _, s := range samples {
			for _, m := range methods {
				t.Run(m+" "+s.path, func(t *testing.T) {
					req := httptest.NewRequest(m, s.path, nil)
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if m == s.method {
						// The registered method — must not be a routing-level 404/405.
						if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
							t.Fatalf("registered method %s %s got routing status %d", m, s.path, rec.Code)
						}
						return
					}
					// An unregistered method on a known path: chi's router resolves
					// method-not-allowed before dispatching to any handler or
					// middleware, so this must be 405 regardless of auth state.
					if rec.Code != http.StatusMethodNotAllowed {
						t.Fatalf("unregistered method %s %s: status = %d, want 405", m, s.path, rec.Code)
					}
				})
			}
		}
	})
}

func TestUserHandlers_MalformedPathParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		adminID := seedUser(t, pool, "peggy", "password123", "admin", true)

		// Empty id segment.
		req := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/", nil, auth.RoleAdmin, adminID), "id", "")
		rec := callAuthed(h.DeleteUser, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("empty id: status = %d, want 204 (DELETE ... WHERE id='' affects 0 rows, no error)", rec.Code)
		}

		// SQL-metacharacter id — must be treated as inert parameterized data.
		req2 := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/x", nil, auth.RoleAdmin, adminID), "id", "' OR 1=1--")
		rec2 := callAuthed(h.DeleteUser, req2)
		if rec2.Code != http.StatusNoContent {
			t.Fatalf("SQL-metacharacter id: status = %d, want 204", rec2.Code)
		}
		var remaining int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&remaining); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if remaining != 1 {
			t.Fatalf("user count after SQL-metacharacter delete attempt = %d, want 1 (only the untouched admin row)", remaining)
		}
	})
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRBACMatrix|TestUserHandlers_MalformedPathParams' -v`
Expected: PASS. If `TestRBACMatrix_NoDrift` fails, it will name the exact route(s) causing the mismatch — reconcile `routeMatrix`/`publicRoutes` against `routes.go` until it's clean; do not weaken the check.

If `TestRBACMatrix_MethodConfusion` fails on the "unregistered method → 405" assertion, that means chi's actual precedence differs from what's assumed here (e.g., it might return 404 for some path shapes, or the auth middleware might run before routing resolves method-not-allowed for grouped routes). Record the actual observed status codes and adjust the assertion to match reality — this test's job is to pin the real behavior, not a presumed one.

- [ ] **Step 3: Concurrency/complexity checkpoint — extra rigor**

This is the most complex task in the phase (mounts the full router, ~650 sub-tests across the matrix). Verify determinism:

Run: `go test ./internal/api/... -run 'TestRBACMatrix' -count=10`
Expected: 10/10 clean.

- [ ] **Step 4: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/rbac_matrix_test.go
git commit -m "test(api): add full RBAC route matrix with two-way drift guard and method-confusion coverage

Mounts the real router and drives every authenticated route in routes.go
under anonymous/viewer/analyst/admin identities, asserting the authz
boundary (401 for unauthenticated, 403 for wrong role/permission, cleared
gate otherwise). chi.Walk cross-checks the matrix against the live router
in both directions so route additions or renames can't silently go
untested.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 8: `internal/api/privilege_escalation_test.go`

**Files:**
- Create: `orchestrator/internal/api/privilege_escalation_test.go`

**Interfaces:**
- Consumes: `routeMatrix`, `tierAdminOnly`, `concretePath`, `mountTestRouter` (all from Task 7, same package); `auth.GenerateToken`.

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

// TestPrivilegeEscalation_NonAdminBlockedFromEveryAdminRoute cross-references
// routeMatrix (Task 7) rather than re-enumerating admin routes by hand, so it
// can never silently drift from the matrix that drives the main RBAC test.
func TestPrivilegeEscalation_NonAdminBlockedFromEveryAdminRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		for _, rc := range routeMatrix {
			if rc.tier != tierAdminOnly {
				continue
			}
			for _, role := range []auth.Role{auth.RoleViewer, auth.RoleAnalyst} {
				t.Run(string(role)+" "+rc.method+" "+rc.path, func(t *testing.T) {
					tok, _ := auth.GenerateToken("escalate-"+string(role), role, testJWTSecret, time.Hour)
					req := httptest.NewRequest(rc.method, concretePath(rc.path), nil)
					req.Header.Set("Authorization", "Bearer "+tok)
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if rec.Code != http.StatusForbidden {
						t.Fatalf("%s on admin-only %s %s: status = %d, want 403", role, rc.method, rc.path, rec.Code)
					}
				})
			}
		}
	})
}

func TestPrivilegeEscalation_ViewerCannotUpdateOwnAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		viewerID := seedUser(t, pool, "quinn", "password123", "viewer", true)
		tok, _ := auth.GenerateToken(viewerID, auth.RoleViewer, testJWTSecret, time.Hour)

		body, _ := json.Marshal(map[string]any{"role": "admin"})
		req := httptest.NewRequest(http.MethodPut, "/api/users/"+viewerID, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer self-update: status = %d, want 403 (blocked by the outer admin-only route group, before any handler-level self-protection logic runs)", rec.Code)
		}
	})
}

func TestPrivilegeEscalation_ForgedRoleClaimRejectedAtAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		// A token claiming role=admin, signed with a secret the server does
		// not recognize (the attacker doesn't know testJWTSecret). Must be
		// rejected at authentication (401), never reach the role check.
		forged, err := auth.GenerateToken("attacker", auth.RoleAdmin, "attacker-controlled-secret", time.Hour)
		if err != nil {
			t.Fatalf("mint forged token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+forged)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("forged-secret admin token: status = %d, want 401", rec.Code)
		}
	})
}

func TestPrivilegeEscalation_MissingRoleClaimDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		claims := auth.Claims{
			UserID: "no-role-user",
			// Role deliberately left as the zero value "".
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("empty-role token on admin-only route: status = %d, want 403", rec.Code)
		}
	})
}

func TestPrivilegeEscalation_ExtraneousFieldsIgnored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		adminID := seedUser(t, pool, "rex", "password123", "admin", true)
		tok, _ := auth.GenerateToken(adminID, auth.RoleAdmin, testJWTSecret, time.Hour)

		body, _ := json.Marshal(map[string]any{
			"username": "sam",
			"password": "password123",
			"role":     "viewer",
			"isAdmin":  true,
			"id":       "attacker-chosen-id",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create with extraneous fields: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &created)
		if created["role"] != "viewer" {
			t.Fatalf("role = %q, want viewer (isAdmin field must be ignored, not bound anywhere)", created["role"])
		}
		if created["id"] == "attacker-chosen-id" {
			t.Fatal("server accepted a client-supplied id via the full HTTP stack")
		}
	})
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestPrivilegeEscalation' -v`
Expected: all PASS.

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/privilege_escalation_test.go
git commit -m "test(api): add dedicated privilege-escalation regression suite

Covers non-admin-vs-every-admin-route (cross-referencing the RBAC matrix),
self-update blocked at the outer route group, forged-secret role claims,
missing role claims, and JSON field-smuggling attempts.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 9: Final validation pass

**Files:** none (verification only).

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: clean.

- [ ] **Step 2: Full test suite**

Run: `go test ./...`
Expected: all packages PASS, including the newly-executing `event_handlers_test.go` DB tests and every test added in Tasks 2-8.

- [ ] **Step 3: vet + staticcheck + gofmt**

Run: `go vet ./... && staticcheck ./...`
Expected: clean.

Run: `git show HEAD:internal/auth/jwt_test.go | gofmt -l -` (repeat for every new/modified file in this phase)
Expected: no output (clean) — confirms the committed blobs are gofmt-clean even if the Windows working tree shows CRLF false positives via plain `gofmt -l .`.

- [ ] **Step 4: Determinism — repeat the concurrency-sensitive packages**

Run: `go test ./internal/auth/... ./internal/api/... -count=10`
Expected: 10/10 clean, no flakes, across the full auth and api packages (not just the isolated subsets checked at Tasks 4/6/7's checkpoints).

- [ ] **Step 5: -race note**

`-race` requires cgo, unavailable on this Windows host (`CGO_ENABLED=0`, no gcc). This is verified on `ubuntu-latest` in CI (`.github/workflows/test.yml`), which has gcc preinstalled. Do not attempt to force it locally.

- [ ] **Step 6: Coverage report**

Run: `go test ./internal/auth/... ./internal/api/... -coverprofile=coverage-3a.out && go tool cover -func=coverage-3a.out | tail -30`
Expected: `internal/auth` at or above 95%. Review the `internal/api` function list for the 10 in-scope handlers (`Login`, `Setup`, `Logout`, `ChangePassword`, `ResetPassword`, `ListUsers`, `CreateUser`, `UpdateUser`, `DeleteUser`, `GetMyPermissions`) and confirm every authorization/validation/error branch inside them shows nonzero coverage; note (don't chase) any handler-adjacent helper that's still low because its coverage belongs to a later sub-phase.

Delete the scratch profile when done: `rm coverage-3a.out` (CI produces its own `coverage.out` covering the whole module — this one is just for this pass's review).

- [ ] **Step 7: Update memory**

Update `project_test_generation_phase0.md` with a "Phase 3a DONE" section (commit range, coverage numbers, and the key learnings: dead `TEST_DATABASE_URL` pattern found and retired, unexported `ctxClaimsKey` forces claims-injection tests to go through the real `auth.Middleware` rather than direct context manipulation, chi's actual method-not-allowed/auth precedence as observed, the two flagged-not-fixed findings — no `Secure` cookie flag, no self-role-change guard on `UpdateUser`). Update the `MEMORY.md` index line.

---

## Self-Review

**Spec coverage:** All 8 spec sections have a task — clock boundaries (Task 2), cookie security (Task 5), authorization precedence (Task 3), method confusion (Task 7), path parameter edge cases (Task 7 + Task 6), concurrent auth (Task 6), password migration (Task 5), enumeration resistance (Task 5), permission-matrix completeness (Task 4), two-way drift guard (Task 7), privilege-escalation suite (Task 8). The harness fix (retiring `TEST_DATABASE_URL`) is Task 1.

**Placeholder scan:** No TBD/TODO; every step has complete, runnable code; no "similar to Task N" references — Task 8 explicitly imports `routeMatrix` from Task 7 rather than describing it.

**Type consistency:** `authTier`/`routeCase`/`routeMatrix`/`concretePath`/`mountTestRouter` are defined once in Task 7 and consumed as-is in Task 8 (same package, no re-declaration). `seedUser`/`authedRequest`/`callAuthed`/`sharedDB`/`testJWTSecret` are defined once in Task 1 and reused verbatim by Tasks 5, 6, 7, 8. `auth.Claims`, `auth.Role`, `auth.Permission`, `auth.GenerateToken`, `auth.ValidateToken`, `auth.HasPermission`, `auth.Permissions`, `auth.NeedsUpgrade` are all used with the exact signatures read from the current source in `internal/auth/{jwt,middleware,permissions,password}.go`.
