# Phase 3a: Auth & Access Control — Test Design

## Goal

Build a comprehensive regression suite for the authentication and authorization boundary — `internal/auth` (JWT, middleware, permissions) plus the `internal/api` handlers that manage identity (login/setup/logout, password lifecycle, user CRUD) — and validate that `routes.go`'s Role × Endpoint × Method wiring actually enforces what it claims to. This is the security perimeter of the whole platform; per the master test-generation strategy, it belongs in the 95%+ confidence tier alongside verification/relationships/integrity.

This is sub-phase **3a** of Phase 3 (`internal/api`, 12,553 lines / 27 files — too large for one spec, decomposed into 3a Auth & Access Control → 3c Agent Lifecycle → 3b Scenario & Run Lifecycle → 3e remaining domain handlers → 3d Reporting & Compliance, per user-directed ordering: build confidence from the security perimeter inward).

## Scope

**In scope:**
- `internal/auth`: `jwt.go`, `middleware.go`, `permissions.go`
- `internal/api` handlers: `Login`, `Setup`, `Logout`, `ChangePassword`, `ResetPassword`, `ListUsers`, `CreateUser`, `UpdateUser`, `DeleteUser`, `GetMyPermissions`
- `internal/api/routes.go` — full authenticated-route authorization matrix, tested against the real mounted router (`Mount()`)
- Harness fix: migrate `event_handlers_test.go`'s DB setup off the dead `TEST_DATABASE_URL` pattern (never set in CI — those 3 tests have silently skipped on every CI run since they were written) onto `internal/testutil`, and add the `api` package's first `TestMain`

**Explicitly out of scope** (belongs to later sub-phases or separate follow-up):
- Agent-secret/MAC auth (`validateAgentAuth`, `verifyResultMAC`) → 3c Agent Lifecycle (distinct trust boundary — agent identity, not user identity)
- WebSocket upgrade success path (`/ws/agent`, `/ws/browser`) — only pre-upgrade auth rejection is tested; a real upgrade handshake belongs to the `ws` package
- Business-logic correctness of every other route's handler (scenario CRUD, reporting, SIEM, etc.) → 3b/3d/3e
- Async audit-log row content (`auditLog`/`auditLogAs` fire via unawaited `go func()`) — asserting on it would reintroduce goroutine-timing flake risk, same call Phase 2 made for handler async bodies
- **Known finding, not fixed here**: the `bas_token` cookie never sets `Secure: true` (verified — no TLS conditional exists anywhere in the codebase). Tests characterize the actual current flags (`Secure: false` included). This is a real gap worth a dedicated security fix — flagged for you to schedule separately, not silently patched inside a test-generation phase.

## Test files

### 1. `internal/auth/jwt_test.go`
- `GenerateToken`/`ValidateToken` round trip (correct claims survive)
- Wrong secret → error
- Wrong signing algorithm — a token crafted with `alg: none` or RS256 must be rejected (the `ValidateToken` keyfunc explicitly checks `*jwt.SigningMethodHMAC`)
- Malformed / truncated token string → error
- Tampered payload (flip a byte, signature no longer matches) → error
- **Clock boundary matrix**: token that expires exactly `now`, 1 second before `now`, 1 second after `now` — pins the exact off-by-one behavior of the underlying `jwt/v5` library's leeway (none configured, so expect zero-leeway exact-boundary behavior; test records whatever the library actually does at the boundary instant using a fixed/frozen `time.Now()` substitute via constructing claims directly rather than racing real wall-clock)

### 2. `internal/auth/middleware_test.go`
- `Middleware`: no token → 401; cookie only → claims in context; `Authorization: Bearer` header only → claims in context; **both present → cookie wins** (per the documented priority order); invalid/expired token → 401
- `RequireRole`: allowed role passes to next handler; disallowed role → 403; **no claims in context → 403 (deny-by-default)**, not a panic
- `ClaimsFrom`: present/absent cases
- **Authorization precedence matrix** (table-driven, one table covering the full decision chain): anonymous / malformed JWT / expired JWT / valid-but-wrong-role / valid-but-missing-permission → each asserts the *specific* status code (401 for anything that fails authentication, 403 for anything that fails authorization post-authentication) so the precedence order (authn before authz) is pinned as an explicit invariant, not incidentally true

### 3. `internal/auth/permissions_test.go`
- `HasPermission` table-driven over all 3 roles × all 7 `Permission` constants — locks in the exact matrix including the deliberate Analyst withholdings (`CanDeleteEvidence`, `CanReviewThreatIntel`)
- **Completeness invariant**: the test's permission list is asserted equal (as a set) to `auth.Permissions(auth.RoleAdmin)` (admin currently holds all defined permissions) — if a new `Permission` constant is added and granted to admin but the test table isn't updated, the completeness check fails instead of silently under-testing it. (Documented caveat: a new permission added but *not* granted to admin wouldn't trip this check — inherent to Go's lack of const-enum reflection; noted inline in the test.)
- `RequirePermission` middleware: granted → next called; denied → 403; no claims → 403

### 4. `internal/api/testmain_test.go` (new)
- `sharedDB *testutil.TestDB` + `TestMain` — identical pattern to `internal/exercise/store_test.go`. Shared by every api DB-backed test file from here through 3b-3e.

### 5. `internal/api/auth_handlers_test.go`
- `Login`: success sets `bas_token` cookie + returns `role`/`userId`/`mustChangePw`; wrong password and unknown username return the *identical* error body and status (enumeration resistance — assert byte-identical response body, not just status code; timing is not asserted exactly but the test notes both paths execute the same `VerifyPassword` call regardless of DB hit, which is the actual mechanism providing timing resistance — no artificial sleep to test); disabled account (`is_active=false`) → 403 with a distinct message; malformed JSON body → 400
- **Cookie security assertions on success**: `HttpOnly=true`, `Secure=false` (characterized as-is per the flagged finding above), `SameSite=Strict`, `Path=/`, `MaxAge=86400`
- **Legacy password migration**: seed a user with a real bcrypt hash (via `golang.org/x/crypto/bcrypt.GenerateFromPassword`, matching what `bcrypt_legacy.go` verifies), log in — assert (a) login succeeds, (b) `password_hash` column changed, (c) `auth.NeedsUpgrade(newHash)` is now `false` (confirms the new hash uses the current algorithm, not just "changed to *something*"), (d) a second login with the same plaintext password against the new hash also succeeds
- `Setup`: first call with no existing users creates an admin and returns 200; second call → 409 `{"error":"already configured"}` (idempotent-safe for the installer)
- `Logout`: clears cookie (`MaxAge=-1`), 204

### 6. `internal/api/user_handlers_test.go`
- `CreateUser`: invalid role → 400; password <8 chars → 400; duplicate username → 409; success → 201 with expected body; **body-field immunity**: a request body containing an unbound `id` field is ignored (id is server-generated, not client-suppliable) — characterizes that clients can't pre-seed IDs
- `ListUsers`: returns seeded rows, empty case returns `[]` not `null`
- `UpdateUser`: role change persists; self-deactivation blocked (400, `claims.UserID == targetID`); invalid role rejected; **no self-role-protection exists** — an admin *can* demote their own role (characterized, not fixed, since `UpdateUser` only special-cases `IsActive`, not `Role`, for self-targeting)
- `DeleteUser`: self-delete blocked (400); **deleting a nonexistent ID still returns 204** (the handler doesn't check rows-affected) — characterized as current idempotent-ish behavior
- `ChangePassword`: wrong current password → 401; success rehashes and clears `must_change_pw`; **structurally cross-user-proof** — the handler takes no target-user parameter at all (always `claims.UserID`), so there is no cross-user vector to test around; this is noted as a design confirmation, not a gap
- `ResetPassword`: sets `must_change_pw=true`; new password authenticates on next login
- `GetMyPermissions`: returns `{role, permissions}` matching `auth.Permissions(claims.Role)` for each of the 3 roles
- **Concurrent auth operations**: N goroutines (e.g. 20) issuing concurrent `ChangePassword` calls for the same user with different new passwords, and separately N concurrent `ResetPassword` calls from an admin — assert no panics/deadlocks, every request gets a definitive response (success or a real error, never a hang), and the final `password_hash` in the DB is one of the attempted values (last-write-wins is an acceptable outcome here since `ChangePassword`/`ResetPassword` have no optimistic-concurrency check — the invariant is "no corruption," not "a specific writer wins," following the same lesson as Phase 1's Attest concurrency test)

### 7. `internal/api/rbac_matrix_test.go`
Mounts the real router via `Mount(h, ws.NewHub(), secret, "", http.NotFoundHandler())`. Mints one JWT per role (`admin`/`analyst`/`viewer`) via `auth.GenerateToken`, plus an anonymous (no-token) case.

- **Route matrix**: hand-written table of every authenticated route in `routes.go` — `(method, path template, requiredTier)` where tier ∈ {any-authenticated, analyst-or-admin, admin-only, permission:X}. For permission-gated routes (`CanVerify`, `CanCurateThreatIntel`, etc.) mint a token with a role known to hold/lack that permission per `permissions.go`'s matrix.
- **Blocked combos**: exact status asserted — 401 for anonymous/invalid-token, 403 for wrong-role/wrong-permission.
- **Permitted combos**: status asserted as *not* 401/403 (authz-boundary only, per prior agreement — full 2xx correctness depends on seeded data/optional deps owned by 3b-3e).
- **Method confusion**: for a sample of representative routes (at least one per tier), issue every HTTP method chi supports (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS) against the registered path and assert the *actual* observed behavior — for a method that has no registered handler on that path, chi's default `MethodNotAllowedHandler` (405) applies. The test pins whichever precedence chi actually exhibits between routing (405) and the auth middleware (401/403) rather than presupposing one — run once, record the real result, assert it explicitly with a comment explaining what was observed.
- **Path parameter edge cases** (`internal/api/user_handlers_test.go`, not the matrix — these are handler-level, not routing-level): empty ID segment (`/api/users//reset-password` — chi treats the empty segment as a literal empty `URLParam`), a syntactically-valid-but-nonexistent ID, and a SQL-metacharacter-laden ID (`' OR 1=1--`) — asserts the parameterized query treats it as inert data (no injection, just a definitive not-found/no-op response).
- **Two-way drift guard**: `chi.Walk()`s the live mounted router to collect every registered `(method, path)` pair.
  - *Positive*: every walked authenticated route must have a matrix entry — an unentried route fails the test by name, so a future route added to `routes.go` without an explicit role decision breaks CI instead of silently going untested.
  - *Negative*: every matrix entry must correspond to a route `chi.Walk` actually found — a stale entry (route renamed/removed) fails the test by name too, so the matrix can't silently drift out of sync with reality in either direction.

### 8. `internal/api/privilege_escalation_test.go` (new, dedicated per your request)
A named regression suite for the highest-impact authorization failure modes, kept separate from the matrix/handler tests for visibility:
- Analyst/Viewer JWT against every admin-only route in the matrix → 403 (cross-reference against the matrix table, not re-enumerated by hand)
- Viewer attempts `UpdateUser` on their own account → 403 (blocked by `RequireRole(Admin)` before the handler's own self-protection logic even runs — confirms the outer gate, not just the inner one)
- Forged-role JWT: a token with `role: admin` claims signed with a secret the server doesn't recognize → 401 (rejected at authentication, never reaches the role check — same underlying mechanism as the jwt.go wrong-secret test, asserted here through the full HTTP stack via `Mount()` to confirm the precedence, not just the library call)
- Token missing the `role` claim entirely (empty `Role` string) → `RequireRole`'s `allowed[claims.Role]` lookup misses for any non-empty required-role set → 403, confirmed explicitly rather than assumed
- `CreateUser`/`UpdateUser` request bodies containing extraneous privilege-adjacent fields (`"isAdmin": true`, `"id": "<other-user-id>"`) are silently ignored because the request struct doesn't bind them — confirms there's no shadow field an attacker could smuggle through `encoding/json`'s default unknown-field tolerance

## Coverage target

`internal/auth` → **95%+** line coverage (small, security-critical, matches the master spec's top tier).

`internal/api` overall is **not** chased to a package-wide percentage in this sub-phase — per your guidance, security-branch coverage matters more than line coverage here. The concrete bar for 3a: every authorization decision branch, every validation branch, and every error-return branch in the 10 in-scope handlers is exercised at least once. The full `internal/api` package reaches its 90%+ target only after 3b-3e land.

## Determinism

All DB-backed tests use `internal/testutil` (`sharedDB.RunWithPool`), consistent with Phases 0-2 — no bespoke env-var-gated setup. The concurrent-auth tests assert structural invariants (no panic/deadlock, definitive terminal state) rather than a specific interleaving outcome, avoiding the flake patterns already ruled out in Phase 1/2. `-race` remains CI-only on this Windows host (no local cgo); local verification substitutes `-count=10`.
