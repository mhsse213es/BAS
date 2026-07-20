# Enable RLS on `users` Table Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make tenant isolation on the `users` table a database-enforced invariant by wrapping every remaining `users`-touching code path in `db.WithTenant` and enabling forced Row-Level Security on the table.

**Architecture:** The pilot already scoped `ListUsers`/`UpdateUser`/`DeleteUser` and created a dormant `tenant_isolation` RLS policy. This plan migrates the remaining paths (Login, first-run Setup, CreateUser, ChangePassword, ResetPassword, SSO JIT, SCIM CRUD, and the startup `ensureAdminUser` seed) to run their queries inside a tenant-scoped transaction, then flips the policy to `ENABLE`/`FORCE ROW LEVEL SECURITY`. RLS is inert on un-hardened installs (superuser bypass) and enforces once Spec 1's role hardening is applied. Correctness is proven by a new non-superuser integration harness that reproduces hardened-prod conditions — a superuser test connection would bypass RLS and hide a missed wrapper.

**Tech Stack:** Go, `github.com/jackc/pgx/v5` (`pgx.Tx`, `pgxpool`), chi router, Postgres 16, testcontainers (Docker-gated).

## Global Constraints

- **Tenant seam:** every `users` query must run inside `db.WithTenant(ctx, pool, tenantID string, isPlatformAdmin bool, fn func(pgx.Tx) error) error` (`orchestrator/internal/db/tenant.go`). Inside `fn`, use the `tx` for all queries — never `h.db` (that would run outside the tenant transaction).
- **Caller context helper:** `callerTenant(r *http.Request) (tenantID string, isPlatformAdmin bool)` (`handlers.go:1963`) returns `("default", false)` for a tenant-less caller, `(*claims.TenantID, claims.IsPlatformAdmin)` otherwise. Reuse it — do not reimplement.
- **Platform-admin context** is the literal pair `("", true)` — used only for pre-auth/system paths (Login, first-run Setup, `ensureAdminUser`).
- **Policy body is frozen.** The `tenant_isolation` policy predicate in `postgres.go` does NOT change. Only the `ENABLE`/`FORCE` statements are added.
- **Username stays globally `UNIQUE`.** Do not add a tenant to any username lookup's uniqueness assumption.
- **No login-UX change.** Token shape, cookie, and response body are unchanged.
- **Windows build host cannot run Docker.** All container-backed tests (`sharedDB.RunWithPool`, the new probe harness) are Docker-gated and run on the VM. On Windows, the per-task gate is `go build ./... && go vet ./... && gofmt -l` (expect no output). Test-run steps below note "VM" where they need Docker.
- **Commit + push after every task** (user pulls on the VM). Work directly on `main`.
- Run all `go`/`gofmt` commands from `orchestrator/`.

---

### Task 1: Wrap Login + first-run Setup in platform-admin context

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`Login` 273-338, `Setup` 344-379)

**Interfaces:**
- Consumes: `db.WithTenant`, `pgx.Tx` (both already imported in this file by the pilot).
- Produces: no new exported symbols. Behavior unchanged under superuser; under RLS these paths resolve the globally-unique username / seed the first admin.

**Why platform-admin:** Login is pre-authentication — no tenant is known yet. `username` is globally `UNIQUE`, so a platform-admin ("see all tenants") lookup returns exactly one row. The token minted is still scoped to the row's own `tenant_id`. Setup runs before any user exists.

- [ ] **Step 1: Wrap the `Login` DB access in a platform-admin transaction**

Replace the SELECT + the two conditional UPDATEs (current lines 286-319) so all three run inside one `db.WithTenant(..., "", true, ...)`. Keep the password-verify / audit / token logic outside the transaction (it doesn't touch the DB). Concretely, restructure `Login` so the row read happens in the transaction, returns the scanned fields, then the upgrade/last_login UPDATEs happen in a second short transaction (or the same one). Minimal version — read in a tenant tx, then do the bookkeeping UPDATEs in a tenant tx:

```go
	var id, hash, role, authSource string
	var isActive, mustChangePw bool
	var tenantID *string
	dbErr := db.WithTenant(r.Context(), h.db, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT id, password_hash, role, is_active, must_change_pw, tenant_id, auth_source FROM users WHERE username = $1`, req.Username,
		).Scan(&id, &hash, &role, &isActive, &mustChangePw, &tenantID, &authSource)
	})
	// Evaluate password even on DB miss to prevent timing-based user enumeration.
	ok, needsUpgrade, _ := auth.VerifyPassword(req.Password, hash)
	if dbErr != nil || !ok || authSource == "sso" {
		h.auditLogAs(r, "", "user.login", req.Username, map[string]any{"username": req.Username, "reason": "invalid credentials"}, "fail")
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if needsUpgrade {
		if newHash, hErr := auth.HashPassword(req.Password); hErr == nil {
			_ = db.WithTenant(r.Context(), h.db, "", true, func(tx pgx.Tx) error {
				_, e := tx.Exec(r.Context(), `UPDATE users SET password_hash = $1 WHERE id = $2`, newHash, id)
				return e
			})
		}
	}
	if !isActive {
		h.auditLogAs(r, id, "user.login", id, map[string]any{"username": req.Username, "reason": "account disabled"}, "fail")
		jsonError(w, "account is disabled — contact your administrator", http.StatusForbidden)
		return
	}

	token, err := auth.GenerateTenantToken(id, auth.Role(role), tenantID, tenantID == nil, h.secret, 24*time.Hour)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	_ = db.WithTenant(r.Context(), h.db, "", true, func(tx pgx.Tx) error {
		_, e := tx.Exec(r.Context(), `UPDATE users SET last_login = NOW() WHERE id = $1`, id)
		return e
	})
```

Note: `db.WithTenant` returns `pgx.ErrNoRows` from `.Scan` on a username miss, which flows into `dbErr` — same "invalid credentials" branch as before. Timing behavior is preserved (password is still verified on miss).

- [ ] **Step 2: Wrap the `Setup` COUNT + INSERT in a platform-admin transaction**

Replace the `h.db.QueryRow(... COUNT ...)` (355) and `h.db.Exec(... INSERT ...)` (368) so both run in `db.WithTenant(..., "", true, ...)`:

```go
	var count int
	if err := db.WithTenant(r.Context(), h.db, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT COUNT(*) FROM users`).Scan(&count)
	}); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "already configured"})
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	err = db.WithTenant(r.Context(), h.db, "", true, func(tx pgx.Tx) error {
		_, e := tx.Exec(r.Context(),
			`INSERT INTO users (username, password_hash, role, must_change_pw) VALUES ($1, $2, 'admin', false)`,
			req.Email, hash)
		return e
	})
	if err != nil {
		jsonError(w, "failed to create admin user", http.StatusInternalServerError)
		return
	}
```

- [ ] **Step 3: Verify build/vet/format on Windows**

Run (from `orchestrator/`): `go build ./... ; go vet ./internal/api/... ; gofmt -l internal/api/handlers.go`
Expected: build + vet clean; `gofmt -l` prints nothing.

- [ ] **Step 4: Commit + push**

```bash
git add orchestrator/internal/api/handlers.go
git commit -m "feat(multitenancy): run Login + first-run Setup in platform-admin tenant context"
git push
```

---

### Task 2: Wrap CreateUser, ChangePassword, ResetPassword in caller context

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`CreateUser` 2021-2091, `ChangePassword` 2213-2255, `ResetPassword` 2258-2281)

**Interfaces:**
- Consumes: `callerTenant`, `db.WithTenant`, `pgx.Tx`.
- Produces: `ResetPassword` gains a 404-on-zero-rows outcome (previously always 200) so a cross-tenant reset is observably rejected.

- [ ] **Step 1: Wrap `CreateUser`'s INSERT**

`CreateUser` already resolves the target `tenantID` and has `claims`. Replace the `h.db.QueryRow(... INSERT ... RETURNING id)` block (2072-2086) with a `WithTenant` using the resolved tenant + the caller's platform-admin flag. A tenant admin's `tenantID` equals its own tenant (WITH CHECK passes); a platform-admin's `isPlatformAdmin=true` bypasses the predicate:

```go
	var id string
	err = db.WithTenant(r.Context(), h.db, tenantID, claims.IsPlatformAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`INSERT INTO users (username, password_hash, role, must_change_pw, tenant_id)
			 VALUES ($1, $2, $3, true, $4)
			 RETURNING id`,
			req.Username, hash, req.Role, tenantID,
		).Scan(&id)
	})
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "username already exists", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
```

- [ ] **Step 2: Wrap `ChangePassword`'s SELECT + UPDATE**

Use `callerTenant(r)` for context (the caller edits their own row, which lives in their tenant; a platform-admin caller gets the bypass). Wrap both the hash SELECT (2233) and the UPDATE (2249):

```go
	tenantID, isPlatformAdmin := callerTenant(r)
	var hash string
	if err := db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT password_hash FROM users WHERE id = $1`, claims.UserID).Scan(&hash)
	}); err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	if ok, _, _ := auth.VerifyPassword(req.CurrentPassword, hash); !ok {
		jsonError(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}
	_ = db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		_, e := tx.Exec(r.Context(),
			`UPDATE users SET password_hash = $1, must_change_pw = false WHERE id = $2`,
			newHash, claims.UserID)
		return e
	})
```

- [ ] **Step 3: Wrap `ResetPassword`'s UPDATE and 404 on zero rows**

Reset is an admin action within the caller's tenant. Under RLS the UPDATE keyed on `id` is filtered to the caller's tenant, so a cross-tenant target affects zero rows — surface that as 404 instead of a misleading 200:

```go
	tenantID, isPlatformAdmin := callerTenant(r)
	var affected int64
	err = db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		ct, e := tx.Exec(r.Context(),
			`UPDATE users SET password_hash = $1, must_change_pw = true WHERE id = $2`,
			hash, targetID)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if affected == 0 {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "user.reset_password", targetID, nil, "ok")
	respond(w, map[string]string{"status": "password reset — user must change on next login"})
```

- [ ] **Step 4: Verify build/vet/format on Windows**

Run: `go build ./... ; go vet ./internal/api/... ; gofmt -l internal/api/handlers.go`
Expected: clean; `gofmt -l` prints nothing.

- [ ] **Step 5: Commit + push**

```bash
git add orchestrator/internal/api/handlers.go
git commit -m "feat(multitenancy): tenant-scope CreateUser/ChangePassword/ResetPassword; 404 cross-tenant reset"
git push
```

---

### Task 3: Wrap SSO JIT provisioning in resolved-tenant context

**Files:**
- Modify: `orchestrator/internal/api/sso_login_handlers.go` (SELECT 100-103, INSERT 112-116, UPDATE 135)

**Interfaces:**
- Consumes: `db.WithTenant`, `pgx.Tx`, `state.TenantID` (the tenant resolved from the SSO state).
- Produces: no new symbols. The JIT lookup/insert and last_login update run in the resolved tenant's context.

**Context:** `state.TenantID` is a concrete tenant (SSO is per-tenant), so `isPlatformAdmin=false`. Confirm `pgx` and `db` are imported in this file; if not, add `"github.com/jackc/pgx/v5"` and `"github.com/audspect/bas/internal/db"` (both used elsewhere in the package).

- [ ] **Step 1: Wrap the JIT SELECT + INSERT**

Replace lines 98-122 so the lookup and the provisioning INSERT run in one tenant transaction:

```go
	var userID, role string
	var isActive bool
	selErr := db.WithTenant(r.Context(), h.db, state.TenantID, false, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT id, role, is_active FROM users WHERE username = $1 AND tenant_id = $2`,
			email, state.TenantID,
		).Scan(&userID, &role, &isActive)
	})
	if selErr != nil {
		placeholder, hErr := auth.HashPassword(randomSSOPlaceholder())
		if hErr != nil {
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		role = defaultRole
		isActive = true
		insErr := db.WithTenant(r.Context(), h.db, state.TenantID, false, func(tx pgx.Tx) error {
			return tx.QueryRow(r.Context(),
				`INSERT INTO users (username, password_hash, role, tenant_id, auth_source)
				 VALUES ($1,$2,$3,$4,'sso') RETURNING id`,
				email, placeholder, role, state.TenantID,
			).Scan(&userID)
		})
		if insErr != nil {
			jsonError(w, insErr.Error(), http.StatusInternalServerError)
			return
		}
		h.auditLogAs(r, userID, "user.sso_provisioned", userID, map[string]any{"username": email, "tenantId": state.TenantID, "role": role}, "ok")
	}
```

- [ ] **Step 2: Wrap the last_login UPDATE**

Replace line 135:

```go
	_ = db.WithTenant(r.Context(), h.db, state.TenantID, false, func(tx pgx.Tx) error {
		_, e := tx.Exec(r.Context(), `UPDATE users SET last_login = NOW() WHERE id = $1`, userID)
		return e
	})
```

- [ ] **Step 3: Verify build/vet/format on Windows**

Run: `go build ./... ; go vet ./internal/api/... ; gofmt -l internal/api/sso_login_handlers.go`
Expected: clean; `gofmt -l` prints nothing.

- [ ] **Step 4: Commit + push**

```bash
git add orchestrator/internal/api/sso_login_handlers.go
git commit -m "feat(multitenancy): run SSO JIT provisioning in resolved-tenant context"
git push
```

---

### Task 4: Wrap SCIM user CRUD in token-tenant context

**Files:**
- Modify: `orchestrator/internal/api/scim_handlers.go` (`SCIMCreateUser` ~101, `SCIMListUsers` 144-152, `loadSCIMUserRow` 182-185, `SCIMReplaceUser` 226-228, `SCIMPatchUser` 274, `SCIMDeleteUser` 306)

**Interfaces:**
- Consumes: `db.WithTenant`, `pgx.Tx`, `tenantID` from `scimTenantFrom(r.Context())` (already resolved in each handler).
- Produces: no new symbols. Every SCIM `users` query runs in the token's tenant context (`isPlatformAdmin=false`).

**Note:** The `scim_configs` read in `SCIMCreateUser` (line 91) is NOT a `users` query and has no RLS — leave it on `h.db`. Only the `users` INSERT/SELECT/UPDATE move into `WithTenant`.

- [ ] **Step 1: Wrap `SCIMCreateUser`'s users INSERT**

Replace the `h.db.QueryRow(... INSERT INTO users ... RETURNING ...)` (101-105) with:

```go
	var id, createdAt string
	err = db.WithTenant(r.Context(), h.db, tenantID, false, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`INSERT INTO users (username, password_hash, role, tenant_id, auth_source, is_active)
			 VALUES ($1,$2,$3,$4,'sso',$5) RETURNING id, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`,
			in.UserName, placeholder, defaultRole, tenantID, in.ActiveOrDefault(),
		).Scan(&id, &createdAt)
	})
```

- [ ] **Step 2: Wrap `SCIMListUsers`'s COUNT + SELECT**

Both queries (144-152) must share one tenant transaction. Replace with:

```go
	var total int
	resources := []scim.User{}
	err = db.WithTenant(r.Context(), h.db, tenantID, false, func(tx pgx.Tx) error {
		if e := tx.QueryRow(r.Context(),
			`SELECT COUNT(*) FROM users WHERE tenant_id=$1 AND ($2 = '' OR username = $2)`,
			tenantID, usernameFilter).Scan(&total); e != nil {
			return e
		}
		rows, e := tx.Query(r.Context(),
			`SELECT id, username, is_active, to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			   FROM users WHERE tenant_id=$1 AND ($2 = '' OR username = $2)
			  ORDER BY created_at ASC OFFSET $3 LIMIT $4`,
			tenantID, usernameFilter, startIndex-1, count)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var row scim.UserRow
			if rows.Scan(&row.ID, &row.Username, &row.Active, &row.CreatedAt) != nil {
				continue
			}
			row.UpdatedAt = row.CreatedAt
			resources = append(resources, scim.FromUserRow(row))
		}
		return rows.Err()
	})
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
```

(Remove the now-duplicated `rows`/`resources` code that followed the old queries.)

- [ ] **Step 3: Wrap `loadSCIMUserRow`'s SELECT**

This helper is called by Get/Replace/Patch. Wrap its query (182-185):

```go
	var row scim.UserRow
	err := db.WithTenant(r.Context(), h.db, tenantID, false, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT id, username, is_active, to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			   FROM users WHERE id=$1 AND tenant_id=$2`, id, tenantID,
		).Scan(&row.ID, &row.Username, &row.Active, &row.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	row.UpdatedAt = row.CreatedAt
	return &row, nil
```

- [ ] **Step 4: Wrap the three `UPDATE users` statements (Replace/Patch/Delete)**

Each is a single `h.db.Exec` returning a `pgconn.CommandTag` whose `RowsAffected()` drives the 404. Preserve that. For `SCIMReplaceUser` (226-228):

```go
	var ct pgconn.CommandTag
	err = db.WithTenant(r.Context(), h.db, tenantID, false, func(tx pgx.Tx) error {
		var e error
		ct, e = tx.Exec(r.Context(),
			`UPDATE users SET username=$1, is_active=$2 WHERE id=$3 AND tenant_id=$4`,
			in.UserName, in.ActiveOrDefault(), id, tenantID)
		return e
	})
```

Apply the identical pattern to `SCIMPatchUser` (274, `is_active=$1 WHERE id=$2 AND tenant_id=$3`) and `SCIMDeleteUser` (306, `is_active=false WHERE id=$1 AND tenant_id=$2`), capturing `ct` from the closure. Add `"github.com/jackc/pgx/v5/pgconn"` to the imports if not already present (needed for the `ct` declaration).

- [ ] **Step 5: Verify build/vet/format on Windows**

Run: `go build ./... ; go vet ./internal/api/... ; gofmt -l internal/api/scim_handlers.go`
Expected: clean; `gofmt -l` prints nothing.

- [ ] **Step 6: Commit + push**

```bash
git add orchestrator/internal/api/scim_handlers.go
git commit -m "feat(multitenancy): run SCIM user CRUD in token-tenant context"
git push
```

---

### Task 5: Wrap `ensureAdminUser` startup seed in platform-admin context

**Files:**
- Modify: `orchestrator/cmd/server/main.go` (`ensureAdminUser` 485-525, imports 3-15)

**Interfaces:**
- Consumes: `db.WithTenant`, `pgx.Tx`.
- Produces: no new symbols. The boot-time admin upsert runs in platform-admin context so it works once RLS is forced.

- [ ] **Step 1: Add the `pgx` import**

In the import block (after line 15's `pgxpool`), add:

```go
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
```

(`db` is already imported at line 22.)

- [ ] **Step 2: Wrap the upsert Exec**

Replace the `pool.Exec(context.Background(), ...)` block (503-518) so the WITH/INSERT/UPDATE runs inside `db.WithTenant`:

```go
	err = db.WithTenant(context.Background(), pool, "", true, func(tx pgx.Tx) error {
		_, e := tx.Exec(context.Background(), `
			WITH existing AS (
				SELECT id FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1
			),
			ins AS (
				INSERT INTO users (username, password_hash, role, is_active, must_change_pw)
				SELECT $1, $2, 'admin', true, $3
				WHERE NOT EXISTS (SELECT 1 FROM existing)
			)
			UPDATE users
			   SET username       = $1,
			       password_hash  = $2,
			       is_active      = true,
			       must_change_pw = $3
			 WHERE id IN (SELECT id FROM existing)
		`, adminUsername, hash, mustChange)
		return e
	})
	if err != nil {
		return fmt.Errorf("ensure admin: %w", err)
	}
```

- [ ] **Step 3: Verify build/vet/format on Windows**

Run: `go build ./... ; go vet ./cmd/server/... ; gofmt -l cmd/server/main.go`
Expected: clean; `gofmt -l` prints nothing.

- [ ] **Step 4: Commit + push**

```bash
git add orchestrator/cmd/server/main.go
git commit -m "feat(multitenancy): run ensureAdminUser startup seed in platform-admin context"
git push
```

---

### Task 6: Enable + force RLS on `users` and flip the dormancy test

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (dormant-policy block ~963-980)
- Modify: `orchestrator/internal/api/user_handlers_test.go` (`TestUsersRLSPolicyDormant` 486-508)

**Interfaces:**
- Consumes: the existing `tenant_isolation` policy (created by the pilot's `DO $$ … $$`).
- Produces: `users` now has `relrowsecurity=true` and `relforcerowsecurity=true` after `EnsureSchema`. The renamed test asserts this.

- [ ] **Step 1: Add ENABLE + FORCE after the policy-create block**

The pilot left these as commented lines. Replace the comment block (the `// ALTER TABLE users ENABLE ROW LEVEL SECURITY;` / `FORCE` comments, ~965-968) and add two real statements to the `EnsureSchema` statement slice, immediately after the `DO $$ … CREATE POLICY tenant_isolation … $$` entry:

```go
		// RLS on users is now ENFORCING (Spec 2). Both statements are
		// idempotent. FORCE is required because bas_user owns the table and
		// owners bypass plain ENABLE. Inert on un-hardened installs where
		// bas_user is still a superuser (superusers bypass RLS unconditionally);
		// enforces once BAS_DB_BREAKGLASS_PASSWORD hardening is applied.
		// See docs/superpowers/specs/2026-07-20-multitenancy-users-rls-enable-design.md.
		`ALTER TABLE users ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE users FORCE ROW LEVEL SECURITY`,
```

Leave the policy `USING` predicate untouched.

- [ ] **Step 2: Rewrite the dormancy test to assert enforcement**

Rename `TestUsersRLSPolicyDormant` → `TestUsersRLSPolicyEnforced` and assert both flags true plus the policy still present:

```go
func TestUsersRLSPolicyEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var rlsEnabled, rlsForced bool
		if err := pool.QueryRow(context.Background(),
			`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'users'`,
		).Scan(&rlsEnabled, &rlsForced); err != nil {
			t.Fatalf("read pg_class: %v", err)
		}
		if !rlsEnabled {
			t.Fatal("RLS is not ENABLED on users — Spec 2 requires it enforcing")
		}
		if !rlsForced {
			t.Fatal("RLS is not FORCED on users — table owner would bypass the policy")
		}
		var policyCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM pg_policies WHERE tablename = 'users' AND policyname = 'tenant_isolation'`).Scan(&policyCount); err != nil {
			t.Fatalf("read pg_policies: %v", err)
		}
		if policyCount != 1 {
			t.Fatalf("expected the tenant_isolation policy to exist, found %d", policyCount)
		}
	})
}
```

Also update the doc comment above `TestUsers_TenantIsolation` (391-395) that still describes the policy as "dormant" — change "but RLS stays DISABLED … enabling it is gated" to note RLS is now enforcing (a one-line comment fix; no code change).

- [ ] **Step 3: Verify build/vet/format on Windows**

Run: `go build ./... ; go vet ./... ; gofmt -l internal/db/postgres.go internal/api/user_handlers_test.go`
Expected: clean; `gofmt -l` prints nothing. (The renamed test itself runs on the VM — Docker-gated.)

- [ ] **Step 4: Commit + push**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/api/user_handlers_test.go
git commit -m "feat(multitenancy): enable + force RLS on users; assert enforcement in tests"
git push
```

---

### Task 7: Non-superuser integration harness (the enforcing proof)

**Files:**
- Create: `orchestrator/internal/api/users_rls_integration_test.go`

**Interfaces:**
- Consumes: `sharedDB.RunWithPool` (superuser pool for seeding + role creation), `New(pool, hub, nil, testJWTSecret)` (Handler constructor), `auth.ContextWithClaims`, `auth.Claims`, `withURLParam`, `seedUser` (existing test helpers in the package).
- Produces: `rlsProbePool(t, superPool) *pgxpool.Pool` — a pool connected as a `NOSUPERUSER NOBYPASSRLS` role with DML on all tables, reproducing hardened prod. A missing `WithTenant` on any exercised path makes its query error / return zero rows under this pool, failing the test.

**Why:** The existing suite connects as the Postgres superuser, which bypasses RLS — a missed `WithTenant` would pass there but break hardened prod. This harness is the only test that actually enforces the policy.

- [ ] **Step 1: Write the probe-pool helper**

```go
package api

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// rlsProbePool returns a pool connected as a disposable NOSUPERUSER
// NOBYPASSRLS role with DML on every table — the same conditions as a
// hardened runtime role in production, where RLS on users actually
// enforces. Seeding/inspection still uses the superuser pool passed in.
func rlsProbePool(t *testing.T, super *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`DROP OWNED BY users_rls_probe`,
		`DROP ROLE IF EXISTS users_rls_probe`,
		`CREATE ROLE users_rls_probe LOGIN PASSWORD 'probe' NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO users_rls_probe`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO users_rls_probe`,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO users_rls_probe`,
	}
	for _, s := range stmts {
		// DROP OWNED fails if the role doesn't exist yet — ignore that one.
		_, _ = super.Exec(ctx, s)
	}
	cfg := super.Config().Copy()
	cfg.ConnConfig.User = "users_rls_probe"
	cfg.ConnConfig.Password = "probe"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("probe pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = super.Exec(ctx, `DROP OWNED BY users_rls_probe`)
		_, _ = super.Exec(ctx, `DROP ROLE IF EXISTS users_rls_probe`)
	})
	return pool
}
```

- [ ] **Step 2: Write the enforcing isolation test**

```go
func TestUsersRLS_EnforcedIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(super *pgxpool.Pool) {
		ctx := context.Background()
		// Two tenants must exist for the FK on users.tenant_id.
		_, _ = super.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('tenant-a','A'),('tenant-b','B') ON CONFLICT DO NOTHING`)

		// Seed one user per tenant via the superuser pool (bypasses RLS).
		aUser := seedUser(t, super, "rls-a-user", "password123", "admin", true)
		bUser := seedUser(t, super, "rls-b-user", "password123", "viewer", true)
		_, _ = super.Exec(ctx, `UPDATE users SET tenant_id='tenant-a' WHERE id=$1`, aUser)
		_, _ = super.Exec(ctx, `UPDATE users SET tenant_id='tenant-b' WHERE id=$1`, bUser)

		probe := rlsProbePool(t, super)
		h := New(probe, ws.NewHub(), nil, testJWTSecret)

		tenantA := "tenant-a"
		tenantB := "tenant-b"
		asA := func(method, path string, body io.Reader) *http.Request {
			req := httptest.NewRequest(method, path, body)
			return req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
				UserID: aUser, Role: auth.RoleAdmin, TenantID: &tenantA,
			}))
		}
		asB := func(method, path string, body io.Reader) *http.Request {
			req := httptest.NewRequest(method, path, body)
			return req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
				UserID: bUser, Role: auth.RoleAdmin, TenantID: &tenantB,
			}))
		}

		// 1. Login works under enforcing RLS (platform-admin context path).
		loginRec := httptest.NewRecorder()
		loginBody, _ := json.Marshal(map[string]string{"username": "rls-a-user", "password": "password123"})
		h.Login(loginRec, httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody)))
		if loginRec.Code != http.StatusOK {
			t.Fatalf("login under RLS: status=%d body=%s", loginRec.Code, loginRec.Body.String())
		}

		// 2. Tenant-A admin lists — sees A, never B.
		listRec := httptest.NewRecorder()
		h.ListUsers(listRec, asA(http.MethodGet, "/api/users", nil))
		if listRec.Code != http.StatusOK {
			t.Fatalf("list under RLS: status=%d body=%s", listRec.Code, listRec.Body.String())
		}
		var listed []map[string]any
		_ = json.Unmarshal(listRec.Body.Bytes(), &listed)
		for _, u := range listed {
			if u["username"] == "rls-b-user" {
				t.Fatalf("tenant-A saw tenant-B user under RLS: %v", listed)
			}
		}

		// 3. Cross-tenant reset → 404 (RLS filters the UPDATE to A's tenant).
		resetBody, _ := json.Marshal(map[string]string{"newPassword": "newpassword123"})
		rec := httptest.NewRecorder()
		h.ResetPassword(rec, withURLParam(asA(http.MethodPost, "/api/auth/reset-password/"+bUser, bytes.NewReader(resetBody)), "id", bUser))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant reset under RLS: status=%d, want 404", rec.Code)
		}

		// 4. Cross-tenant delete → 404, row survives.
		delRec := httptest.NewRecorder()
		h.DeleteUser(delRec, withURLParam(asA(http.MethodDelete, "/api/users/"+bUser, nil), "id", bUser))
		if delRec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant delete under RLS: status=%d, want 404", delRec.Code)
		}
		var cnt int
		super.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE id=$1`, bUser).Scan(&cnt)
		if cnt != 1 {
			t.Fatalf("tenant-B user deleted cross-tenant under RLS")
		}

		// 5. Same-tenant create works (predicate doesn't over-block writes).
		createBody, _ := json.Marshal(map[string]string{"username": "rls-a-new", "password": "password123", "role": "viewer"})
		createRec := httptest.NewRecorder()
		h.CreateUser(createRec, asA(http.MethodPost, "/api/users", bytes.NewReader(createBody)))
		if createRec.Code != http.StatusCreated {
			t.Fatalf("same-tenant create under RLS: status=%d body=%s", createRec.Code, createRec.Body.String())
		}

		// 6. Tenant-B admin cannot see the freshly created tenant-A user.
		listBRec := httptest.NewRecorder()
		h.ListUsers(listBRec, asB(http.MethodGet, "/api/users", nil))
		var listedB []map[string]any
		_ = json.Unmarshal(listBRec.Body.Bytes(), &listedB)
		for _, u := range listedB {
			if u["username"] == "rls-a-new" {
				t.Fatalf("tenant-B saw tenant-A's new user under RLS: %v", listedB)
			}
		}
	})
}
```

- [ ] **Step 3: Add a SCIM isolation assertion**

Append a second test that drives one SCIM CRUD path under the probe pool. The SCIM handlers read their tenant from `scimTenantFrom(ctx)`, which reads the unexported context key `ctxSCIMTenantKey{}` (set by `scimAuth` middleware at `scim_auth_middleware.go:33`). Since this test is in package `api`, it sets that key directly to bypass the bearer-token middleware.

Two schema facts to honor: `scim_configs` requires `token_hash` (`NOT NULL`, no default) and has `UNIQUE (tenant_id)`; `SCIMCreateUser` reads `default_role` from it.

```go
func TestUsersRLS_SCIMIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(super *pgxpool.Pool) {
		ctx := context.Background()
		_, _ = super.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('tenant-a','A'),('tenant-b','B') ON CONFLICT DO NOTHING`)
		_, _ = super.Exec(ctx,
			`INSERT INTO scim_configs (tenant_id, token_hash, default_role)
			 VALUES ('tenant-a','hash-a','viewer'),('tenant-b','hash-b','viewer')
			 ON CONFLICT (tenant_id) DO NOTHING`)

		probe := rlsProbePool(t, super)
		h := New(probe, ws.NewHub(), nil, testJWTSecret)

		withSCIMTenant := func(ctx context.Context, tid string) context.Context {
			return context.WithValue(ctx, ctxSCIMTenantKey{}, tid)
		}

		// Create a SCIM user in tenant-a.
		createReq := httptest.NewRequest(http.MethodPost, "/scim/v2/Users",
			strings.NewReader(`{"userName":"scim-a@example.com","active":true}`))
		createReq = createReq.WithContext(withSCIMTenant(createReq.Context(), "tenant-a"))
		createRec := httptest.NewRecorder()
		h.SCIMCreateUser(createRec, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("SCIM create under RLS: status=%d body=%s", createRec.Code, createRec.Body.String())
		}

		// List as tenant-b — must not see the tenant-a user.
		listReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		listReq = listReq.WithContext(withSCIMTenant(listReq.Context(), "tenant-b"))
		listRec := httptest.NewRecorder()
		h.SCIMListUsers(listRec, listReq)
		if strings.Contains(listRec.Body.String(), "scim-a@example.com") {
			t.Fatalf("tenant-b saw tenant-a SCIM user under RLS: %s", listRec.Body.String())
		}
	})
}
```

- [ ] **Step 4: Verify build/vet/format on Windows**

Run: `go build ./... ; go vet ./internal/api/... ; gofmt -l internal/api/users_rls_integration_test.go`
Expected: clean; `gofmt -l` prints nothing. The tests themselves run on the VM.

- [ ] **Step 5: Commit + push**

```bash
git add orchestrator/internal/api/users_rls_integration_test.go
git commit -m "test(multitenancy): non-superuser RLS integration harness for users isolation"
git push
```

---

## VM Verification (after all tasks — Docker required)

Run on the Ubuntu VM where Docker is available:

```bash
cd orchestrator
go test ./internal/api/ -run 'TestUsers' -v          # pilot + enforced + integration harness
go test ./internal/api/ -run 'TestUsersRLS' -v        # the enforcing proof
go test ./internal/db/ -run 'TestHardenRuntimeRole' -v
go test ./... -short                                  # full non-container suite stays green
```

Then a deploy smoke-test with hardening applied:
1. Set `BAS_DB_BREAKGLASS_PASSWORD` in `.env`, `docker compose up -d`.
2. Confirm boot log shows the runtime role demoted and schema verified.
3. Log in, create a user, list users, run a scenario, generate a report — all succeed.
4. If a second tenant exists, confirm it cannot see the first tenant's users.
5. Break-glass recovery check (documented, not destructive to prod): as `bas_breakglass`, `ALTER ROLE bas_user SUPERUSER` restores superuser bypass (RLS inert); revert with `NOSUPERUSER`.

## Notes & Known Deviations

- **SSO end-to-end is not in the harness.** Task 3 migrates the SSO JIT path, but exercising it in a unit test requires a mocked OIDC provider (`oidcauth.NewProvider` + `Exchange`) — disproportionate for this plan. SSO JIT wrapping is verified by build/vet (identical `WithTenant` pattern to the SCIM path, which *is* covered) plus a real SSO login in the VM smoke-test. This is a deliberate narrowing of the spec's "one SSO JIT path" harness item; flag to the user at execution start.
- **Probe role is non-owner.** The harness role is not the `users` table owner, so plain `ENABLE` already enforces against it; `FORCE` (which matters for the owner path in prod) is covered by the VM smoke-test against the real `bas_user` owner.
