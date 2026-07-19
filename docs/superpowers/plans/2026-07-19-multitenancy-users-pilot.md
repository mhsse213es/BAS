# Multi-Tenancy `users`-Table Pilot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `users` table's list/update/delete handlers tenant-aware end-to-end (app-layer `WHERE tenant_id` filtering + `db.WithTenant` wrapping) and add a dormant, not-yet-enabled RLS policy on `users`, as the first Phase-7 Multi-Tenancy rollout wave.

**Architecture:** `ListUsers`/`UpdateUser`/`DeleteUser` in `internal/api/handlers.go` derive a tenant scope from JWT claims via a shared `callerTenant` helper (platform-admin → cross-tenant; otherwise scoped to `claims.TenantID`, defaulting to `'default'`), run their DB work inside `db.WithTenant`, and filter/scope by `tenant_id`. Cross-tenant update/delete returns `404`. A `tenant_isolation` RLS policy is created on `users` but RLS stays disabled (activation gated on DB-role hardening). Spec: `docs/superpowers/specs/2026-07-19-multitenancy-users-pilot-design.md`.

**Tech Stack:** Go (`internal/api`, `internal/db`), Postgres.

## Global Constraints
- **Docker-gated tests.** The new DB-backed tests use `sharedDB.RunWithPool` (real Postgres via testcontainers) and **cannot run on the Windows build host** (rootless Docker unsupported). On Windows, verify each task with `go build ./...`, `go vet ./...`, and `gofmt -l` only; the container-backed tests must be run on a Docker-capable Linux host (the VM). This is the same known gap SP4/SP6/the connectors hit — state the real result, never claim a Docker test passed on Windows.
- `internal/db` is already imported in `handlers.go` (line 25); this plan additionally imports `github.com/jackc/pgx/v5` (for `pgx.Tx`). No import cycle (`internal/db` does not import `internal/api`).
- Every task ends with `gofmt -l <touched files>` empty and `go build ./...` + `go vet ./internal/api/... ./internal/db/...` clean before moving on.
- Run all `cd`-relative commands from `orchestrator/`.
- Do NOT enable RLS, harden the DB role, or touch Login/SSO/SCIM/bootstrap/`CreateUser`.

---

### Task 1: Dormant RLS policy on `users` (migration)

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (add one statement to the schema slice, after the tenant_id migration block ending ~line 954)
- Test: `orchestrator/internal/api/user_handlers_test.go` (append)

**Interfaces:**
- Produces: a `tenant_isolation` policy row on `users` in `pg_policies`, with RLS left disabled (`pg_class.relrowsecurity = false`) — asserted by Task 1's test and by the guardrail in the definition of done.

- [ ] **Step 1: Write the guardrail test**

Append to `orchestrator/internal/api/user_handlers_test.go`:
```go
// TestUsersRLSPolicyDormant pins the pilot's central safety property: the
// tenant_isolation policy exists on users (reviewable, syntax-checked at boot),
// but RLS stays DISABLED — enabling it is gated on the bas_user role hardening
// (see the migration comment in postgres.go). A future accidental ENABLE would
// fail this test.
func TestUsersRLSPolicyDormant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var rlsEnabled bool
		if err := pool.QueryRow(context.Background(),
			`SELECT relrowsecurity FROM pg_class WHERE relname = 'users'`).Scan(&rlsEnabled); err != nil {
			t.Fatalf("read pg_class.relrowsecurity: %v", err)
		}
		if rlsEnabled {
			t.Fatal("RLS is ENABLED on users — this pilot must leave it dormant until DB-role hardening")
		}
		var policyCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM pg_policies WHERE tablename = 'users' AND policyname = 'tenant_isolation'`).Scan(&policyCount); err != nil {
			t.Fatalf("read pg_policies: %v", err)
		}
		if policyCount != 1 {
			t.Fatalf("expected the dormant tenant_isolation policy to exist, found %d", policyCount)
		}
	})
}
```

- [ ] **Step 2: Run the test to verify it fails (Docker host only)**

Run (on a Docker-capable host): `cd orchestrator && go test ./internal/api/... -run TestUsersRLSPolicyDormant -v`
Expected: FAIL — `policyCount` is 0 (policy not created yet). On Windows, instead confirm it compiles: `cd orchestrator && go vet ./internal/api/...`.

- [ ] **Step 3: Add the dormant policy statement**

In `orchestrator/internal/db/postgres.go`, find the last tenant_id migration line (~954):
```go
		`ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
```
Insert immediately after it:
```go

		// SP7 Multi-Tenancy — users-table pilot. Create a tenant-isolation RLS
		// policy on users so it is reviewable and syntax-checked at boot, but
		// deliberately DO NOT enable RLS: the production role (bas_user) is a
		// Postgres superuser and bypasses RLS regardless, and Login/ChangePassword/
		// bootstrap query users with no tenant context and would be blocked the
		// moment RLS enforces. Activation is gated on the bas_user ->
		// NOSUPERUSER/NOBYPASSRLS role-hardening follow-up, at which point a future
		// migration uncomments the ENABLE/FORCE lines below AND routes the
		// tenant-agnostic auth paths through a platform-admin WithTenant context.
		// Enable-when-ready (do NOT uncomment without that follow-up):
		//   ALTER TABLE users ENABLE ROW LEVEL SECURITY;
		//   ALTER TABLE users FORCE ROW LEVEL SECURITY;
		// See docs/superpowers/specs/2026-07-19-multitenancy-users-pilot-design.md.
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_policies WHERE tablename = 'users' AND policyname = 'tenant_isolation'
			) THEN
				CREATE POLICY tenant_isolation ON users
					USING (
						tenant_id = current_setting('app.tenant_id', true)
						OR current_setting('app.is_platform_admin', true)::boolean
					);
			END IF;
		END
		$$;`,
```

- [ ] **Step 4: Verify the test passes (Docker host only) + build**

Run (Docker host): `cd orchestrator && go test ./internal/api/... -run TestUsersRLSPolicyDormant -v` → PASS.
Run (always, incl. Windows): `cd orchestrator && gofmt -l internal/db/postgres.go internal/api/user_handlers_test.go && go build ./internal/db/... && go vet ./internal/db/...`
Expected: no gofmt output; build/vet clean.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/api/user_handlers_test.go
git commit -m "feat(multitenancy): dormant tenant_isolation RLS policy on users"
```

---

### Task 2: `callerTenant` helper + tenant-scope `ListUsers`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (add `callerTenant` above `ListUsers`; rewrite `ListUsers`; add `pgx` import)

**Interfaces:**
- Produces: `callerTenant(r *http.Request) (tenantID string, isPlatformAdmin bool)`, consumed by `ListUsers` (this task), `UpdateUser` (Task 3), `DeleteUser` (Task 4).

- [ ] **Step 1: Add the `pgx` import**

In `orchestrator/internal/api/handlers.go`, find:
```go
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
```
Replace with:
```go
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
```

- [ ] **Step 2: Add the `callerTenant` helper and rewrite `ListUsers`**

In `orchestrator/internal/api/handlers.go`, find the whole current `ListUsers`:
```go
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, username, role, is_active, must_change_pw, created_at, last_login
		 FROM users ORDER BY created_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type UserRow struct {
		ID           string     `json:"id"`
		Username     string     `json:"username"`
		Role         string     `json:"role"`
		IsActive     bool       `json:"isActive"`
		MustChangePw bool       `json:"mustChangePw"`
		CreatedAt    time.Time  `json:"createdAt"`
		LastLogin    *time.Time `json:"lastLogin"`
	}
	var users []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.IsActive, &u.MustChangePw, &u.CreatedAt, &u.LastLogin); err != nil {
			continue
		}
		users = append(users, u)
	}
	if users == nil {
		users = []UserRow{}
	}
	respond(w, users)
}
```
Replace with:
```go
// callerTenant derives the tenant scope for a request from its JWT claims.
// Platform admins get cross-tenant access (isPlatformAdmin=true); everyone
// else — including tenant-less legacy tokens and direct-call unit tests with
// no claims — is scoped to their tenant, defaulting to the canonical 'default'
// tenant that the whole schema uses as its single-tenant baseline. In
// production these handlers sit behind auth middleware, so claims are always
// present; the no-claims path exists only for direct-call tests.
func callerTenant(r *http.Request) (tenantID string, isPlatformAdmin bool) {
	tenantID = "default"
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		return tenantID, false
	}
	if claims.TenantID != nil {
		tenantID = *claims.TenantID
	}
	return tenantID, claims.IsPlatformAdmin
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, isPlatformAdmin := callerTenant(r)

	type UserRow struct {
		ID           string     `json:"id"`
		Username     string     `json:"username"`
		Role         string     `json:"role"`
		IsActive     bool       `json:"isActive"`
		MustChangePw bool       `json:"mustChangePw"`
		CreatedAt    time.Time  `json:"createdAt"`
		LastLogin    *time.Time `json:"lastLogin"`
	}
	var users []UserRow
	err := db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		q := `SELECT id, username, role, is_active, must_change_pw, created_at, last_login FROM users`
		args := []any{}
		if !isPlatformAdmin {
			q += ` WHERE tenant_id = $1`
			args = append(args, tenantID)
		}
		q += ` ORDER BY created_at ASC`
		rows, qerr := tx.Query(r.Context(), q, args...)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var u UserRow
			if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.IsActive, &u.MustChangePw, &u.CreatedAt, &u.LastLogin); err != nil {
				continue
			}
			users = append(users, u)
		}
		return rows.Err()
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []UserRow{}
	}
	respond(w, users)
}
```

- [ ] **Step 3: Build, vet, format**

Run: `cd orchestrator && gofmt -l internal/api/handlers.go && go build ./... && go vet ./internal/api/...`
Expected: no gofmt output; build/vet clean. (`TestListUsers_EmptyAndSeeded` calls `ListUsers` with no claims → `callerTenant` returns `("default", false)` → scoped to the `'default'` tenant where `seedUser` inserts, so that existing test still holds — verified on the Docker host in Task 5.)

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/handlers.go
git commit -m "feat(multitenancy): tenant-scope ListUsers via callerTenant + WithTenant"
```

---

### Task 3: Tenant-scope `UpdateUser` (cross-tenant → 404)

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`UpdateUser`)

**Interfaces:**
- Consumes: `callerTenant` (Task 2), `db.WithTenant`, `pgx.Tx`.
- Produces: `UpdateUser` returns `404` for a target outside the caller's tenant (or nonexistent), no mutation.

- [ ] **Step 1: Rewrite `UpdateUser`**

In `orchestrator/internal/api/handlers.go`, find the whole current `UpdateUser` (from `func (h *Handler) UpdateUser` through its closing brace, including the two `h.db.Exec(... UPDATE users ...)` calls and the trailing audit/respond). Replace its body **from the two DB `Exec` calls onward** — keep the decode, validation, and self-modification guards exactly as they are. Concretely, find:
```go
	if req.Role != nil {
		h.db.Exec(r.Context(), `UPDATE users SET role = $1 WHERE id = $2`, *req.Role, targetID)
	}
	if req.IsActive != nil {
		h.db.Exec(r.Context(), `UPDATE users SET is_active = $1 WHERE id = $2`, *req.IsActive, targetID)
	}
	h.auditLog(r, "user.update", targetID, nil, "ok")
	w.WriteHeader(http.StatusOK)
	respond(w, map[string]string{"status": "updated"})
}
```
Replace with:
```go
	tenantID, isPlatformAdmin := callerTenant(r)
	notFound := false
	err := db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		// Existence + tenant-scope check up front: a target in another tenant
		// (or nonexistent) is indistinguishable from not-found, so a
		// cross-tenant write returns 404 without leaking which ids exist
		// elsewhere. Once the row is confirmed in-tenant, the UPDATEs key on
		// the primary-key id alone.
		var exists bool
		var checkErr error
		if isPlatformAdmin {
			checkErr = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, targetID).Scan(&exists)
		} else {
			checkErr = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)`, targetID, tenantID).Scan(&exists)
		}
		if checkErr != nil {
			return checkErr
		}
		if !exists {
			notFound = true
			return nil
		}
		if req.Role != nil {
			if _, err := tx.Exec(r.Context(), `UPDATE users SET role = $1 WHERE id = $2`, *req.Role, targetID); err != nil {
				return err
			}
		}
		if req.IsActive != nil {
			if _, err := tx.Exec(r.Context(), `UPDATE users SET is_active = $1 WHERE id = $2`, *req.IsActive, targetID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if notFound {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "user.update", targetID, nil, "ok")
	w.WriteHeader(http.StatusOK)
	respond(w, map[string]string{"status": "updated"})
}
```

- [ ] **Step 2: Build, vet, format**

Run: `cd orchestrator && gofmt -l internal/api/handlers.go && go build ./... && go vet ./internal/api/...`
Expected: no gofmt output; build/vet clean.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/handlers.go
git commit -m "feat(multitenancy): tenant-scope UpdateUser, cross-tenant returns 404"
```

---

### Task 4: Tenant-scope `DeleteUser` (cross-tenant/nonexistent → 404) + update characterization test

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`DeleteUser`)
- Modify: `orchestrator/internal/api/user_handlers_test.go` (`TestDeleteUser_SelfBlockedNonexistentIsNoop`)

**Interfaces:**
- Consumes: `callerTenant`, `db.WithTenant`, `pgx.Tx`.
- Produces: `DeleteUser` returns `404` when nothing was deleted (target outside tenant or nonexistent).

- [ ] **Step 1: Rewrite `DeleteUser`**

In `orchestrator/internal/api/handlers.go`, find the whole current `DeleteUser`:
```go
// DELETE /api/users/{id}  — hard delete (admin only, cannot delete self)
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	claims, _ := auth.ClaimsFrom(r.Context())
	if claims != nil && claims.UserID == targetID {
		jsonError(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}
	if _, err := h.db.Exec(r.Context(), `DELETE FROM users WHERE id = $1`, targetID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "user.delete", targetID, nil, "ok")
	w.WriteHeader(http.StatusNoContent)
}
```
Replace with:
```go
// DELETE /api/users/{id}  — hard delete (admin only, cannot delete self)
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	claims, _ := auth.ClaimsFrom(r.Context())
	if claims != nil && claims.UserID == targetID {
		jsonError(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}
	tenantID, isPlatformAdmin := callerTenant(r)
	var deleted int64
	err := db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		q := `DELETE FROM users WHERE id = $1`
		args := []any{targetID}
		if !isPlatformAdmin {
			q += ` AND tenant_id = $2`
			args = append(args, tenantID)
		}
		ct, derr := tx.Exec(r.Context(), q, args...)
		if derr != nil {
			return derr
		}
		deleted = ct.RowsAffected()
		return nil
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if deleted == 0 {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "user.delete", targetID, nil, "ok")
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 2: Update the characterization test (204 → 404)**

In `orchestrator/internal/api/user_handlers_test.go`, find in `TestDeleteUser_SelfBlockedNonexistentIsNoop`:
```go
		// Characterization: deleting a nonexistent id still returns 204 — the
		// handler doesn't check rows-affected.
		req2 := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/does-not-exist", nil, auth.RoleAdmin, adminID), "id", "does-not-exist")
		if rec2 := callAuthed(h.DeleteUser, req2); rec2.Code != http.StatusNoContent {
			t.Fatalf("nonexistent id delete: status = %d, want 204 (current idempotent-ish behavior)", rec2.Code)
		}
```
Replace with:
```go
		// SP7 pilot: DeleteUser now checks rows-affected, so a nonexistent id
		// (like a cross-tenant one) returns 404 instead of the old 204.
		req2 := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/does-not-exist", nil, auth.RoleAdmin, adminID), "id", "does-not-exist")
		if rec2 := callAuthed(h.DeleteUser, req2); rec2.Code != http.StatusNotFound {
			t.Fatalf("nonexistent id delete: status = %d, want 404", rec2.Code)
		}
```

- [ ] **Step 3: Build, vet, format**

Run: `cd orchestrator && gofmt -l internal/api/handlers.go internal/api/user_handlers_test.go && go build ./... && go vet ./internal/api/...`
Expected: no gofmt output; build/vet clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/user_handlers_test.go
git commit -m "feat(multitenancy): tenant-scope DeleteUser, cross-tenant/nonexistent returns 404"
```

---

### Task 5: End-to-end isolation test + full validation + capture

**Files:**
- Modify: `orchestrator/internal/api/user_handlers_test.go` (append `TestUsers_TenantIsolation`)
- Modify (memory): `project_platform_roadmap_2026h2.md`
- Modify (vault, outside repo): daily note + Multi-Tenancy feature note

**Interfaces:**
- Consumes: the tenant-scoped `ListUsers`/`UpdateUser`/`DeleteUser` (Tasks 2-4).

- [ ] **Step 1: Write the end-to-end isolation test**

Append to `orchestrator/internal/api/user_handlers_test.go`:
```go
// TestUsers_TenantIsolation exercises the whole pilot: a tenant-scoped admin
// cannot see, modify, or delete a user in another tenant, while a platform
// admin sees across tenants. Claims are injected directly (not via a bearer
// token) so the handlers are called without the auth middleware — withURLParam
// preserves the injected context.
func TestUsers_TenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)

		aAdmin := seedUser(t, pool, "iso-a-admin", "password123", "admin", true)
		aUser := seedUser(t, pool, "iso-a-user", "password123", "viewer", true)
		bUser := seedUser(t, pool, "iso-b-user", "password123", "viewer", true)
		if _, err := pool.Exec(context.Background(), `UPDATE users SET tenant_id = 'tenant-b' WHERE id = $1`, bUser); err != nil {
			t.Fatalf("move user to tenant-b: %v", err)
		}

		defaultTenant := "default"
		asDefaultAdmin := func(method, path string, body io.Reader) *http.Request {
			req := httptest.NewRequest(method, path, body)
			return req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
				UserID: aAdmin, Role: auth.RoleAdmin, TenantID: &defaultTenant,
			}))
		}
		callID := func(fn http.HandlerFunc, req *http.Request, id string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			fn(rec, withURLParam(req, "id", id))
			return rec
		}

		// 1. Default-tenant admin lists — sees default users, NOT tenant-b's.
		listRec := httptest.NewRecorder()
		h.ListUsers(listRec, asDefaultAdmin(http.MethodGet, "/api/users", nil))
		var listed []map[string]any
		_ = json.Unmarshal(listRec.Body.Bytes(), &listed)
		for _, u := range listed {
			if u["username"] == "iso-b-user" {
				t.Fatalf("default-tenant admin must not see tenant-b user: %v", listed)
			}
		}

		// 2. Cross-tenant update → 404, no mutation.
		body, _ := json.Marshal(map[string]any{"role": "admin"})
		if rec := callID(h.UpdateUser, asDefaultAdmin(http.MethodPut, "/api/users/"+bUser, bytes.NewReader(body)), bUser); rec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant update: status = %d, want 404", rec.Code)
		}
		var bRole string
		pool.QueryRow(context.Background(), `SELECT role FROM users WHERE id = $1`, bUser).Scan(&bRole)
		if bRole != "viewer" {
			t.Fatalf("tenant-b user role mutated cross-tenant: %q", bRole)
		}

		// 3. Cross-tenant delete → 404, row survives.
		if rec := callID(h.DeleteUser, asDefaultAdmin(http.MethodDelete, "/api/users/"+bUser, nil), bUser); rec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant delete: status = %d, want 404", rec.Code)
		}
		var bCount int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM users WHERE id = $1`, bUser).Scan(&bCount)
		if bCount != 1 {
			t.Fatalf("tenant-b user deleted cross-tenant, rows = %d", bCount)
		}

		// 4. Platform admin sees across tenants.
		paReq := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		paReq = paReq.WithContext(auth.ContextWithClaims(paReq.Context(), &auth.Claims{
			UserID: "platform-admin", Role: auth.RoleAdmin, IsPlatformAdmin: true,
		}))
		paRec := httptest.NewRecorder()
		h.ListUsers(paRec, paReq)
		var all []map[string]any
		_ = json.Unmarshal(paRec.Body.Bytes(), &all)
		var sawB bool
		for _, u := range all {
			if u["username"] == "iso-b-user" {
				sawB = true
			}
		}
		if !sawB {
			t.Fatalf("platform admin should see tenant-b user: %v", all)
		}

		// 5. Same-tenant delete still works (predicate doesn't over-block).
		if rec := callID(h.DeleteUser, asDefaultAdmin(http.MethodDelete, "/api/users/"+aUser, nil), aUser); rec.Code != http.StatusNoContent {
			t.Fatalf("same-tenant delete: status = %d, want 204", rec.Code)
		}
	})
}
```

- [ ] **Step 2: Build, vet, format (Windows OK)**

Run: `cd orchestrator && gofmt -l internal/api/user_handlers_test.go && go build ./... && go vet ./internal/api/...`
Expected: no gofmt output; build/vet clean.

- [ ] **Step 3: Full container-backed run (Docker host only)**

Run on the VM: `cd orchestrator && go test ./internal/api/... -run 'TestUsers_TenantIsolation|TestUsersRLSPolicyDormant|TestListUsers|TestUpdateUser|TestDeleteUser' -v`
Expected: PASS, all listed tests (new isolation + guardrail + every pre-existing user test, including the updated 204→404 characterization). If Docker is unavailable where this task runs, record that explicitly and defer the run to the VM — do not claim it passed.

- [ ] **Step 4: Update roadmap memory**

In `project_platform_roadmap_2026h2.md`, in the "Sub-project 1: Multi-Tenancy" section, mark the `users`-table pilot done: note the commits from Tasks 1-5, that isolation is now enforced app-layer on `ListUsers`/`UpdateUser`/`DeleteUser`, that the RLS policy is created-but-dormant, and that DB-role hardening + the remaining ~23 handlers + 5 aggregator packages are the next waves. Update the "Resume by" line to point at the next wave.

- [ ] **Step 5: Vault capture**

Draft (for user review) a daily-note entry and a Multi-Tenancy feature-note update recording the pilot: the three prongs, the dormant-policy decision, the Login-landmine finding that drove deferring RLS enablement, and the Docker-gated test status.

- [ ] **Step 6: Push**

```bash
git push
```

- [ ] **Step 7: Manual verification recommended (VM)**

On the VM after `git pull` + rebuild: run the container-backed tests (Step 3) to green them, then spot-check the Users admin panel still lists/updates/deletes within a tenant. Flag as a known gap in the daily note if not performed.

## Self-Review

- **Spec coverage:** Prong 1 (app-layer filter) → Tasks 2-4; Prong 2 (`WithTenant`) → Tasks 2-4; Prong 3 (dormant policy) → Task 1; all 7 spec test cases → Task 1 (guardrail) + Task 5 (isolation, platform-admin, same-tenant regression) + the preserved existing self-guard tests; the 204→404 characterization change → Task 4 Step 2.
- **Placeholders:** none — every code step shows complete before/after.
- **Type consistency:** `callerTenant(r) (string, bool)` defined in Task 2, used identically in Tasks 3-4; `db.WithTenant(ctx, *pgxpool.Pool, string, bool, func(pgx.Tx) error) error` matches `internal/db/tenant.go:21`; `pgx.Tx.Exec` returns a command tag with `RowsAffected() int64` (Task 4).
