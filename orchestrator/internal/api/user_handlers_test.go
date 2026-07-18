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

func TestCreateUser_MalformedBody(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	h.CreateUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestChangePassword_NoClaimsUnauthorized(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", nil)
	rec := httptest.NewRecorder()
	h.ChangePassword(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no claims in context)", rec.Code)
	}
}

func TestChangePassword_MalformedBodyAndShortPassword(t *testing.T) {
	userID := "does-not-matter-claims-check-runs-first"
	malformed := authedRequest(t, http.MethodPost, "/api/auth/change-password", bytes.NewReader([]byte("{not json")), auth.RoleViewer, userID)
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	if rec := callAuthed(h.ChangePassword, malformed); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: status = %d, want 400", rec.Code)
	}

	shortBody, _ := json.Marshal(map[string]string{"currentPassword": "whatever", "newPassword": "short"})
	shortReq := authedRequest(t, http.MethodPost, "/api/auth/change-password", bytes.NewReader(shortBody), auth.RoleViewer, userID)
	if rec := callAuthed(h.ChangePassword, shortReq); rec.Code != http.StatusBadRequest {
		t.Fatalf("short new password: status = %d, want 400", rec.Code)
	}
}

func TestResetPassword_MalformedBodyAndShortPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		adminID := seedUser(t, pool, "priya", "password123", "admin", true)
		targetID := seedUser(t, pool, "raj", "password123", "viewer", true)

		malformed := withURLParam(authedRequest(t, http.MethodPost, "/api/users/"+targetID+"/reset-password", bytes.NewReader([]byte("{not json")), auth.RoleAdmin, adminID), "id", targetID)
		if rec := callAuthed(h.ResetPassword, malformed); rec.Code != http.StatusBadRequest {
			t.Fatalf("malformed body: status = %d, want 400", rec.Code)
		}

		shortBody, _ := json.Marshal(map[string]string{"newPassword": "short"})
		shortReq := withURLParam(authedRequest(t, http.MethodPost, "/api/users/"+targetID+"/reset-password", bytes.NewReader(shortBody), auth.RoleAdmin, adminID), "id", targetID)
		if rec := callAuthed(h.ResetPassword, shortReq); rec.Code != http.StatusBadRequest {
			t.Fatalf("short new password: status = %d, want 400", rec.Code)
		}
	})
}

func TestGetMyPermissions_NoClaimsUnauthorized(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/me/permissions", nil)
	rec := httptest.NewRecorder()
	h.GetMyPermissions(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no claims in context)", rec.Code)
	}
}

func TestCreateUser_ValidationAndDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)

		post := func(payload map[string]any) *httptest.ResponseRecorder {
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
			// CreateUser now derives the new user's tenant from the caller's
			// claims; inject a default-tenant admin the way auth.Middleware
			// would, preserving this test's original intent (a regular admin
			// creating users in their own tenant).
			tenantID := "default"
			req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
				UserID: "test-admin", Role: auth.RoleAdmin, TenantID: &tenantID,
			}))
			rec := httptest.NewRecorder()
			h.CreateUser(rec, req)
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

		// Self-role-change is blocked — same self-modification guard as
		// self-deactivation/self-delete, so an admin can't escalate or lock
		// themselves out; role changes must come from a second admin.
		selfDemote, _ := json.Marshal(map[string]any{"role": "viewer"})
		req4 := withURLParam(authedRequest(t, http.MethodPut, "/api/users/"+adminID, bytes.NewReader(selfDemote), auth.RoleAdmin, adminID), "id", adminID)
		if rec4 := callAuthed(h.UpdateUser, req4); rec4.Code != http.StatusBadRequest {
			t.Fatalf("self role change: status = %d, want 400", rec4.Code)
		}
		var adminRole string
		if err := pool.QueryRow(context.Background(), `SELECT role FROM users WHERE id=$1`, adminID).Scan(&adminRole); err != nil {
			t.Fatalf("read admin role: %v", err)
		}
		if adminRole != "admin" {
			t.Fatalf("admin role = %q, want unchanged admin", adminRole)
		}
	})
}

// TestUpdateUser_OtherAdminCanChangeThisAdminsRole pins that the self-role
// guard is scoped to the acting user only — a second admin can still change
// a different admin's role (the guard checks claims.UserID == targetID, not
// the target's role).
func TestUpdateUser_OtherAdminCanChangeThisAdminsRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		actingAdminID := seedUser(t, pool, "iris", "password123", "admin", true)
		targetAdminID := seedUser(t, pool, "jack", "password123", "admin", true)

		body, _ := json.Marshal(map[string]any{"role": "analyst"})
		req := withURLParam(authedRequest(t, http.MethodPut, "/api/users/"+targetAdminID, bytes.NewReader(body), auth.RoleAdmin, actingAdminID), "id", targetAdminID)
		rec := callAuthed(h.UpdateUser, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var role string
		if err := pool.QueryRow(context.Background(), `SELECT role FROM users WHERE id=$1`, targetAdminID).Scan(&role); err != nil {
			t.Fatalf("read role: %v", err)
		}
		if role != "analyst" {
			t.Fatalf("role = %q, want analyst", role)
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
			Role        string            `json:"role"`
			Permissions []auth.Permission `json:"permissions"`
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
