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

func TestSetup_MalformedBody(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	h.Setup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
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
