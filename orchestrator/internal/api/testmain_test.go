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
