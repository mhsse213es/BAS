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
