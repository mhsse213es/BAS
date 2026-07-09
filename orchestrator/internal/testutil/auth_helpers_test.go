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
