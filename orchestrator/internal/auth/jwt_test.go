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
