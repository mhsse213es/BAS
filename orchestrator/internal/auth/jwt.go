package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Role defines the three access levels in the platform.
type Role string

const (
	RoleAdmin   Role = "admin"   // full access: users, config, run scenarios
	RoleAnalyst Role = "analyst" // run scenarios, view all reports
	RoleViewer  Role = "viewer"  // read-only: view reports and agents
)

// Claims is the JWT payload. TenantID is nil for a platform-admin (who
// belongs to no single tenant) and non-nil for a regular tenant user.
// IsPlatformAdmin is an orthogonal flag — which tenant, or none — distinct
// from Role, which answers what permission level within that scope.
type Claims struct {
	UserID          string  `json:"user_id"`
	Role            Role    `json:"role"`
	TenantID        *string `json:"tenant_id,omitempty"`
	IsPlatformAdmin bool    `json:"is_platform_admin,omitempty"`
	jwt.RegisteredClaims
}

// GenerateTenantToken creates a signed JWT carrying tenant context.
// tenantID must be nil when isPlatformAdmin is true, and non-nil otherwise.
func GenerateTenantToken(userID string, role Role, tenantID *string, isPlatformAdmin bool, secret string, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID:          userID,
		Role:            role,
		TenantID:        tenantID,
		IsPlatformAdmin: isPlatformAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// GenerateToken creates a signed JWT for the given user and role, with no
// tenant context. Equivalent to GenerateTenantToken with tenantID=nil,
// isPlatformAdmin=false — kept as a separate, stable-signature function so
// the many pre-tenancy call sites across the codebase never need to change.
func GenerateToken(userID string, role Role, secret string, ttl time.Duration) (string, error) {
	return GenerateTenantToken(userID, role, nil, false, secret, ttl)
}

// ValidateToken parses and validates a JWT, returning its claims.
func ValidateToken(tokenStr, secret string) (*Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
