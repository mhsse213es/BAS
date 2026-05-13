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

// Claims is the JWT payload.
type Claims struct {
	UserID string `json:"user_id"`
	Role   Role   `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken creates a signed JWT for the given user and role.
func GenerateToken(userID string, role Role, secret string, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
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
