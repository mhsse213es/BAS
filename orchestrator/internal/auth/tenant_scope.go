package auth

import (
	"errors"
	"fmt"
)

type ScopeKind int

const (
	ScopeTenant ScopeKind = iota + 1
	ScopePlatform
)

// Scope is the caller's authorized row visibility, derived only from
// authenticated claims. The zero value is not a valid scope.
type Scope struct {
	kind     ScopeKind
	tenantID string
}

var (
	ErrNoClaims    = errors.New("tenant scope: no authenticated claims")
	ErrNoTenant    = errors.New("tenant scope: caller has no tenant and is not a platform administrator")
	ErrEmptyTenant = errors.New("tenant scope: tenant ID is empty")
)

// ScopeFromClaims resolves the caller's scope. IsPlatformAdmin is the sole
// platform authority; a nil TenantID alone never grants platform access.
func ScopeFromClaims(c *Claims) (Scope, error) {
	if c == nil {
		return Scope{}, ErrNoClaims
	}
	if c.IsPlatformAdmin {
		return Scope{kind: ScopePlatform}, nil
	}
	if c.TenantID == nil {
		return Scope{}, ErrNoTenant
	}
	if *c.TenantID == "" {
		return Scope{}, ErrEmptyTenant
	}
	return Scope{kind: ScopeTenant, tenantID: *c.TenantID}, nil
}

func (s Scope) Kind() ScopeKind { return s.kind }

func (s Scope) TenantID() string { return s.tenantID }

// AllowsRow reports whether a row owned by rowTenant is visible. A nil
// rowTenant means unowned: visible only to the platform scope.
func (s Scope) AllowsRow(rowTenant *string) bool {
	if s.kind == ScopePlatform {
		return true
	}
	return rowTenant != nil && *rowTenant == s.tenantID
}

// Predicate returns the SQL restriction and its args for a tenant_id column
// reference, numbering placeholders from argIdx. Never emits an IS NULL arm.
func (s Scope) Predicate(column string, argIdx int) (string, []any) {
	if s.kind == ScopePlatform {
		return "TRUE", nil
	}
	return fmt.Sprintf("%s = $%d", column, argIdx), []any{s.tenantID}
}
