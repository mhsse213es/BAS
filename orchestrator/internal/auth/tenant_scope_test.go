package auth

import "testing"

func strPtr(s string) *string { return &s }

func TestScopeFromClaims_TenantUser_ScopedToOwnTenant(t *testing.T) {
	s, err := ScopeFromClaims(&Claims{UserID: "u1", TenantID: strPtr("tenant-a")})
	if err != nil {
		t.Fatalf("ScopeFromClaims: %v", err)
	}
	if s.Kind() != ScopeTenant || s.TenantID() != "tenant-a" {
		t.Fatalf("got kind=%v tenant=%q, want tenant-scoped to tenant-a", s.Kind(), s.TenantID())
	}
}

func TestScopeFromClaims_PlatformAdmin_AllRows(t *testing.T) {
	s, err := ScopeFromClaims(&Claims{UserID: "admin", IsPlatformAdmin: true})
	if err != nil {
		t.Fatalf("ScopeFromClaims: %v", err)
	}
	if s.Kind() != ScopePlatform {
		t.Fatalf("got kind=%v, want platform", s.Kind())
	}
}

// A nil TenantID alone must not confer platform access: the explicit
// IsPlatformAdmin flag is the authority, per the design spec §2.
func TestScopeFromClaims_NilTenantWithoutAdminFlag_Denied(t *testing.T) {
	if _, err := ScopeFromClaims(&Claims{UserID: "orphan"}); err == nil {
		t.Fatal("want an error for a nil tenant without the platform-admin flag")
	}
}

func TestScopeFromClaims_MissingClaims_Denied(t *testing.T) {
	if _, err := ScopeFromClaims(nil); err == nil {
		t.Fatal("want an error for nil claims")
	}
}

func TestScopeFromClaims_EmptyTenantID_Denied(t *testing.T) {
	if _, err := ScopeFromClaims(&Claims{UserID: "u", TenantID: strPtr("")}); err == nil {
		t.Fatal("want an error for an empty tenant ID, never an unrestricted scope")
	}
}

// NULL ownership is platform-admin-only: a tenant scope must never
// match an unowned row, and the platform scope must.
func TestScope_AllowsRow_NullOwnershipOnlyForPlatform(t *testing.T) {
	tenant, _ := ScopeFromClaims(&Claims{TenantID: strPtr("tenant-a")})
	platform, _ := ScopeFromClaims(&Claims{IsPlatformAdmin: true})

	if tenant.AllowsRow(nil) {
		t.Fatal("tenant scope must not see NULL-owned rows")
	}
	if !platform.AllowsRow(nil) {
		t.Fatal("platform scope must see NULL-owned rows")
	}
}

func TestScope_AllowsRow_OwnTenantOnly(t *testing.T) {
	tenant, _ := ScopeFromClaims(&Claims{TenantID: strPtr("tenant-a")})
	if !tenant.AllowsRow(strPtr("tenant-a")) {
		t.Fatal("tenant-a must see its own rows")
	}
	if tenant.AllowsRow(strPtr("tenant-b")) {
		t.Fatal("tenant-a must not see tenant-b's rows")
	}
}

func TestScope_Predicate_TenantUser_ExactMatchNeverNullOr(t *testing.T) {
	tenant, _ := ScopeFromClaims(&Claims{TenantID: strPtr("tenant-a")})
	sql, args := tenant.Predicate("r.tenant_id", 3)
	if sql != "r.tenant_id = $3" {
		t.Fatalf("predicate = %q, want exact match with no NULL disjunction", sql)
	}
	if len(args) != 1 || args[0] != "tenant-a" {
		t.Fatalf("args = %v, want [tenant-a]", args)
	}
}

func TestScope_Predicate_Platform_NoRestriction(t *testing.T) {
	platform, _ := ScopeFromClaims(&Claims{IsPlatformAdmin: true})
	sql, args := platform.Predicate("r.tenant_id", 1)
	if sql != "TRUE" || len(args) != 0 {
		t.Fatalf("platform predicate = %q args=%v, want TRUE and no args", sql, args)
	}
}
