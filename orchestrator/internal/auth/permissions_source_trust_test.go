package auth

import "testing"

func TestCanManageSourceTrust_AdminOnly(t *testing.T) {
	if !HasPermission(RoleAdmin, CanManageSourceTrust) {
		t.Error("expected RoleAdmin to hold CanManageSourceTrust")
	}
	if HasPermission(RoleAnalyst, CanManageSourceTrust) {
		t.Error("expected RoleAnalyst NOT to hold CanManageSourceTrust")
	}
}
