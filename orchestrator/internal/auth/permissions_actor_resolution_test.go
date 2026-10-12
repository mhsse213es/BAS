package auth

import "testing"

// TCF Phase 2 spec §3.4: identity decisions are Admin-only.
func TestCanResolveActorIdentity_AdminOnly(t *testing.T) {
	if !HasPermission(RoleAdmin, CanResolveActorIdentity) {
		t.Error("expected RoleAdmin to hold CanResolveActorIdentity")
	}
	if HasPermission(RoleAnalyst, CanResolveActorIdentity) {
		t.Error("expected RoleAnalyst NOT to hold CanResolveActorIdentity")
	}
	if HasPermission(RoleViewer, CanResolveActorIdentity) {
		t.Error("expected RoleViewer NOT to hold CanResolveActorIdentity")
	}
}
