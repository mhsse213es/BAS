package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// withTestRole grants a role the given permissions for the duration of one test. No shipped role has
// cleanup approval without injection approval, so the split is tested with a role that exists only here.
func withTestRole(t *testing.T, role Role, perms ...Permission) {
	t.Helper()
	set := map[Permission]bool{}
	for _, p := range perms {
		set[p] = true
	}
	rolePermissions[role] = set
	t.Cleanup(func() { delete(rolePermissions, role) })
}

// The cleanup approver's role holds cleanup approval and nothing else for approvals.
func TestApprovalSplit_CleanupOnlyRoleHasNoInjectionPermission(t *testing.T) {
	const cleanupOnly Role = "test-cleanup-approver"
	withTestRole(t, cleanupOnly, CanApprovePipelineCleanup)
	if !HasPermission(cleanupOnly, CanApprovePipelineCleanup) {
		t.Fatal("cleanup approver lacks cleanup approval")
	}
	if HasPermission(cleanupOnly, CanApprovePipelineInjection) {
		t.Fatal("cleanup approver gained injection approval")
	}
}

// The shared approval routes admit a caller holding either permission. The kind check in the handler
// then decides which one applies, so this gate alone never grants an injection decision.
func TestApprovalSplit_SharedRouteGateAdmitsEitherButNoOthers(t *testing.T) {
	const cleanupOnly Role = "test-cleanup-approver-gate"
	withTestRole(t, cleanupOnly, CanApprovePipelineCleanup)
	gate := RequireAnyPermission(CanApprovePipelineInjection, CanApprovePipelineCleanup)
	ok := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	cases := []struct {
		name string
		role Role
		want int
	}{
		{"cleanup-only role admitted at the door", cleanupOnly, http.StatusOK},
		{"role with no approval permission refused", "test-no-approval", http.StatusForbidden},
	}
	withTestRole(t, "test-no-approval")
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/pipeline-approvals", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxClaimsKey{}, &Claims{Role: c.role, UserID: "u"}))
		rec := httptest.NewRecorder()
		ok.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Fatalf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
	}
}
