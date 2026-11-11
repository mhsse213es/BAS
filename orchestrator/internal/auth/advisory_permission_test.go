package auth

import "testing"

// Advisory relevance decisions are an analyst function. Viewers never hold it.
// Admin and analyst are the two roles the platform has for this work; the
// owner's "Senior Analyst" and "Curator" map to analyst.
func TestAdvisoryRelevancePermissionMatrix(t *testing.T) {
	want := map[Role]bool{
		RoleAdmin:   true,
		RoleAnalyst: true,
		RoleViewer:  false,
	}
	for role, allowed := range want {
		if got := HasPermission(role, CanDecideAdvisoryRelevance); got != allowed {
			t.Errorf("role %s: HasPermission(CanDecideAdvisoryRelevance) = %v, want %v", role, got, allowed)
		}
	}
}
