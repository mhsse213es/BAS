package auth

import "testing"

// Segmentation runs send real traffic between zones, so starting one is admin
// only. Analysts may read results; viewers may not see them.
func TestSegmentationPermissionMatrix(t *testing.T) {
	cases := []struct {
		role Role
		perm Permission
		want bool
	}{
		{RoleAdmin, CanRunSegmentation, true},
		{RoleAnalyst, CanRunSegmentation, false},
		{RoleViewer, CanRunSegmentation, false},
		{RoleAdmin, CanViewSegmentation, true},
		{RoleAnalyst, CanViewSegmentation, true},
		{RoleViewer, CanViewSegmentation, false},
	}
	for _, c := range cases {
		if got := HasPermission(c.role, c.perm); got != c.want {
			t.Errorf("%s %s: got %v, want %v", c.role, c.perm, got, c.want)
		}
	}
}
