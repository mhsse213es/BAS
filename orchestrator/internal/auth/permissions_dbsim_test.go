package auth

import "testing"

// Database security simulation: reading targets, runs and settings is
// Analyst+Admin (the people who run assessments); registering/deleting targets,
// running the read-only identity check and the DB client mode switch are Admin
// only, like the other connector/target configuration permissions.
func TestDBSimPermissions(t *testing.T) {
	for _, c := range []struct {
		perm                  Permission
		admin, analyst, viewr bool
	}{
		{CanViewDBSim, true, true, false},
		{CanManageDBSimTargets, true, false, false},
		{CanSetDBSimClientMode, true, false, false},
	} {
		if HasPermission(RoleAdmin, c.perm) != c.admin || HasPermission(RoleAnalyst, c.perm) != c.analyst ||
			HasPermission(RoleViewer, c.perm) != c.viewr {
			t.Errorf("%s: admin=%v analyst=%v viewer=%v", c.perm, HasPermission(RoleAdmin, c.perm),
				HasPermission(RoleAnalyst, c.perm), HasPermission(RoleViewer, c.perm))
		}
	}
	// An unknown role holds nothing.
	for _, p := range []Permission{CanViewDBSim, CanManageDBSimTargets, CanSetDBSimClientMode} {
		if HasPermission(Role("nobody"), p) || HasPermission(Role(""), p) {
			t.Errorf("unknown role holds %s", p)
		}
	}
}
