package dbsim

import "testing"

// PostgreSQL grants read on pg_roles to every login, so a restricted login can
// always see other role names. The step records that exposure: the database
// permits the read (allow), and the objective no longer claims names are hidden.
func TestRoleNameDiscoveryRecordsExposureNotDenial(t *testing.T) {
	e, ok := ExpectationFor("dbsim-db03-unauthorized-access", "read_foreign_role_names")
	if !ok {
		t.Fatal("no expectation for read_foreign_role_names")
	}
	if e.ExpectedPrevention != "allow" {
		t.Fatalf("ExpectedPrevention = %q, want allow", e.ExpectedPrevention)
	}
	if !e.ExpectDetection {
		t.Fatal("role enumeration must still expect a SIEM detection")
	}
}
