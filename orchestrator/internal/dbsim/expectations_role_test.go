package dbsim

import "testing"

// DB-04-06: the GRANT and the REVOKE must both be recorded by the audit trail.
func TestRoleRoundtripExpectsGrantAndRevokeRecorded(t *testing.T) {
	e, ok := ExpectationFor("dbsim-db04-06-role-audit", "audit_role_roundtrip")
	if !ok {
		t.Fatal("no expectation for audit_role_roundtrip")
	}
	if e.ExpectedPrevention != "allow" || !e.ExpectAudit || e.AuditRequire != "GRANT|REVOKE" {
		t.Fatalf("expectation = %+v, want allow with audit requiring GRANT|REVOKE", e)
	}
}
