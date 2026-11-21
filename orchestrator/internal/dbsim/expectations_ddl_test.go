package dbsim

import "testing"

// DB-04-08: the DDL round-trip must be recorded by the audit trail (marker
// readback). The statements are allowed by the database.
func TestDDLRoundtripExpectsAuditRecord(t *testing.T) {
	e, ok := ExpectationFor("dbsim-db04-08-ddl-audit", "audit_ddl_roundtrip")
	if !ok {
		t.Fatal("no expectation for audit_ddl_roundtrip")
	}
	if e.ExpectedPrevention != "allow" || !e.ExpectAudit {
		t.Fatalf("expectation = %+v, want allow with audit", e)
	}
}
