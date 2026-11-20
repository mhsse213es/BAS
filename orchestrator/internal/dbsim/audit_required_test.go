package dbsim

import "testing"

// DB-04-08: both the marker-tagged CREATE and DROP must appear in the audit trail.
// One of them alone is a FAIL (the source was healthy and caught up).
func TestAuditRequiredStatementsAllMustAppear(t *testing.T) {
	s := ScenarioMeta{ExpectAudit: true, AuditRequireStatements: []string{"CREATE TABLE", "DROP TABLE"}}
	create := DBProbeAuditEvent{Statement: "/* dbsim:m1 */ CREATE TABLE \"dbsim_ab12\".\"dbsim_ddl_probe\" (id int)"}
	drop := DBProbeAuditEvent{Statement: "/* dbsim:m1 */ DROP TABLE \"dbsim_ab12\".\"dbsim_ddl_probe\""}

	only := Outcome{Marker: "m1", Probe: DBProbeResult{AuditStatus: AuditFound, AuditEvents: []DBProbeAuditEvent{create}}}
	if g, _ := auditGrade(s, only); g != DimFail {
		t.Fatalf("CREATE without DROP graded %v, want fail", g)
	}
	both := Outcome{Marker: "m1", Probe: DBProbeResult{AuditStatus: AuditFound, AuditEvents: []DBProbeAuditEvent{create, drop}}}
	if g, _ := auditGrade(s, both); g != DimPass {
		t.Fatalf("CREATE and DROP graded %v, want pass", g)
	}
}
