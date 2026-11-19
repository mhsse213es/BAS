package scenario

import "testing"

// DB-04-03: db_audit_basis accepts only the known evidence classes.
func TestDBAuditBasisValidation(t *testing.T) {
	mk := func(basis string) *Scenario {
		return &Scenario{ProductLine: ProductLineDBSim, Steps: []Step{{
			Name: "s", Executor: ExecutorDBProbe, DBTarget: "t1", DBProbe: "auth_check",
			DBAuditBasis: basis,
		}}}
	}
	if err := mk("role_window").ValidateDBProbeSteps(); err != nil {
		t.Fatalf("role_window must be accepted: %v", err)
	}
	if err := mk("").ValidateDBProbeSteps(); err != nil {
		t.Fatalf("empty basis (marker) must be accepted: %v", err)
	}
	if err := mk("hostname").ValidateDBProbeSteps(); err == nil {
		t.Fatal("an unknown db_audit_basis must be refused")
	}
}
