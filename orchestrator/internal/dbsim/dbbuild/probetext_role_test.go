package dbbuild

import "testing"

func TestRoleRoundtripHasObjectiveText(t *testing.T) {
	pt, ok := probeText["audit_role_roundtrip"]
	if !ok || pt.objective == "" || pt.action == "" {
		t.Fatalf("probe text missing for audit_role_roundtrip: %+v", pt)
	}
}
