package dbbuild

import "testing"

func TestDDLRoundtripHasObjectiveText(t *testing.T) {
	pt, ok := probeText["audit_ddl_roundtrip"]
	if !ok || pt.objective == "" || pt.action == "" {
		t.Fatalf("probe text missing for audit_ddl_roundtrip: %+v", pt)
	}
}
