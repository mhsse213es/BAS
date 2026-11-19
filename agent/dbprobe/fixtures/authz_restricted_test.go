package fixtures

import (
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// Every table in the authz-restricted fixture is restricted, validates against the
// shared fixture rules, and carries only synthetic rows.
func TestAuthzRestrictedFixtureIsRestrictedAndSynthetic(t *testing.T) {
	spec, ok := Lookup(KindAuthzRestricted)
	if !ok {
		t.Fatal("authz-restricted fixture is not in the catalog")
	}
	if err := dbprobe.ValidateFixtureTables(spec.Tables); err != nil {
		t.Fatalf("fixture does not validate: %v", err)
	}
	want := map[string]bool{"restricted": true, "customers": true, "transactions": true}
	for _, tb := range spec.Tables {
		if !want[tb.Name] {
			t.Errorf("unexpected table %q", tb.Name)
		}
		if !tb.Restricted {
			t.Errorf("table %q must be restricted", tb.Name)
		}
		if len(tb.Rows) == 0 {
			t.Errorf("table %q has no rows", tb.Name)
		}
		for _, row := range tb.Rows {
			marked := false
			for _, cell := range row {
				if s, ok := cell.(string); ok && strings.HasPrefix(s, SyntheticMarker) {
					marked = true
				}
			}
			if !marked {
				t.Errorf("table %q has a row without the synthetic marker: %v", tb.Name, row)
			}
		}
		delete(want, tb.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing tables: %v", want)
	}
}
