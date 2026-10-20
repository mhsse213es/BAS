package scenario

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// The two marked scenarios must keep their markers. A marker removed by an edit would
// silently turn a stage back into a gap, so this test fails loudly instead.
func TestMarkedScenarioFiles_CarryValidMarkers(t *testing.T) {
	cases := map[string]struct{ file, marker string }{
		"credential-access":        {"../../../scenarios/credential-access.yaml", "bas-cred-ident-01"},
		"caldera-lateral-movement": {"../../../scenarios/caldera-lateral-movement.yaml", "bas-lat-svc-create-01"},
	}
	for id, c := range cases {
		raw, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		var sc Scenario
		if err := yaml.Unmarshal(raw, &sc); err != nil {
			t.Fatalf("%s: parse: %v", id, err)
		}
		if err := sc.ValidateMarkers(); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		found := false
		for _, st := range sc.Steps {
			if st.Marker == c.marker {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: marker %q is missing from its steps", id, c.marker)
		}
	}
}
