package detect

import "testing"

// REL-012 fires on a destination outside policy, whatever the outcome. An allowed destination, or no destination at all,
// raises nothing.
func TestRel012DestinationPolicy(t *testing.T) {
	cases := []struct {
		name    string
		policy  string
		outcome string
		status  int
		want    bool
	}{
		{"redirect off origin, served", "outside_allowlist", "success", 200, true},
		{"redirect off origin, refused", "outside_allowlist", "failure", 400, true},
		{"internal address, refused", "internal", "failure", 403, true},
		{"allowlisted destination", "allowed", "success", 200, false},
		{"no destination recorded", "", "success", 200, false},
	}
	for _, c := range cases {
		ev := Event{Seq: 1, CorrelationID: "run", Action: "GET /api/integrations/return", Outcome: c.outcome,
			Status: c.status, Identity: "cust-a", DestinationPolicy: c.policy}
		alerts := evaluate([]Event{ev}, ElasticRules, "run", SourceElastic)
		if got := hasRule(alerts, "APIBAS-REL-012"); got != c.want {
			t.Errorf("%s: REL-012 = %v, want %v", c.name, got, c.want)
		}
	}
}
