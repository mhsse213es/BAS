package detect

import "testing"

// Each of REL-023, REL-024 and REL-025 fires on its route when the actor's role is known and is not the permitted role, whatever
// the outcome. The permitted role, an unauthenticated request and an unrelated route do not fire it.
func TestCommerceRoleRules(t *testing.T) {
	cases := []struct {
		rule, action, okRole string
		bad                  []string
	}{
		{"APIBAS-REL-023", "PATCH /api/retail/orders/RORD-A-001", "agent", []string{"shopper", "partner"}},
		{"APIBAS-REL-024", "POST /api/retail/partner-keys/PKEY-1-001/escalate", "agent", []string{"partner", "shopper"}},
		{"APIBAS-REL-025", "POST /api/retail/shipments/SHIP-A-001/callback", "carrier", []string{"shopper", "agent"}},
	}
	fires := func(rule, action, role string) bool {
		ev := Event{Seq: 1, CorrelationID: "run", Action: action, ActorRole: role, Identity: "x", Status: 403, Outcome: "failure"}
		return hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), rule)
	}
	for _, c := range cases {
		for _, role := range c.bad {
			if !fires(c.rule, c.action, role) {
				t.Errorf("%s did not fire for role %q", c.rule, role)
			}
		}
		if fires(c.rule, c.action, c.okRole) {
			t.Errorf("%s fired for the permitted role %q", c.rule, c.okRole)
		}
		if fires(c.rule, c.action, "") {
			t.Errorf("%s fired for an unauthenticated request", c.rule)
		}
	}
	for rule, action := range map[string]string{
		"APIBAS-REL-023": "GET /api/retail/orders/RORD-A-001",
		"APIBAS-REL-024": "GET /api/retail/partner-keys/PKEY-1-001",
		"APIBAS-REL-025": "GET /api/retail/shipments/SHIP-A-001",
	} {
		if fires(rule, action, "shopper") {
			t.Errorf("%s fired on a read: %s", rule, action)
		}
	}
}
