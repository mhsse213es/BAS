package detect

import "testing"

// Policy: privilege comes from the action and its resource. Ordinary access to an owned object is not privileged by
// ownership alone.
func TestActionClassPrivilegedOperations(t *testing.T) {
	privileged := []string{
		"PATCH /api/me/role",
		"POST /api/admin/orders/ORD-2001/status",
		"PATCH /api/admin/orders/ORD-2001/status",
		"GET /api/admin/reports",
		"POST /api/biz/orders/ORD-2001/approve-payout",
		"POST /api/biz/orders/ORD-2001/refund",
		"POST /api/keys/rotate",
		"PATCH /api/keys/orders/ORD-2001/status",
		"DELETE /api/authz/orders/ORD-2001",
		"GET /api/authz/orders/ORD-2001/audit",
	}
	for _, a := range privileged {
		if got := ActionClass(a); got != ClassPrivileged {
			t.Errorf("ActionClass(%q) = %q, want privileged", a, got)
		}
	}
}

func TestActionClassOrdinaryOwnedObjectAccessIsNotPrivileged(t *testing.T) {
	ordinary := []string{
		"GET /api/orders/ORD-2001",
		"PATCH /api/orders/ORD-2001",
		"GET /api/orders/ORD-2001/export",
		"POST /api/orders/ORD-2001/close",
		"POST /api/biz/orders/ORD-2001/withdraw",
		"PATCH /api/biz/orders/ORD-2001/status",
		"POST /api/biz/payments",
		"GET /api/admin-notes/ORD-2001", // a prefix look-alike is not an administrative route
		"",
	}
	for _, a := range ordinary {
		if got := ActionClass(a); got != "" {
			t.Errorf("ActionClass(%q) = %q, want no class", a, got)
		}
	}
}

// REL-007 reads the class. An event with the class set fires it even when its action is not in the fallback list.
func TestRel007FiresOnClassedEvent(t *testing.T) {
	ev := Event{Seq: 1, CorrelationID: "run", Action: "POST /api/x/special", ActionClass: ClassPrivileged, Outcome: "failure", Status: 403, Identity: "cust-a"}
	alerts := evaluate([]Event{ev}, ElasticRules, "run", SourceElastic)
	if !hasRule(alerts, "APIBAS-REL-007") {
		t.Error("a classed privileged event did not raise REL-007")
	}
}

// REL-011: an anonymous success on an owned object alerts. Insufficient telemetry does not: a refused anonymous request,
// or an anonymous success that reaches no owned object, raises nothing.
func TestRel011AnonymousSuccessOnOwnedObject(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{"anonymous success on an owned order", Event{Seq: 1, CorrelationID: "run", Action: "GET /api/orders/ORD-2001", Identity: "anonymous", Status: 200, ObjectOwner: "cust-b", ObjectOwners: []string{"cust-b"}}, true},
		{"anonymous request refused", Event{Seq: 1, CorrelationID: "run", Action: "GET /api/orders/ORD-2001", Identity: "anonymous", Status: 401, ObjectOwner: "cust-b", ObjectOwners: []string{"cust-b"}}, false},
		{"anonymous success with no owned object named", Event{Seq: 1, CorrelationID: "run", Action: "GET /docs", Identity: "anonymous", Status: 200}, false},
		{"authenticated owner success", Event{Seq: 1, CorrelationID: "run", Action: "GET /api/orders/ORD-2001", Identity: "cust-b", Status: 200, ObjectOwner: "cust-b", ObjectOwners: []string{"cust-b"}}, false},
	}
	for _, c := range cases {
		alerts := evaluate([]Event{c.ev}, ElasticRules, "run", SourceElastic)
		if got := hasRule(alerts, "APIBAS-REL-011"); got != c.want {
			t.Errorf("%s: REL-011 = %v, want %v", c.name, got, c.want)
		}
	}
}

func hasRule(alerts []Alert, id string) bool {
	for _, a := range alerts {
		if a.RuleID == id {
			return true
		}
	}
	return false
}
