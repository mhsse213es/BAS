package detect

import "testing"

// Policy: the class comes from the method and the route, never from ownership. The same route classifies the same way for
// the owner and for anyone else.
func TestActionClassVocabulary(t *testing.T) {
	cases := []struct {
		action, want string
	}{
		{"PATCH /api/me/role", ClassPrivilegeChange},
		{"POST /api/admin/orders/ORD-2001/status", ClassPrivilegeChange},
		{"GET /api/admin/reports", ClassPrivilegeChange},
		{"POST /api/biz/orders/ORD-2001/approve-payout", ClassFinancialApproval},
		{"POST /api/biz/orders/ORD-2001/refund", ClassFinancialApproval},
		{"POST /api/keys/rotate", ClassSecurityControlChange},
		{"PATCH /api/keys/orders/ORD-2001/status", ClassSecurityControlChange},
		{"DELETE /api/authz/orders/ORD-2001", ClassSecurityControlChange},
		{"GET /api/authz/orders/ORD-2001/audit", ClassSecurityControlChange},
		{"GET /api/orders/ORD-2001/export", ClassSensitiveExport},
		{"GET /api/orders/ORD-2001", ClassRead},
		{"GET /api/orders/ORD-2001/statement", ClassRead},
		{"PATCH /api/orders/ORD-2001", ClassWrite},
		{"POST /api/orders/ORD-2001/close", ClassWrite},
		{"DELETE /api/orders/ORD-2001", ClassWrite},
		{"", ""},
		{"no-method-separator", ""},
	}
	for _, c := range cases {
		if got := ActionClass(c.action); got != c.want {
			t.Errorf("ActionClass(%q) = %q, want %q", c.action, got, c.want)
		}
	}
}

// Only the three administrative, financial and security-control classes are privileged. An owned object's read, write
// or export is not.
func TestPrivilegedClassesAreTheAdministrativeOnes(t *testing.T) {
	privileged := []string{ClassPrivilegeChange, ClassFinancialApproval, ClassSecurityControlChange}
	for _, c := range privileged {
		if !isPrivilegedClass(c) {
			t.Errorf("%s is not privileged, want privileged", c)
		}
	}
	ordinary := []string{ClassRead, ClassWrite, ClassSensitiveExport, ""}
	for _, c := range ordinary {
		if isPrivilegedClass(c) {
			t.Errorf("%q is privileged, want ordinary", c)
		}
	}
}

// A admin-prefix look-alike is not an administrative route. It is an ordinary write or read on the route it names.
func TestAdminPrefixLookAlikeIsNotPrivilege(t *testing.T) {
	if got := ActionClass("GET /api/admin-notes/ORD-2001"); got != ClassRead {
		t.Errorf("admin-notes read = %q, want read", got)
	}
}

// REL-007 reads the class. An event with a privileged class fires it even when its action is not in the fallback list.
func TestRel007FiresOnClassedEvent(t *testing.T) {
	ev := Event{Seq: 1, CorrelationID: "run", Action: "POST /api/x/special", ActionClass: ClassFinancialApproval,
		Outcome: "failure", Status: 403, Identity: "cust-a"}
	alerts := evaluate([]Event{ev}, ElasticRules, "run", SourceElastic)
	if !hasRule(alerts, "APIBAS-REL-007") {
		t.Error("a classed privileged event did not raise REL-007")
	}
}

// REL-007 does not fire on an ordinary classed event, even on an owned object.
func TestRel007IgnoresOrdinaryClasses(t *testing.T) {
	for _, class := range []string{ClassRead, ClassWrite, ClassSensitiveExport} {
		ev := Event{Seq: 1, CorrelationID: "run", Action: "PATCH /api/orders/ORD-2001", ActionClass: class,
			Outcome: "success", Status: 200, Identity: "cust-a"}
		if hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-007") {
			t.Errorf("REL-007 fired on an ordinary %s event", class)
		}
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
