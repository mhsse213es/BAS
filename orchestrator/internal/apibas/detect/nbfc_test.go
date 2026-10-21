package detect

import "testing"

// The NBFC pack's routes classify as privileged or financial, so REL-007 reports them. Administrative routes are privileged.
func TestNBFCActionClasses(t *testing.T) {
	cases := []struct {
		action, want string
	}{
		{"POST /api/nbfc/loans/LOAN-B-001/decision", ClassFinancialApproval},
		{"POST /api/nbfc/loans/LOAN-A-001/prepare", ClassWrite},
		{"GET /api/nbfc/admin/loans/LOAN-B-001", ClassPrivilegeChange},
		{"GET /api/nbfc/admin/kyc/KYC-B-001", ClassPrivilegeChange},
		{"GET /api/nbfc/loans/LOAN-B-001/statement", ClassRead},
		{"PATCH /api/nbfc/repayments/REP-A-001", ClassWrite},
	}
	for _, c := range cases {
		if got := ActionClass(c.action); got != c.want {
			t.Errorf("ActionClass(%q) = %q, want %q", c.action, got, c.want)
		}
	}
}

// REL-018 fires on a repayment change by an identity that is not lender staff, whatever the outcome. The same change by an
// officer or administrator does not fire it.
func TestREL018RepaymentChangeByNonStaff(t *testing.T) {
	action := "PATCH /api/nbfc/repayments/REP-A-001"
	cases := []struct {
		role string
		want bool
	}{
		{"borrower", true},
		{"customer", true},
		{"officer", false},
		{"administrator", false},
		{"", false}, // an unauthenticated request carries no role, so the rule does not judge it
	}
	for _, c := range cases {
		ev := Event{Seq: 1, CorrelationID: "run", Action: action, ActorRole: c.role, Identity: "x", Status: 200, Outcome: "success"}
		if got := hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-018"); got != c.want {
			t.Errorf("role %q: REL-018 fired = %t, want %t", c.role, got, c.want)
		}
	}
	// A read of the same route is not a change.
	ev := Event{Seq: 1, CorrelationID: "run", Action: "GET /api/nbfc/repayments/REP-A-001", ActorRole: "borrower", Identity: "x", Status: 200, Outcome: "success"}
	if hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-018") {
		t.Error("REL-018 fired on a read of a repayment")
	}
}

// REL-019 fires on a privileged route called by a role that is not the administrator, whatever the outcome. The administrator's
// call does not fire it; REL-007 still reports the privileged call.
func TestREL019PrivilegedRouteWithoutAdministratorRole(t *testing.T) {
	action := "GET /api/nbfc/admin/loans/LOAN-B-001"
	cases := []struct {
		role string
		want bool
	}{
		{"borrower", true},
		{"officer", true},
		{"customer", true},
		{"administrator", false},
		{"", false},
	}
	for _, c := range cases {
		ev := Event{Seq: 1, CorrelationID: "run", Action: action, ActionClass: ClassPrivilegeChange, ActorRole: c.role, Identity: "x", Status: 403, Outcome: "failure"}
		if got := hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-019"); got != c.want {
			t.Errorf("role %q: REL-019 fired = %t, want %t", c.role, got, c.want)
		}
	}
	admin := Event{Seq: 2, CorrelationID: "run", Action: action, ActionClass: ClassPrivilegeChange, ActorRole: "administrator", Identity: "nbfc-admin", Status: 200, Outcome: "success"}
	alerts := evaluate([]Event{admin}, ElasticRules, "run", SourceElastic)
	if !hasRule(alerts, "APIBAS-REL-007") {
		t.Error("REL-007 did not report the administrator's privileged call")
	}
}
