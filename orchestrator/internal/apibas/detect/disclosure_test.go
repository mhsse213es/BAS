package detect

import "testing"

// REL-020 reads the disclosure policy, not ownership. Each case names one disclosed class on one action.
func TestREL020DisclosurePolicy(t *testing.T) {
	cases := []struct {
		name   string
		action string
		class  string
		want   bool
	}{
		// Allowed combinations do not fire.
		{"kyc identity on the KYC resource", "GET /api/nbfc/kyc/KYC-A-001", DisclosureKYCIdentity, false},
		{"kyc identity on the admin KYC resource", "GET /api/nbfc/admin/kyc/KYC-B-001", DisclosureKYCIdentity, false},
		{"debit mandate on a statement", "GET /api/nbfc/loans/LOAN-A-001/statement", DisclosurePaymentCredential, false},
		{"account identifier on the loan", "GET /api/nbfc/loans/LOAN-A-001", DisclosureAccountIdentifier, false},
		// A class on a resource the policy does not list fires, whatever the owner.
		{"kyc identity through a loan read", "GET /api/nbfc/loans/LOAN-A-001", DisclosureKYCIdentity, true},
		{"debit mandate through a loan read", "GET /api/nbfc/loans/LOAN-A-001", DisclosurePaymentCredential, true},
		{"account identifier through the admin loan route", "GET /api/nbfc/admin/loans/LOAN-B-001", DisclosureAccountIdentifier, true},
		{"account identifier on a statement", "GET /api/nbfc/loans/LOAN-A-001/statement", DisclosureAccountIdentifier, true},
		// A class outside the closed set is never allowed.
		{"unknown class", "GET /api/nbfc/kyc/KYC-A-001", "unlisted_class", true},
	}
	for _, c := range cases {
		ev := Event{Seq: 1, CorrelationID: "run", Action: c.action, DisclosedClasses: []string{c.class}, Identity: "borrower-a", Status: 200, Outcome: "success"}
		if got := hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-020"); got != c.want {
			t.Errorf("%s: REL-020 fired = %t, want %t", c.name, got, c.want)
		}
	}
}

// An event with no disclosure has nothing to judge.
func TestREL020NoDisclosureDoesNotFire(t *testing.T) {
	ev := Event{Seq: 1, CorrelationID: "run", Action: "GET /api/nbfc/loans/LOAN-A-001", Identity: "borrower-a", Status: 200, Outcome: "success"}
	if hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-020") {
		t.Error("REL-020 fired on an event with no disclosed classes")
	}
}

// The ownership rules keep their logic: an owner reading their own KYC record is not a REL-004 event.
func TestREL020LeavesOwnershipRulesUnchanged(t *testing.T) {
	ev := Event{Seq: 1, CorrelationID: "run", Action: "GET /api/nbfc/kyc/KYC-A-001", DisclosedClasses: []string{DisclosureKYCIdentity},
		ObjectOwner: "borrower-a", ObjectOwners: []string{"borrower-a"}, Identity: "borrower-a", Status: 200, Outcome: "success"}
	if hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-004") {
		t.Error("REL-004 fired on the owner's own KYC read")
	}
}
