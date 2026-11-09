package detect

import "testing"

// REL-021 fires on a laboratory result change by an identity whose role is known and is not a device, whatever the outcome.
func TestREL021ResultChangeByNonDevice(t *testing.T) {
	action := "PATCH /api/health/lab-results/LAB-A-001"
	cases := []struct {
		role string
		want bool
	}{
		{"patient", true},
		{"clinician", true},
		{"device", false},
		{"", false}, // an unauthenticated request carries no role, so the rule does not judge it
	}
	for _, c := range cases {
		ev := Event{Seq: 1, CorrelationID: "run", Action: action, ActorRole: c.role, Identity: "x", Status: 403, Outcome: "failure"}
		if got := hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-021"); got != c.want {
			t.Errorf("role %q: REL-021 fired=%t, want %t", c.role, got, c.want)
		}
	}
	other := Event{Seq: 1, CorrelationID: "run", Action: "GET /api/health/lab-results/LAB-A-001", ActorRole: "patient", Identity: "x", Status: 200, Outcome: "success"}
	if hasRule(evaluate([]Event{other}, ElasticRules, "run", SourceElastic), "APIBAS-REL-021") {
		t.Error("a read of a result must not fire REL-021")
	}
}

// REL-022 fires when a response to a delegate emits a clinical field, and not on a summary read or on another role.
func TestREL022ClinicalDataToDelegate(t *testing.T) {
	cases := []struct {
		name    string
		role    string
		classes []string
		want    bool
	}{
		{"delegate receives diagnosis", "delegate", []string{DisclosureClinicalRecord}, true},
		{"delegate receives summary only", "delegate", nil, false},
		{"patient receives diagnosis", "patient", []string{DisclosureClinicalRecord}, false},
		{"delegate receives another class", "delegate", []string{DisclosureKYCIdentity}, false},
	}
	for _, c := range cases {
		ev := Event{Seq: 1, CorrelationID: "run", Action: "GET /api/health/records/REC-A-001", ActorRole: c.role, Identity: "x",
			Status: 200, Outcome: "success", DisclosedClasses: c.classes}
		if got := hasRule(evaluate([]Event{ev}, ElasticRules, "run", SourceElastic), "APIBAS-REL-022"); got != c.want {
			t.Errorf("%s: REL-022 fired=%t, want %t", c.name, got, c.want)
		}
	}
}

// A clinical field on the record and export resources is inside the disclosure policy, so REL-020 stays quiet for an owner's
// own read. On any other resource it is a violation.
func TestClinicalClassPolicy(t *testing.T) {
	for action, want := range map[string]bool{
		"GET /api/health/records/REC-A-001": true,
		"GET /api/health/export":            true,
		"GET /api/health/images/IMG-A-001":  false,
	} {
		if got := disclosureAllowed(DisclosureClinicalRecord, action); got != want {
			t.Errorf("%s: allowed=%t, want %t", action, got, want)
		}
	}
}
