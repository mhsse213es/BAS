package dbsim

import "testing"

func TestExpectationForPinsTheLiveVerifiedGrading(t *testing.T) {
	allow := Expectation{ExpectedPrevention: "allow", ExpectDetection: true}
	cases := []struct {
		scenario, probe string
		want            Expectation
	}{
		{"dbsim-db01-auth-policy", "auth_check", allow},
		{"dbsim-db01-auth-policy", "read_roles", allow},
		{"dbsim-db02-excessive-grants", "read_roles", allow},
		{"dbsim-db02-excessive-grants", "read_grants", Expectation{ExpectedPrevention: "allow", ExpectDetection: true, RequireObservation: true, RequirePolicyDiff: true}},
		{"dbsim-db03-unauthorized-access", "read_restricted_table", Expectation{ExpectedPrevention: "deny", ExpectDetection: true}},
		{"dbsim-db04-audit-coverage", "read_audit_config", Expectation{ExpectedPrevention: "allow", ExpectAuditConfig: true}},
		{"dbsim-db04-audit-coverage", "read_roles", Expectation{ExpectedPrevention: "allow", ExpectDetection: true, ExpectAudit: true}},
		{"dbsim-db05-suspicious-read", "suspicious_read", allow},
		{"dbsim-db06-account-revocation", "auth_after_revoke", Expectation{ExpectedPrevention: "deny"}},
		{"dbsim-db07-sensitive-classification", "read_classified_fixture", Expectation{ExpectedPrevention: "allow", ExpectDetection: true, ExpectClassification: true}},
		{"dbsim-db08-audit-tamper-resistance", "try_disable_audit", Expectation{ExpectedPrevention: "deny", ExpectDetection: true}},
		{"dbsim-db09-bounded-bulk-read", "bounded_synthetic_read", allow},
		{"dbsim-db10-write-delete-prevention", "try_write_fixture", Expectation{ExpectedPrevention: "deny", ExpectDetection: true}},
		{"dbsim-db11-backup-export-permissions", "check_export_privileges", Expectation{ExpectedPrevention: "deny"}},
	}
	for _, c := range cases {
		got, ok := ExpectationFor(c.scenario, c.probe)
		if !ok {
			t.Errorf("%s/%s: not found", c.scenario, c.probe)
			continue
		}
		if got != c.want {
			t.Errorf("%s/%s: got %+v want %+v", c.scenario, c.probe, got, c.want)
		}
	}
}

func TestExpectationForUnknownFailsClosed(t *testing.T) {
	for _, c := range [][2]string{
		{"", ""}, {"nope", "read_roles"}, {"dbsim-db01-auth-policy", "nope"},
		{"dbsim-db03-unauthorized-access", "read_roles"}, // known probe, wrong scenario
	} {
		if e, ok := ExpectationFor(c[0], c[1]); ok || e != (Expectation{}) {
			t.Errorf("%v: got %+v ok=%v, want zero/false", c, e, ok)
		}
	}
}
