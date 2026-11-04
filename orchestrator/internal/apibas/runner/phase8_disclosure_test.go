package runner_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Disclosure evidence and REL-020 end to end. Each request carries one correlation ID, so its access event can be read back
// the way the runner reads it, and the events are judged by the same detector the runner uses.

const discRun = "disc-run"

// discCall sends one request as the named identity under the correlation ID and returns the access events it produced.
func discCall(t *testing.T, e *env, identity, method, path string) []detect.Event {
	t.Helper()
	tok, err := e.secrets.Resolve("apibas/lab/" + identity)
	if err != nil {
		t.Fatalf("%s token: %v", identity, err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-BAS-Run", discRun)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", identity, path, err)
	}
	resp.Body.Close()
	events, err := e.admin.AccessEvents(context.Background(), discRun)
	if err != nil {
		t.Fatalf("access events: %v", err)
	}
	return events
}

// rel020Fired reports whether REL-020 fires on the events, using the detector the runner uses.
func rel020Fired(events []detect.Event) bool {
	f := detect.NewElasticFixture()
	if err := f.Ingest(events); err != nil {
		panic(err)
	}
	for _, a := range f.Alerts(discRun) {
		if a.RuleID == "APIBAS-REL-020" {
			return true
		}
	}
	return false
}

// The vulnerable build's expanded loan read emits the KYC identity fields. The event records their names and classes, and
// REL-020 fires. No value reaches the event.
func TestPhase8_VulnerableExpandedLoanRecordsKYCFields(t *testing.T) {
	e := newEnvWith(t, lab.ModeVulnerable, fixture.NBFCTwoBorrower(), nil, false)
	events := discCall(t, e, "borrower-a", http.MethodGet, "/api/nbfc/loans/LOAN-A-001?expand=kyc")
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	for _, f := range []string{"pan_number", "aadhaar_ref"} {
		if !slices.Contains(ev.DisclosedFields, f) {
			t.Errorf("disclosed fields %v do not include %s", ev.DisclosedFields, f)
		}
	}
	if !slices.Contains(ev.DisclosedClasses, detect.DisclosureKYCIdentity) {
		t.Errorf("disclosed classes %v do not include kyc_identity", ev.DisclosedClasses)
	}
	if !rel020Fired(events) {
		t.Error("REL-020 did not fire on a loan read that emitted KYC identity fields")
	}
	raw, _ := json.Marshal(events)
	for _, value := range []string{"BAS-SIM-PAN-A", "BAS-SIM-AADHAAR-A", "BAS-SIM-LOAN-A-ACC"} {
		if strings.Contains(string(raw), value) {
			t.Errorf("a protected value %s reached the access event", value)
		}
	}
}

// The fixed build never emits KYC through the loan read, so nothing is recorded as KYC and REL-020 does not fire.
func TestPhase8_FixedExpandedLoanEmitsNoKYC(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.NBFCTwoBorrower(), nil, false)
	events := discCall(t, e, "borrower-a", http.MethodGet, "/api/nbfc/loans/LOAN-A-001?expand=kyc")
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if slices.Contains(events[0].DisclosedClasses, detect.DisclosureKYCIdentity) {
		t.Errorf("fixed build recorded kyc_identity: %v", events[0].DisclosedClasses)
	}
	if rel020Fired(events) {
		t.Error("REL-020 fired on the fixed build")
	}
}

// Negative test (approved condition): the owner's KYC record through the KYC resource is legitimate disclosure, and REL-020
// does not fire, even though the class is emitted.
func TestPhase8_OwnerKYCResourceIsNotREL020(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.NBFCTwoBorrower(), nil, false)
	events := discCall(t, e, "borrower-a", http.MethodGet, "/api/nbfc/kyc/KYC-A-001")
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if !slices.Contains(events[0].DisclosedClasses, detect.DisclosureKYCIdentity) {
		t.Fatalf("the owner's KYC read recorded no kyc_identity class: %v", events[0].DisclosedClasses)
	}
	if rel020Fired(events) {
		t.Error("REL-020 fired on the owner's legitimate KYC-resource disclosure")
	}
}

// The fixed statement returns the owner's debit mandates, which the policy allows, and not the disbursement account.
func TestPhase8_FixedStatementOmitsDisbursementAccount(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.NBFCTwoBorrower(), nil, false)
	events := discCall(t, e, "borrower-b", http.MethodGet, "/api/nbfc/loans/LOAN-B-001/statement")
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if slices.Contains(events[0].DisclosedFields, "disbursement_account") {
		t.Errorf("fixed statement emitted the disbursement account: %v", events[0].DisclosedFields)
	}
	if !slices.Contains(events[0].DisclosedFields, "debit_mandate") {
		t.Errorf("owner's statement did not carry its debit mandate: %v", events[0].DisclosedFields)
	}
	if rel020Fired(events) {
		t.Error("REL-020 fired on the owner's own statement in the fixed build")
	}
}

// The vulnerable admin loan route emits the disbursement account to a borrower. That is outside the policy for the admin
// loan resource, so REL-020 fires alongside the administrative-access rules.
func TestPhase8_VulnerableAdminLoanDisclosesAccountOutsidePolicy(t *testing.T) {
	e := newEnvWith(t, lab.ModeVulnerable, fixture.NBFCTwoBorrower(), nil, false)
	events := discCall(t, e, "borrower-a", http.MethodGet, "/api/nbfc/admin/loans/LOAN-B-001")
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if !slices.Contains(events[0].DisclosedClasses, detect.DisclosureAccountIdentifier) {
		t.Fatalf("admin loan read recorded no account_identifier: %v", events[0].DisclosedClasses)
	}
	if !rel020Fired(events) {
		t.Error("REL-020 did not fire on an account identifier through the admin loan route")
	}
}
