package lab

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
)

// Every protected NBFC field has a disclosure class. A protected field added to the fixture without a class fails here.
func TestEveryProtectedNBFCFieldIsClassified(t *testing.T) {
	for _, o := range fixture.NBFCTwoBorrower().Objects {
		for field := range o.Protected {
			if _, ok := disclosedFieldClass[field]; !ok {
				t.Errorf("protected field %q on %s has no disclosure class", field, o.ID)
			}
		}
	}
}

// The healthcare clinical fields are classified. Its other protected fields (report and storage references) are not
// policy-governed disclosure classes yet and are deliberately absent.
func TestHealthcareClinicalFieldsAreClassified(t *testing.T) {
	for _, f := range []string{"diagnosis", "insurance_id"} {
		if _, ok := disclosedFieldClass[f]; !ok {
			t.Errorf("clinical field %q has no disclosure class", f)
		}
	}
}

// The walk finds protected names inside nested objects and lists, and returns names only.
func TestEmittedDisclosureFieldsWalksAndReturnsNamesOnly(t *testing.T) {
	body := map[string]any{
		"id":                   "LOAN-A-001",
		"disbursement_account": "BAS-SIM-LOAN-A-ACC",
		"kyc":                  map[string]any{"pan_number": "BAS-SIM-PAN-A", "aadhaar_ref": "BAS-SIM-AADHAAR-A"},
		"repayments":           []map[string]any{{"debit_mandate": "BAS-SIM-MANDATE-A"}},
	}
	got := emittedDisclosureFields(body)
	want := []string{"aadhaar_ref", "debit_mandate", "disbursement_account", "pan_number"}
	if !slices.Equal(got, want) {
		t.Fatalf("emitted fields = %v, want %v", got, want)
	}
	for _, name := range got {
		if strings.Contains(name, "BAS-SIM") {
			t.Errorf("a value leaked into a field name: %q", name)
		}
	}
}

// A body with no protected field records nothing.
func TestEmittedDisclosureFieldsEmptyForPublicBody(t *testing.T) {
	if got := emittedDisclosureFields(map[string]any{"id": "BOR-A", "segment": "salaried"}); len(got) != 0 {
		t.Errorf("public body recorded %v, want none", got)
	}
}

// Classes are derived from the fields, distinct and sorted.
func TestDisclosureClassesFromFields(t *testing.T) {
	got := disclosureClasses([]string{"pan_number", "aadhaar_ref", "debit_mandate"})
	want := []string{"kyc_identity", "payment_credential"}
	if !slices.Equal(got, want) {
		t.Fatalf("classes = %v, want %v", got, want)
	}
}

// An access event with no disclosure serialises without the disclosure keys, so existing consumers see the same shape.
func TestAccessEventOmitsEmptyDisclosure(t *testing.T) {
	b, err := json.Marshal(accessEvent{Seq: 1, Action: "GET /x", Outcome: "success", Identity: "a", Status: 200})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "disclosed_") {
		t.Errorf("empty disclosure serialised: %s", b)
	}
}
