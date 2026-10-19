package api

import (
	"testing"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

func TestEmailGWExpectationFor_KnownScenario(t *testing.T) {
	id, ok := emailGWExpectationFor("PH-AUTH-002")
	if !ok || id != "EG-001.spf.known-bad" {
		t.Fatalf("emailGWExpectationFor(PH-AUTH-002) = %q, %v; want EG-001.spf.known-bad, true", id, ok)
	}
}

func TestEmailGWExpectationFor_UnmappedScenario_NotFound(t *testing.T) {
	if _, ok := emailGWExpectationFor("PH-URL-005"); ok {
		t.Fatal("PH-URL-005 must not map: its Challenged/Delivered expectation has no verified EG counterpart")
	}
}

// Every mapping must resolve to a real dispatch expectation, and that
// expectation's actual expected mail action must be consistent with the
// phishing scenario's own catalog expectation. Variant names are not
// uniform across scenarios (EG-002.known-good expects quarantine), so
// this, not the label, is what proves the pairing.
func TestEmailGWMapping_ConsistentWithPhishCatalogExpectation(t *testing.T) {
	for phID, egID := range phishEmailGWExpectation {
		exp, ok := emailgwefficacy.ExpectationByID(egID)
		if !ok {
			t.Errorf("%s maps to %q, which is not in the dispatch table", phID, egID)
			continue
		}
		catalogExp, err := lookupPhishingCatalogExpectation(phID)
		if err != nil {
			t.Fatalf("lookupPhishingCatalogExpectation(%s): %v", phID, err)
		}
		if catalogExp.Response != nil {
			if egID != "EG-008.known-good" && egID != "EG-008.known-bad" {
				t.Errorf("%s expects a Response outcome, which only EG-008 post-delivery verdicts provide; got %s", phID, egID)
			}
			continue
		}
		if catalogExp.Enforcement != nil && *catalogExp.Enforcement == phishval.EnforcementBlocked {
			if exp.ExpectedAction != emailgwefficacy.ExpectedQuarantine && exp.ExpectedAction != emailgwefficacy.ExpectedReject {
				t.Errorf("%s expects Enforcement=Blocked but %s expects %q, not a block", phID, egID, exp.ExpectedAction)
			}
		}
	}
}
