package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishval"
)

func scenarioWindow() emailgwefficacy.TimeWindow {
	now := time.Now()
	return emailgwefficacy.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
}

// phBEC002Expectation resolves the real catalog entry rather than
// hand-building a duplicate -- if the catalog's declared Expectation ever
// changes, this test changes with it instead of silently drifting out of
// sync.
func phBEC002Expectation(t *testing.T) phishval.Expectation {
	t.Helper()
	catalog, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("AudspectPhishingCatalog() error = %v", err)
	}
	s, ok := phishcatalog.ByID(catalog, "PH-BEC-002")
	if !ok {
		t.Fatal("PH-BEC-002 not found in catalog")
	}
	return s.Expectation
}

// TestPHBEC002_EndToEnd_KnownGood_ControlCatchesFraud is the Phase 1
// acceptance proof: emailgwefficacy's own real BEC fraud-payload
// expectation (SupplierPaymentDiversionExpectation), verified against
// fixture evidence where the control quarantined the message, generated
// a matching alert, and completed remediation, translated through
// phishbridge, must grade as VerdictPass on every PH-BEC-002 dimension.
func TestPHBEC002_EndToEnd_KnownGood_ControlCatchesFraud(t *testing.T) {
	exp := emailgwefficacy.SupplierPaymentDiversionExpectation(true)
	now := time.Now()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: exp.Ref(), Action: "quarantine", ControlProduct: exp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		[]emailgwefficacy.DetectionEvidence{{
			Message: exp.Ref(), AlertGenerated: true, Product: "m365-defender-o365",
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
	).WithResponse([]emailgwefficacy.ResponseEvidence{{
		Message: exp.Ref(), ActionRequired: "quarantine", Completed: true,
		Timestamp: now, Source: emailgwefficacy.SourceFixture,
		Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
	}})

	result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, scenarioWindow())
	obs := FromEmailGWEfficacyResult(result)
	outcome := phishval.Evaluate("run-known-good", "known-good", phBEC002Expectation(t), obs)

	for name, dim := range map[string]phishval.DimensionResult{
		"Delivery": outcome.Delivery, "Enforcement": outcome.Enforcement,
		"Detection": outcome.Detection, "Response": outcome.Response,
	} {
		if dim.Verdict != phishval.VerdictPass {
			t.Errorf("%s.Verdict = %q (%s), want %q", name, dim.Verdict, dim.Reason, phishval.VerdictPass)
		}
	}
}

// TestPHBEC002_EndToEnd_KnownBad_FraudDeliveredUninspected mirrors
// BECSupplierFraudTemplate's own gate condition: the fraud-payload stage
// only continues when the upstream identity probe was itself delivered
// uninspected (ConfirmedFailure) -- the realistic "control missed it
// entirely" branch. No detection or response evidence exists because
// nothing ever caught the message to generate either.
func TestPHBEC002_EndToEnd_KnownBad_FraudDeliveredUninspected(t *testing.T) {
	exp := emailgwefficacy.SupplierPaymentDiversionExpectation(true)
	now := time.Now()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: exp.Ref(), Action: "deliver", ControlProduct: exp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		nil,
	)

	result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, scenarioWindow())
	obs := FromEmailGWEfficacyResult(result)
	outcome := phishval.Evaluate("run-known-bad", "known-bad", phBEC002Expectation(t), obs)

	if outcome.Delivery.Verdict != phishval.VerdictFail {
		t.Errorf("Delivery.Verdict = %q, want %q (expected quarantined, observed delivered)", outcome.Delivery.Verdict, phishval.VerdictFail)
	}
	if outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("Enforcement.Verdict = %q, want %q (expected blocked, observed allowed)", outcome.Enforcement.Verdict, phishval.VerdictFail)
	}
	// No detection/response evidence exists -- emailgwefficacy's own
	// "absence of evidence is not proof of failure" discipline must
	// survive the bridge as NotTested, never a fabricated Fail.
	if outcome.Detection.Verdict != phishval.VerdictNotTested {
		t.Errorf("Detection.Verdict = %q, want %q (no evidence collected, must never be fabricated as Fail)", outcome.Detection.Verdict, phishval.VerdictNotTested)
	}
	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (no evidence collected, must never be fabricated as Fail)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}
