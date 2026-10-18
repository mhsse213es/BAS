package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwcampaign"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

func efficacyResultForAction(t *testing.T, exp emailgwefficacy.MailExpectation, action string, detection *bool, response *bool) emailgwefficacy.EfficacyResult {
	t.Helper()
	now := time.Now()
	var detectionEvidence []emailgwefficacy.DetectionEvidence
	if detection != nil {
		detectionEvidence = []emailgwefficacy.DetectionEvidence{{
			Message: exp.Ref(), AlertGenerated: *detection, Product: "m365-defender-o365",
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}}
	}
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: exp.Ref(), Action: action, ControlProduct: exp.ControlProduct,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		detectionEvidence,
	)
	if response != nil {
		provider = provider.WithResponse([]emailgwefficacy.ResponseEvidence{{
			Message: exp.Ref(), ActionRequired: "quarantine", Completed: *response,
			Timestamp: now, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}})
	}
	return emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, scenarioWindow())
}

func boolPtr(b bool) *bool { return &b }

// TestBuildCampaignChain_KnownBad_IdentityProbeDeliveredThenFraudCaught
// replays emailgwcampaign.BECSupplierFraudTemplate's real narrative: the
// identity-probe stage is delivered uninspected (ConfirmedFailure on
// Prevention), which is exactly the one condition BECSupplierFraudTemplate's
// own Gate permits the fraud-payload stage to proceed on. The fraud
// payload is then caught, detected, and remediated -- the chain's
// StoppedAtStage must report "fraud-payload", not "identity-probe"
// (which never stopped anything; it was never caught at all).
func TestBuildCampaignChain_KnownBad_IdentityProbeDeliveredThenFraudCaught(t *testing.T) {
	tmpl := emailgwcampaign.BECSupplierFraudTemplate()
	identityExp := emailgwefficacy.ExecutiveImpersonationExpectation(true)
	fraudExp := emailgwefficacy.SupplierPaymentDiversionExpectation(true)

	stageResults := map[string]emailgwefficacy.EfficacyResult{
		"identity-probe": efficacyResultForAction(t, identityExp, "deliver", nil, nil),
		"fraud-payload":  efficacyResultForAction(t, fraudExp, "quarantine", boolPtr(true), boolPtr(true)),
	}

	chain := BuildCampaignChain("run-chain-1", tmpl, stageResults)

	probe, ok := chain.StageByKey("identity-probe")
	if !ok || probe.Status != phishval.ChainStageCompleted {
		t.Fatalf("identity-probe stage = %+v, want Status=Completed", probe)
	}
	if probe.Outcome.Enforcement.Verdict != phishval.VerdictFail {
		t.Errorf("identity-probe Enforcement.Verdict = %q, want %q (delivered, not blocked)", probe.Outcome.Enforcement.Verdict, phishval.VerdictFail)
	}

	fraud, ok := chain.StageByKey("fraud-payload")
	if !ok || fraud.Status != phishval.ChainStageCompleted {
		t.Fatalf("fraud-payload stage = %+v, want Status=Completed (gate should have permitted it)", fraud)
	}
	if fraud.Outcome.Enforcement.Verdict != phishval.VerdictPass {
		t.Errorf("fraud-payload Enforcement.Verdict = %q, want %q", fraud.Outcome.Enforcement.Verdict, phishval.VerdictPass)
	}

	detectionCheck, ok := chain.StageByKey("detection-check")
	if !ok || detectionCheck.Status != phishval.ChainStageCompleted || detectionCheck.ReadDimension == nil {
		t.Fatalf("detection-check stage = %+v, want a completed derived read", detectionCheck)
	}
	if detectionCheck.ReadDimension.Verdict != phishval.VerdictPass {
		t.Errorf("detection-check.ReadDimension.Verdict = %q, want %q", detectionCheck.ReadDimension.Verdict, phishval.VerdictPass)
	}

	key, stopped := chain.StoppedAtStage()
	if !stopped || key != "fraud-payload" {
		t.Errorf("StoppedAtStage() = (%q, %v), want (%q, true)", key, stopped, "fraud-payload")
	}
}

// TestBuildCampaignChain_KnownGood_IdentityProbeBlockedStopsChainEarly is
// the mirror case: the identity-probe is caught at the first stage
// (ConfirmedSuccess, quarantined) -- BECSupplierFraudTemplate's own Gate
// only permits the fraud-payload stage on ConfirmedFailure, so it and
// both derived stages must come back Blocked, never fabricated as if
// they had run.
func TestBuildCampaignChain_KnownGood_IdentityProbeBlockedStopsChainEarly(t *testing.T) {
	tmpl := emailgwcampaign.BECSupplierFraudTemplate()
	identityExp := emailgwefficacy.ExecutiveImpersonationExpectation(true)

	stageResults := map[string]emailgwefficacy.EfficacyResult{
		"identity-probe": efficacyResultForAction(t, identityExp, "quarantine", nil, nil),
	}

	chain := BuildCampaignChain("run-chain-2", tmpl, stageResults)

	fraud, ok := chain.StageByKey("fraud-payload")
	if !ok || fraud.Status != phishval.ChainStageBlocked {
		t.Fatalf("fraud-payload stage = %+v, want Status=Blocked (gate should not have permitted it)", fraud)
	}
	if fraud.Outcome != nil {
		t.Error("fraud-payload.Outcome is set on a blocked stage, want nil (never fabricated)")
	}

	for _, key := range []string{"detection-check", "response-check"} {
		derived, ok := chain.StageByKey(key)
		if !ok || derived.Status != phishval.ChainStageBlocked {
			t.Errorf("%s stage = %+v, want Status=Blocked (cascades from fraud-payload)", key, derived)
		}
	}

	key, stopped := chain.StoppedAtStage()
	if !stopped || key != "identity-probe" {
		t.Errorf("StoppedAtStage() = (%q, %v), want (%q, true)", key, stopped, "identity-probe")
	}
}

// TestBuildCampaignChain_CredentialPhishingURLChain_EmailToURLToDetectionToResponse
// proves phishing.txt's own capability #1 acceptance example literally:
// a chain spanning email delivery -> URL click-time re-evaluation ->
// detection -> response, replaying
// emailgwcampaign.CredentialPhishingURLChainTemplate's real narrative --
// confirming BuildCampaignChain generalizes beyond the BEC template, not
// a special case tied to it.
func TestBuildCampaignChain_CredentialPhishingURLChain_EmailToURLToDetectionToResponse(t *testing.T) {
	tmpl := emailgwcampaign.CredentialPhishingURLChainTemplate()
	lureExp := emailgwefficacy.CredentialHarvestingURLExpectation(true)
	bypassExp := emailgwefficacy.URLRewriteExpectation(true)

	stageResults := map[string]emailgwefficacy.EfficacyResult{
		// The static lure is delivered uninspected (ConfirmedFailure on
		// Prevention) -- the one condition the template's own Gate
		// permits the click-time-bypass-probe stage to proceed on.
		"initial-lure": efficacyResultForAction(t, lureExp, "deliver", nil, nil),
		// The second, independent layer (click-time re-evaluation)
		// catches it: rewritten for click-time inspection, detected, and
		// remediated.
		"click-time-bypass-probe": efficacyResultForAction(t, bypassExp, "rewrite-link", boolPtr(true), boolPtr(true)),
	}

	chain := BuildCampaignChain("run-chain-url", tmpl, stageResults)

	lure, ok := chain.StageByKey("initial-lure")
	if !ok || lure.Status != phishval.ChainStageCompleted || lure.Outcome.Delivery.Verdict != phishval.VerdictFail {
		t.Fatalf("initial-lure stage = %+v, want Completed with Delivery=Fail (delivered despite expected quarantine)", lure)
	}

	bypass, ok := chain.StageByKey("click-time-bypass-probe")
	if !ok || bypass.Status != phishval.ChainStageCompleted {
		t.Fatalf("click-time-bypass-probe stage = %+v, want Completed (gate should have permitted it)", bypass)
	}
	if bypass.Outcome.Enforcement.Verdict != phishval.VerdictPass {
		t.Errorf("click-time-bypass-probe Enforcement.Verdict = %q, want %q (rewrite-link matches expected Challenged)", bypass.Outcome.Enforcement.Verdict, phishval.VerdictPass)
	}

	responseCheck, ok := chain.StageByKey("response-check")
	if !ok || responseCheck.Status != phishval.ChainStageCompleted || responseCheck.ReadDimension == nil {
		t.Fatalf("response-check stage = %+v, want a completed derived read", responseCheck)
	}
	if responseCheck.ReadDimension.Verdict != phishval.VerdictPass {
		t.Errorf("response-check.ReadDimension.Verdict = %q, want %q", responseCheck.ReadDimension.Verdict, phishval.VerdictPass)
	}

	key, stopped := chain.StoppedAtStage()
	if !stopped || key != "click-time-bypass-probe" {
		t.Errorf("StoppedAtStage() = (%q, %v), want (%q, true) -- the email-layer missed it, the URL-layer caught it", key, stopped, "click-time-bypass-probe")
	}
}
