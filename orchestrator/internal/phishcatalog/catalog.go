package phishcatalog

import "github.com/audspect/bas/internal/phishval"

func ptrDelivery(o phishval.DeliveryOutcome) *phishval.DeliveryOutcome          { return &o }
func ptrEnforcement(o phishval.EnforcementOutcome) *phishval.EnforcementOutcome { return &o }
func ptrDetection(o phishval.DetectionOutcome) *phishval.DetectionOutcome       { return &o }
func ptrResponse(o phishval.ResponseOutcome) *phishval.ResponseOutcome          { return &o }

// phBEC002 builds PH-BEC-002 -- phishing.txt §4's own worked example
// ("Supplier Payment-Change Validation"). It maps onto
// emailgwcampaign.BECSupplierFraudTemplate's real, already-shipped
// two-stage narrative (forged-executive identity probe, then the
// supplier payment-diversion fraud payload gated on the probe's own
// delivery outcome) plus its derived detection/response stages --
// phishing.txt §4 presents this exact scenario as "the target design,
// not a claim that the scenario already exists"; the underlying
// implementation already does, under a different name. See Phase 0's
// reuse-and-gap matrix, table B, row PH-BEC-002.
//
// CoverageFixtureTested, not CoverageLiveValidated: the underlying
// injection (exercise.SpoofableSMTPInjector) is real SMTP, but every
// existing test runs it against emailgwefficacy's
// FixtureMailEvidenceProvider, never a live tenant. Business-workflow
// challenge (phishing.txt §4 step 5) and incident-assignment/audit-trail
// (step 6) are NOT yet mapped -- genuine gaps, deferred to Phase 6
// (SOC/IR/containment); this scenario's Expectation therefore covers
// only Delivery/Enforcement/Detection/Response, UserInteraction left nil
// (not applicable to this email-gateway+SOC narrative).
func phBEC002() Scenario {
	return Scenario{
		ID:               "PH-BEC-002",
		Version:          1,
		Area:             AreaBEC,
		Name:             "Supplier Payment-Change Validation",
		PrimaryObjective: "Detect payment-detail manipulation via a forged-executive identity probe followed by a supplier bank-account-change fraud payload",
		Preconditions:    "test mailbox, approved supplier persona, applicable mail policies, telemetry availability -- see emailgwcampaign.BECSupplierFraudTemplate",
		Limitations:      "business-workflow verification challenge and incident-assignment/audit-trail (phishing.txt §4 steps 5-6) are not modeled; fixture-tested only, no live tenant has run this scenario",
		Provenance:       "phishing.txt §4 worked example, mapped onto the real emailgwcampaign.BECSupplierFraudTemplate narrative",
		Standards:        StandardsMapping{ATTACKTechniques: []string{"T1566", "T1534"}}, // Phishing; Internal Spearphishing (reply-chain/compromised-persona pretext)
		Expectation: phishval.Expectation{
			ScenarioID:  "PH-BEC-002",
			Delivery:    ptrDelivery(phishval.DeliveryQuarantined),
			Enforcement: ptrEnforcement(phishval.EnforcementBlocked),
			Detection:   ptrDetection(phishval.DetectionDetected),
			Response:    ptrResponse(phishval.ResponseRemediated),
		},
		MappedImplementation: "emailgwcampaign.BECSupplierFraudTemplate",
		Coverage:             CoverageFixtureTested,
	}
}

// AudspectPhishingCatalog returns Audspect's current Phishing BAS Mastery
// scenario catalog, validated before being returned. Phase 1 seeds only
// PH-BEC-002 (the proof-of-contract scenario); Phase 2 populates the rest
// of area A/B/C per the Phase 0 reuse-and-gap matrix.
func AudspectPhishingCatalog() ([]Scenario, error) {
	all := []Scenario{phBEC002()}
	if err := ValidateCatalog(all); err != nil {
		return nil, err
	}
	return all, nil
}
