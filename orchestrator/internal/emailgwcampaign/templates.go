package emailgwcampaign

// confirmedFailure matches emailgwefficacy.VerdictConfirmedFailure's
// own string value exactly -- duplicated as a literal, not imported,
// per this package's own doc comment on why it cannot import
// emailgwefficacy.
const confirmedFailure = "confirmed-failure"

// BECSupplierFraudCampaignID is the first real campaign template --
// see the design doc's §10 for the full narrative and why each
// direction/gate was chosen.
const BECSupplierFraudCampaignID = "bec-supplier-fraud"

// BECSupplierFraudTemplate is a synthetic business-email-compromise
// narrative: a forged-executive identity probe (EG-002), followed --
// only if that probe was actually delivered -- by the real
// supplier-payment-diversion fraud message (EG-005), followed by
// read-only checks of that same message's own detection and
// response/remediation evidence. Both injected stages use the
// caught=true direction (ExpectedAction=Quarantine): the direction
// whose VerdictDetail answers "did the relevant control catch this",
// which is what this campaign's own gate and rollup need.
func BECSupplierFraudTemplate() CampaignTemplate {
	return CampaignTemplate{
		ID:   BECSupplierFraudCampaignID,
		Name: "Business Email Compromise - Supplier Payment Fraud",
		Stages: []StageTemplate{
			{
				Key:           "identity-probe",
				Label:         "Executive identity / impersonation probe",
				Kind:          StageKindInjected,
				ExpectationID: "EG-002.known-good",
			},
			{
				Key:           "fraud-payload",
				Label:         "Supplier payment-diversion fraud message",
				Kind:          StageKindInjected,
				ExpectationID: "EG-005.known-good",
				Gate: &GateCondition{
					UpstreamStageKey:  "identity-probe",
					UpstreamDimension: DimensionPrevention,
					// Proceed only when the identity probe was
					// actually delivered (ConfirmedFailure) -- the
					// one case where this attacker's pretext reached
					// the target and continuing the SAME narrative
					// with the real fraud instruction represents an
					// actual continuing attack chain. ConfirmedSuccess
					// (blocked) and Inconclusive both block, for
					// distinct reasons (see the gate evaluator).
					PermittedVerdicts: []string{confirmedFailure},
				},
			},
			{
				Key:               "detection-check",
				Label:             "Downstream detection / alerting evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "fraud-payload",
				ReadsDimension:    DimensionDetection,
			},
			{
				Key:               "response-check",
				Label:             "Response / remediation evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "fraud-payload",
				ReadsDimension:    DimensionResponse,
			},
		},
	}
}

// CredentialPhishingURLChainCampaignID is the second real campaign
// template -- email.txt's own "credential phishing" campaign family
// (its coverage-model area C, the second of the six illustrative,
// not-yet-built families BECSupplierFraudTemplate's design doc §11
// deferred). Narrative: a static credential-harvesting lure, followed
// -- only if that lure actually reached the target uninspected -- by
// a second, independent-layer probe testing whether click-time/
// post-delivery URL re-evaluation (Safe-Links-style time-of-click
// protection) catches what the first-line content scan missed. This
// is deliberately a layered-defense test, not a repeat of the same
// control: a gateway can fail static URL inspection yet still contain
// the attack chain through click-time re-evaluation.
const CredentialPhishingURLChainCampaignID = "credential-phishing-url-chain"

// CredentialPhishingURLChainTemplate chains EG-003's two already-wired
// scenario halves. Both injected stages use the direction whose
// VerdictDetail answers "did the relevant control catch this" --
// CredentialHarvestingURLExpectation(caught=true) and
// URLRewriteExpectation(knownBad=true) -- matching
// BECSupplierFraudTemplate's own convention exactly.
func CredentialPhishingURLChainTemplate() CampaignTemplate {
	return CampaignTemplate{
		ID:   CredentialPhishingURLChainCampaignID,
		Name: "Credential Phishing - Static Lure Then Click-Time Bypass Probe",
		Stages: []StageTemplate{
			{
				Key:           "initial-lure",
				Label:         "Static credential-harvesting URL lure",
				Kind:          StageKindInjected,
				ExpectationID: "EG-003.credential-url.known-good",
			},
			{
				Key:           "click-time-bypass-probe",
				Label:         "Click-time / post-delivery URL re-evaluation probe",
				Kind:          StageKindInjected,
				ExpectationID: "EG-003.url-rewrite.known-bad",
				Gate: &GateCondition{
					UpstreamStageKey:  "initial-lure",
					UpstreamDimension: DimensionPrevention,
					// Proceed only when the static lure was actually
					// delivered uninspected (ConfirmedFailure) -- the
					// one case representing a real attacker who now
					// believes the pretext landed and sends a second,
					// bad-reputation URL to see whether a different,
					// independent control layer still catches it.
					// ConfirmedSuccess (the first lure was already
					// blocked) and Inconclusive both block, for
					// distinct reasons, matching BEC's own gate.
					PermittedVerdicts: []string{confirmedFailure},
				},
			},
			{
				Key:               "detection-check",
				Label:             "Downstream detection / alerting evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "click-time-bypass-probe",
				ReadsDimension:    DimensionDetection,
			},
			{
				Key:               "response-check",
				Label:             "Response / remediation evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "click-time-bypass-probe",
				ReadsDimension:    DimensionResponse,
			},
		},
	}
}

// templatesByID is the static campaign-template registry -- same
// "plain Go function returning a slice/map" convention as
// emailgwefficacy's own scenario registry; not DB-authored.
var templatesByID = map[string]func() CampaignTemplate{
	BECSupplierFraudCampaignID:           BECSupplierFraudTemplate,
	CredentialPhishingURLChainCampaignID: CredentialPhishingURLChainTemplate,
}

// TemplateByID resolves a campaign template ID, or false if unknown.
func TemplateByID(id string) (CampaignTemplate, bool) {
	fn, ok := templatesByID[id]
	if !ok {
		return CampaignTemplate{}, false
	}
	return fn(), true
}

// StageByKey returns the StageTemplate named key within t, or false.
func (t CampaignTemplate) StageByKey(key string) (StageTemplate, bool) {
	for _, s := range t.Stages {
		if s.Key == key {
			return s, true
		}
	}
	return StageTemplate{}, false
}
