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

// templatesByID is the static campaign-template registry -- same
// "plain Go function returning a slice/map" convention as
// emailgwefficacy's own scenario registry; not DB-authored.
var templatesByID = map[string]func() CampaignTemplate{
	BECSupplierFraudCampaignID: BECSupplierFraudTemplate,
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
