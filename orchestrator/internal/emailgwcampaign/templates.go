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

// MalwarePostDeliveryResponseCampaignID is the third real campaign
// template -- the design doc's §11 "malware/post-delivery response"
// family, deferred when BECSupplierFraudTemplate was first built.
const MalwarePostDeliveryResponseCampaignID = "malware-post-delivery-response"

// MalwarePostDeliveryResponseTemplate chains two already-wired, but
// previously never-chained, scenarios: a real malicious attachment
// (EG-004) that reaches the target, followed -- only if delivery
// actually happened -- by EG-008, whose own entire premise is a
// message that was NOT caught at delivery time and must instead be
// remediated afterward. Unlike BECSupplierFraudTemplate/
// CredentialPhishingURLChainTemplate, EG-008's own ExpectedAction is
// always ExpectedDeliver (see PostDeliveryThreatResponseExpectation's
// own doc comment) -- there is no "caught=true" direction to choose
// for this stage, because EG-008 tests the Response dimension, not
// Prevention; its two derived stages make that the actual point of
// this template, not a side effect.
func MalwarePostDeliveryResponseTemplate() CampaignTemplate {
	return CampaignTemplate{
		ID:   MalwarePostDeliveryResponseCampaignID,
		Name: "Malware Delivery - Post-Delivery Threat Response",
		Stages: []StageTemplate{
			{
				Key:           "malware-delivery",
				Label:         "Malicious attachment delivery attempt",
				Kind:          StageKindInjected,
				ExpectationID: "EG-004.known-good",
			},
			{
				Key:           "post-delivery-remediation",
				Label:         "Post-delivery remediation / zero-hour purge",
				Kind:          StageKindInjected,
				ExpectationID: "EG-008.known-good",
				Gate: &GateCondition{
					UpstreamStageKey:  "malware-delivery",
					UpstreamDimension: DimensionPrevention,
					// Proceed only when the malicious attachment was
					// actually delivered (ConfirmedFailure) -- the one
					// case where there is something to remediate after
					// the fact. If the attachment was already quarantined
					// at delivery, there is no post-delivery remediation
					// obligation to test.
					PermittedVerdicts: []string{confirmedFailure},
				},
			},
			{
				Key:               "detection-check",
				Label:             "Downstream detection / alerting evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "post-delivery-remediation",
				ReadsDimension:    DimensionDetection,
			},
			{
				Key:               "response-check",
				Label:             "Response / remediation evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "post-delivery-remediation",
				ReadsDimension:    DimensionResponse,
			},
		},
	}
}

// ExfiltrationCampaignID is the fourth real campaign template -- the
// design doc's §11 "exfiltration" family.
const ExfiltrationCampaignID = "exfiltration-credential-to-data-theft"

// ExfiltrationTemplate chains a credential-harvesting QR-code lure
// (EG-011) with the outbound-DLP scenario (EG-006): the one narrative
// in this catalogue that is genuinely about data leaving the
// organization, not content arriving at it. Gated the same way as
// every other template here (proceed only if the first stage's
// Prevention dimension was ConfirmedFailure), but the second stage
// dispatches through Microsoft Graph sendMail rather than
// exercise.SpoofableSMTPInjector -- dispatchInjectedStage/
// ExecuteEmailGWRun already branch on EnvelopeFrom vs
// OutboundSenderMailbox transparently, so no special-casing was needed
// here. EG-006.known-bad (not known-good) is deliberate: it is the
// sensitive=true/ExpectedQuarantine direction, matching every other
// template's "ConfirmedFailure on the caught=true/ExpectedQuarantine
// direction means the bad thing got through" convention.
func ExfiltrationTemplate() CampaignTemplate {
	return CampaignTemplate{
		ID:   ExfiltrationCampaignID,
		Name: "Credential Harvest Then Outbound Data Exfiltration",
		Stages: []StageTemplate{
			{
				Key:           "credential-lure",
				Label:         "Credential-harvesting QR-code lure",
				Kind:          StageKindInjected,
				ExpectationID: "EG-011.qr-code-lure.known-good",
			},
			{
				Key:           "outbound-exfiltration",
				Label:         "Sensitive-data outbound exfiltration attempt",
				Kind:          StageKindInjected,
				ExpectationID: "EG-006.known-bad",
				Gate: &GateCondition{
					UpstreamStageKey:  "credential-lure",
					UpstreamDimension: DimensionPrevention,
					// Proceed only when the lure was actually delivered
					// (ConfirmedFailure) -- the one case representing an
					// attacker who now believes they hold a usable
					// foothold and attempts to actually move data out.
					PermittedVerdicts: []string{confirmedFailure},
				},
			},
			{
				Key:               "detection-check",
				Label:             "Downstream detection / alerting evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "outbound-exfiltration",
				ReadsDimension:    DimensionDetection,
			},
			{
				Key:               "response-check",
				Label:             "Response / remediation evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "outbound-exfiltration",
				ReadsDimension:    DimensionResponse,
			},
		},
	}
}

// TrustConfigWeaknessCampaignID is the fifth real campaign template --
// the design doc's §11 "trust/configuration weaknesses" family.
const TrustConfigWeaknessCampaignID = "trust-configuration-weakness"

// TrustConfigWeaknessTemplate chains RelayPathBypassDirectExpectation
// and RelayPathBypassRelayExpectation -- PH-EVA-002's own two legs of
// a single, already-paired scenario (see relaypathbypass.go's own
// comments), never chained into a campaign before this template. The
// narrative this gate expresses: the direct leg already proves the
// perimeter gateway's own anti-spoofing policy failed to catch a
// spoofed sender (ConfirmedFailure) -- the one case where testing
// whether the SAME spoofed identity fares even worse through a
// differently-configured internal relay that does not re-apply that
// policy is a meaningful next step, not a redundant repeat.
func TrustConfigWeaknessTemplate() CampaignTemplate {
	return CampaignTemplate{
		ID:   TrustConfigWeaknessCampaignID,
		Name: "Relay-Path Anti-Spoofing Policy Bypass",
		Stages: []StageTemplate{
			{
				Key:           "direct-path-probe",
				Label:         "Spoofed sender via the perimeter gateway's direct inbound path",
				Kind:          StageKindInjected,
				ExpectationID: "EG-016.relay-path.direct.known-good",
			},
			{
				Key:           "relay-path-probe",
				Label:         "Same spoofed identity via a misconfigured internal relay",
				Kind:          StageKindInjected,
				ExpectationID: "EG-016.relay-path.relay.known-good",
				Gate: &GateCondition{
					UpstreamStageKey:  "direct-path-probe",
					UpstreamDimension: DimensionPrevention,
					// Proceed only when the direct-path spoof was
					// actually delivered (ConfirmedFailure) -- the
					// perimeter's own anti-spoofing policy already
					// proved weak, making the relay-path leg's own,
					// separately-configured policy worth testing next.
					PermittedVerdicts: []string{confirmedFailure},
				},
			},
			{
				Key:               "detection-check",
				Label:             "Downstream detection / alerting evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "relay-path-probe",
				ReadsDimension:    DimensionDetection,
			},
			{
				Key:               "response-check",
				Label:             "Response / remediation evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "relay-path-probe",
				ReadsDimension:    DimensionResponse,
			},
		},
	}
}

// MailboxCompromiseCampaignID is the sixth and final real campaign
// template -- the design doc's §11 "mailbox compromise" family. This
// tests the email-content CONSEQUENCE of a compromised mailbox (an
// attacker sending plausible mail through it), not the compromise
// mechanism itself: that is a separate, non-MailExpectation assessment
// model (OAuth consent-grant + delegated-access, see the QA log's item
// 18) that this package cannot chain into a stage, since
// StageKindInjected only resolves through
// emailgwefficacy.ExpectationByID.
const MailboxCompromiseCampaignID = "mailbox-compromise-consequence"

// MailboxCompromiseTemplate chains ReplyChainHijackExpectation (a
// message framed as a reply from an account presented as compromised)
// with OfficeExternalLinkExpectation, continuing the SAME target
// mailbox (both scenarios already use "finance-test@example-lab.test"
// as Recipient, independently of this template). The narrative: a
// hijacked-identity reply-chain message that actually reaches the
// target proves the compromised account's reply-chain credibility is
// exploitable -- worth testing whether the attacker can then leverage
// that same credibility to deliver a malicious-link document.
func MailboxCompromiseTemplate() CampaignTemplate {
	return CampaignTemplate{
		ID:   MailboxCompromiseCampaignID,
		Name: "Compromised-Account Reply-Chain Then Weaponized Follow-Up",
		Stages: []StageTemplate{
			{
				Key:           "reply-chain-hijack",
				Label:         "Reply-chain message from an account presented as compromised",
				Kind:          StageKindInjected,
				ExpectationID: "EG-015.reply-chain-hijack.known-good",
			},
			{
				Key:           "weaponized-follow-up",
				Label:         "Malicious-link document leveraging the same compromised identity",
				Kind:          StageKindInjected,
				ExpectationID: "EG-013.office-external-link.known-good",
				Gate: &GateCondition{
					UpstreamStageKey:  "reply-chain-hijack",
					UpstreamDimension: DimensionPrevention,
					// Proceed only when the hijacked reply-chain message
					// was actually delivered (ConfirmedFailure) -- the
					// one case where the compromised account's
					// credibility proved exploitable, making a follow-up
					// that leverages the same trust a meaningful next
					// step.
					PermittedVerdicts: []string{confirmedFailure},
				},
			},
			{
				Key:               "detection-check",
				Label:             "Downstream detection / alerting evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "weaponized-follow-up",
				ReadsDimension:    DimensionDetection,
			},
			{
				Key:               "response-check",
				Label:             "Response / remediation evidence",
				Kind:              StageKindDerived,
				ReadsFromStageKey: "weaponized-follow-up",
				ReadsDimension:    DimensionResponse,
			},
		},
	}
}

// templatesByID is the static campaign-template registry -- same
// "plain Go function returning a slice/map" convention as
// emailgwefficacy's own scenario registry; not DB-authored.
var templatesByID = map[string]func() CampaignTemplate{
	BECSupplierFraudCampaignID:            BECSupplierFraudTemplate,
	CredentialPhishingURLChainCampaignID:  CredentialPhishingURLChainTemplate,
	MalwarePostDeliveryResponseCampaignID: MalwarePostDeliveryResponseTemplate,
	ExfiltrationCampaignID:                ExfiltrationTemplate,
	TrustConfigWeaknessCampaignID:         TrustConfigWeaknessTemplate,
	MailboxCompromiseCampaignID:           MailboxCompromiseTemplate,
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
