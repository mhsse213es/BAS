package phishcatalog

import "github.com/audspect/bas/internal/phishval"

func ptrDelivery(o phishval.DeliveryOutcome) *phishval.DeliveryOutcome                  { return &o }
func ptrEnforcement(o phishval.EnforcementOutcome) *phishval.EnforcementOutcome         { return &o }
func ptrDetection(o phishval.DetectionOutcome) *phishval.DetectionOutcome               { return &o }
func ptrResponse(o phishval.ResponseOutcome) *phishval.ResponseOutcome                  { return &o }
func ptrInteraction(o phishval.UserInteractionOutcome) *phishval.UserInteractionOutcome { return &o }

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
// CoverageAdapterTested (Phase 3 upgrade from CoverageFixtureTested), not
// CoverageLiveValidated: emailgwefficacy's own
// TestEmailGWScenarioMaturity_RealRun_EG008Response/_AllPreventionScenarios
// (maturity_live_test.go) already runs SupplierPaymentDiversionExpectation
// (EG-005) through the real, httptest-backed DefenderMailEvidenceProvider
// -- actual OAuth token exchange, HTTP request, and JSON parsing, not a
// bare in-memory fixture -- and classifies it MaturityVerifiedThroughExecution.
// That is proof through the real adapter code path, never a live customer
// tenant, which stays separately tracked and is never implied here.
// Business-workflow challenge (phishing.txt §4 step 5) and
// incident-assignment/audit-trail (step 6) are NOT yet mapped -- genuine
// gaps, deferred to Phase 6 (SOC/IR/containment); this scenario's
// Expectation therefore covers only Delivery/Enforcement/Detection/
// Response, UserInteraction left nil (not applicable to this
// email-gateway+SOC narrative).
func phBEC002() Scenario {
	return Scenario{
		ID:               "PH-BEC-002",
		Version:          1,
		Area:             AreaBEC,
		Name:             "Supplier Payment-Change Validation",
		PrimaryObjective: "Detect payment-detail manipulation via a forged-executive identity probe followed by a supplier bank-account-change fraud payload",
		Preconditions:    "test mailbox, approved supplier persona, applicable mail policies, telemetry availability -- see emailgwcampaign.BECSupplierFraudTemplate",
		Limitations:      "business-workflow verification challenge and incident-assignment/audit-trail (phishing.txt §4 steps 5-6) are not modeled; proven through the real adapter code path, no live tenant has run this scenario",
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
		Coverage:             CoverageAdapterTested,
		// Variants: phishing.txt §3's PH-BEC-003 (invoice and payment
		// diversion) and PH-BEC-007 (urgent wire-transfer request) are
		// narrative framings of this identical control test
		// (SupplierPaymentDiversionExpectation's domain-reputation/
		// newly-observed-domain heuristic) -- phishing.txt capability #3's
		// own "Adversarial variant engine" acceptance bar: "Variants
		// share a common scenario definition... without duplicating the
		// entire implementation." Each still needs its own narrative
		// content authored before it is anything more than a declared
		// variant -- not yet built, tracked here rather than as an
		// orphan CatalogOnly stub.
		Variants: []Variant{
			{ID: "PH-BEC-003", BaseScenarioID: "PH-BEC-002", Axis: VariantAxisNarrative, Value: "invoice-diversion-framing",
				Name: "Invoice and payment diversion", PrimaryObjective: "Test financial-fraud detection"},
			{ID: "PH-BEC-007", BaseScenarioID: "PH-BEC-002", Axis: VariantAxisNarrative, Value: "urgent-wire-transfer-framing",
				Name: "Urgent wire-transfer request", PrimaryObjective: "Validate payment-fraud signals and escalation"},
		},
	}
}

// --- Phase 2: email ingress and BEC integration -------------------------
//
// Each function below maps a stable PH-* ID onto an already-shipped
// emailgwefficacy scenario builder (Phase 0's reuse-and-gap matrix, tables
// A/B/C). CoverageFixtureTested entries are proven end to end by
// phishbridge's own table-driven test
// (internal/phishbridge/area_ab_test.go), the same mechanism Phase 1
// proved for PH-BEC-002. CoverageCatalogOnly entries are either a genuine,
// unbuilt gap or an explicit overlap decision cross-referencing the ID
// that actually owns the implementation -- never a second entry silently
// duplicating the same evidence under a new name.

// phAUTH002 wraps emailgwefficacy.SPFAlignmentExpectation.
func phAUTH002() Scenario {
	return Scenario{
		ID: "PH-AUTH-002", Version: 1, Area: AreaAuth, Name: "SPF failure handling",
		PrimaryObjective:     "Verify policy behavior on SPF failure",
		Expectation:          phishval.Expectation{ScenarioID: "PH-AUTH-002", Enforcement: ptrEnforcement(phishval.EnforcementBlocked), Delivery: ptrDelivery(phishval.DeliveryQuarantined)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566"}},
		MappedImplementation: "emailgwefficacy.SPFAlignmentExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phAUTH003 wraps emailgwefficacy.DKIMAlignmentExpectation.
func phAUTH003() Scenario {
	return Scenario{
		ID: "PH-AUTH-003", Version: 1, Area: AreaAuth, Name: "DKIM failure handling",
		PrimaryObjective:     "Verify signature failure handling",
		Expectation:          phishval.Expectation{ScenarioID: "PH-AUTH-003", Enforcement: ptrEnforcement(phishval.EnforcementBlocked), Delivery: ptrDelivery(phishval.DeliveryQuarantined)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566"}},
		MappedImplementation: "emailgwefficacy.DKIMAlignmentExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phAUTH004 wraps emailgwefficacy.DMARCPolicyExpectation.
func phAUTH004() Scenario {
	return Scenario{
		ID: "PH-AUTH-004", Version: 1, Area: AreaAuth, Name: "DMARC enforcement",
		PrimaryObjective:     "Validate alignment and quarantine/reject policy",
		Expectation:          phishval.Expectation{ScenarioID: "PH-AUTH-004", Enforcement: ptrEnforcement(phishval.EnforcementBlocked), Delivery: ptrDelivery(phishval.DeliveryRejected)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566"}},
		MappedImplementation: "emailgwefficacy.DMARCPolicyExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phAUTH001 is an overlap decision, not a second implementation: external
// domain spoofing is, in this gateway model, exactly what DMARC
// enforcement acts on (a header-From domain misaligned against the
// SPF/DKIM-authenticated domain). PH-AUTH-004 owns the real evidence;
// this entry stays catalog-only rather than duplicate it under a second
// ID.
func phAUTH001() Scenario {
	return Scenario{
		ID: "PH-AUTH-001", Version: 1, Area: AreaAuth, Name: "External domain spoofing",
		PrimaryObjective: "Verify spoof detection and enforcement",
		Limitations:      "overlap decision: the same control evidence as PH-AUTH-004 (DMARC enforcement is what actually catches external domain spoofing here); not a second independent implementation",
		Coverage:         CoverageCatalogOnly,
	}
}

// phAUTH005 is an overlap decision: display-name impersonation is exactly
// ExecutiveImpersonationExpectation's own test (a forged display name on
// an otherwise-aligned freemail sender) -- PH-BEC-001 owns the real
// evidence.
func phAUTH005() Scenario {
	return Scenario{
		ID: "PH-AUTH-005", Version: 1, Area: AreaAuth, Name: "Display-name impersonation",
		PrimaryObjective: "Detect trusted-name abuse from an untrusted sender",
		Limitations:      "overlap decision: the same control evidence as PH-BEC-001 (ExecutiveImpersonationExpectation); not a second independent implementation",
		Coverage:         CoverageCatalogOnly,
	}
}

// phAUTH007, phAUTH009, phAUTH010: genuine, unbuilt gaps confirmed by
// Phase 0 research -- no scenario builder of any kind exists for internal
// sender spoofing, trusted-sender exception abuse (a different evidence
// shape -- emailgwefficacy.EmailPolicyBaselineExpectation exists but is a
// config-drift claim, not a MailExpectation, and needs its own bridge
// function, not this one), forwarding/mailing-list behavior, or
// compromised-legitimate-sender detection.
//
// phAUTH006 is corrected from that same earlier Phase 0 note ("genuine
// gap: no scenario builder exists"), which was wrong: PH-BEC-002's own
// mapped implementation (emailgwcampaign.BECSupplierFraudTemplate's
// second-stage payload, SupplierPaymentDiversionExpectation/EG-005)
// IS a lookalike-domain detection control -- its own doc comment says so
// explicitly ("domain-reputation/newly-observed-domain heuristics...
// distinct from... the message's OWN domain authentication"). The only
// difference between the two scenario IDs is narrative framing (BEC
// payment-fraud vs. generic sender-trust), exactly the same
// control-evidence-vs-narrative distinction already recorded as an
// overlap decision for PH-AUTH-001/PH-AUTH-005 above.
func phAUTH006() Scenario {
	return Scenario{ID: "PH-AUTH-006", Version: 1, Area: AreaAuth, Name: "Lookalike-domain detection",
		PrimaryObjective: "Test similarity and impersonation controls",
		Limitations:      "overlap decision: the same control evidence as PH-BEC-002 (SupplierPaymentDiversionExpectation's domain-reputation/newly-observed-domain heuristic); not a second independent implementation",
		Coverage:         CoverageCatalogOnly}
}

// phAUTH007 wraps phishbridge.InternalSenderSpoofExpectation +
// emailgwefficacy.InjectScenarioMessage/VerifyMailExpectation.
// Corrected from the earlier note ("no emailgwefficacy scenario
// builder wires it into a MailExpectation yet"): no new builder
// needed to be added to that package at all -- MailExpectation is a
// plain exported struct and InjectScenarioMessage/VerifyMailExpectation
// are already generic exported entry points that take their own
// content as a parameter, never consulting emailgwefficacy's private
// scenarioTestContent map. phishbridge supplies its own MailExpectation
// and InjectableMessage content directly. Zero changes to
// emailgwefficacy itself.
func phAUTH007() Scenario {
	return Scenario{
		ID: "PH-AUTH-007", Version: 1, Area: AreaAuth, Name: "Internal sender spoofing",
		PrimaryObjective:     "Validate protection against forged internal identities",
		Limitations:          "proven via exercise.SpoofableSMTPInjector's own real SMTP dispatch (HELO/relay control) against a real local SMTP server in tests; evaluation proven via emailgwefficacy.VerifyMailExpectation against fixture evidence -- no live gateway tenant has run this scenario",
		Expectation:          phishval.Expectation{ScenarioID: "PH-AUTH-007", Delivery: ptrDelivery(phishval.DeliveryQuarantined), Enforcement: ptrEnforcement(phishval.EnforcementBlocked), Detection: ptrDetection(phishval.DetectionDetected)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566"}},
		MappedImplementation: "phishbridge.InternalSenderSpoofExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phAUTH008 wraps emailgwefficacy.AuthenticationExceptionScopeExpectation
// (EG-009) -- corrected from an earlier Phase 2 pass, which mistakenly
// pointed this ID at EmailPolicyBaselineExpectation's config-drift shape.
// AuthenticationExceptionScopeExpectation is a real, already-dispatchable
// MailExpectation: a documented mail-flow exception bypassing inspection
// for a genuinely verified trusted source (scoped=true, known-good) vs. a
// message that spoofs only the exception's trigger condition without
// meeting its real verification (scoped=false, known-bad) -- exactly "do
// allowlists override required inspection."
func phAUTH008() Scenario {
	return Scenario{
		ID: "PH-AUTH-008", Version: 1, Area: AreaAuth, Name: "Trusted-sender exception abuse",
		PrimaryObjective:     "Test whether allowlists override required inspection",
		Expectation:          phishval.Expectation{ScenarioID: "PH-AUTH-008", Enforcement: ptrEnforcement(phishval.EnforcementBlocked), Delivery: ptrDelivery(phishval.DeliveryQuarantined)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566"}},
		MappedImplementation: "emailgwefficacy.AuthenticationExceptionScopeExpectation",
		Coverage:             CoverageAdapterTested,
		FalsePositiveRisk:    "the same exception control, if over-broad, risks blocking legitimate trusted-source mail. Phase 8's business-continuity pairing proof: TestPHAUTH008_BusinessContinuity_LegitimateTrustedSenderNotBlocked (phishbridge/phase8_test.go) wires AuthenticationExceptionScopeExpectation(scoped=true), the half of this control's own known-good/false-positive pair that had never been bridged before Phase 8.",
	}
}

// phAUTH009 wraps emailgwefficacy.InboxRuleExpectation (EG-007, external
// auto-forwarding) conceptually -- correcting an earlier Phase 2 claim
// that no scenario builder exists at all. InboxRuleExpectation/
// VerifyInboxRuleExpectation IS a real, dispatchable scenario, but (like
// EmailPolicyBaselineExpectation) a different evidence shape: a mailbox
// CONFIGURATION STATE claim (was a suspicious forwarding rule detected),
// not a MailExpectation/EfficacyResult phishbridge's current
// FromEmailGWEfficacyResult can translate. A second bridge function is
// needed, deferred.
// phAUTH009 wraps phishbridge.FromSingleDimensionDetectionVerdict, translating
// emailgwefficacy.VerifyInboxRuleExpectation's own real
// SuspiciousAutoForwardExpectation (EG-007) -- a mailbox-
// configuration-state claim, not a MailExpectation/EfficacyResult --
// into phishval's Detection dimension. The "needs its own phishbridge
// translation, deferred" note was accurate about what was missing (a
// translation, not a new scenario builder, unlike PH-AUTH-006/007's
// corrected notes); that translation is now built.
func phAUTH009() Scenario {
	return Scenario{
		ID: "PH-AUTH-009", Version: 1, Area: AreaAuth, Name: "Forwarding and mailing-list behavior",
		PrimaryObjective:     "Verify authentication and policy behavior after forwarding",
		Limitations:          "single-dimensional (Detection only): VerifyInboxRuleExpectation checks whether a suspicious rule was detected, nothing about the forwarded message's own delivery/enforcement; proven against fixture evidence, no live tenant audit-log/alert API called",
		Expectation:          phishval.Expectation{ScenarioID: "PH-AUTH-009", Detection: ptrDetection(phishval.DetectionDetected)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1114.003"}},
		MappedImplementation: "emailgwefficacy.SuspiciousAutoForwardExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phAUTH010 wraps phishbridge.FromSingleDimensionDetectionVerdict,
// translating emailgwefficacy.VerifyDelegatedMailboxAccessExpectation's
// own real SuspiciousDelegatedMailboxAccessExpectation
// (mailboxcompromise.go) -- a synthetic Full Access delegation grant
// with no legitimate business need, which tenant security telemetry
// should detect. The prior "no scenario builder exists" note was
// wrong: this capability already existed, built for a different area
// (F: "mailbox persistence") and never mapped to any PH-* ID.
// emailgwefficacy.SuspiciousOAuthConsentGrantExpectation is an
// equally-real sibling (also in mailboxcompromise.go) for a future
// scenario that specifically needs the OAuth-consent angle rather
// than delegated access -- not mapped here, to avoid stretching one
// scenario's Expectation to cover two independently-gradable signals.
func phAUTH010() Scenario {
	return Scenario{
		ID: "PH-AUTH-010", Version: 1, Area: AreaAuth, Name: "Compromised legitimate sender",
		PrimaryObjective:     "Detect suspicious content from an authenticated sender",
		Limitations:          "detects the compromise mechanism (suspicious mailbox delegation), not content-based anomaly in the sender's subsequent messages -- single-dimensional (Detection only), proven against fixture evidence, no live tenant audit-log/alert API called",
		Expectation:          phishval.Expectation{ScenarioID: "PH-AUTH-010", Detection: ptrDetection(phishval.DetectionDetected)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1098.002"}},
		MappedImplementation: "emailgwefficacy.SuspiciousDelegatedMailboxAccessExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phBEC001 wraps emailgwefficacy.ExecutiveImpersonationExpectation (EG-002).
func phBEC001() Scenario {
	return Scenario{
		ID: "PH-BEC-001", Version: 1, Area: AreaBEC, Name: "Executive impersonation",
		PrimaryObjective:     "Detect executive-targeted fraud",
		Expectation:          phishval.Expectation{ScenarioID: "PH-BEC-001", Enforcement: ptrEnforcement(phishval.EnforcementBlocked), Delivery: ptrDelivery(phishval.DeliveryQuarantined)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566", "T1534"}},
		MappedImplementation: "emailgwefficacy.ExecutiveImpersonationExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// PH-BEC-003 and PH-BEC-007 moved to phBEC002's own Variants (Phase 4):
// they are declared narrative variants of its control test, not
// standalone scenarios -- see phBEC002's own doc comment.

// phBEC004/005/006/008: genuine, unbuilt gaps confirmed by Phase 0
// research.
// phBEC004 is an overlap decision, corrected from "genuine gap: no
// scenario builder exists," which was wrong the same way PH-AUTH-006's
// note was: payroll/HR impersonation (a request to redirect
// direct-deposit/payroll details) is a narrative retextualization of
// PH-BEC-002's own SupplierPaymentDiversionExpectation -- the
// identical domain-reputation/newly-observed-domain heuristic catches
// a financial-redirect request regardless of whether its pretext is
// "supplier," "payroll," or anything else. phishing.txt's own
// capability #3 acceptance bar ("variants share a common scenario
// definition... without duplicating the entire implementation")
// governs this exactly like it already governs PH-BEC-002's own
// declared PH-BEC-003/PH-BEC-007 variants -- authoring new narrative
// content here would be exactly the duplication that bar warns
// against, not a genuine new capability.
func phBEC004() Scenario {
	return Scenario{ID: "PH-BEC-004", Version: 1, Area: AreaBEC, Name: "Payroll and HR impersonation",
		PrimaryObjective: "Validate sensitive-data request controls",
		Limitations:      "overlap decision: the same control evidence as PH-BEC-002 (SupplierPaymentDiversionExpectation's domain-reputation heuristic); a narrative retextualization, not a second independent implementation",
		Coverage:         CoverageCatalogOnly}
}

func phBEC005() Scenario {
	return Scenario{ID: "PH-BEC-005", Version: 1, Area: AreaBEC, Name: "Procurement and purchase-order fraud",
		PrimaryObjective: "Test supplier and purchasing workflows",
		Limitations:      "overlap decision: the same control evidence as PH-BEC-002 (SupplierPaymentDiversionExpectation's domain-reputation heuristic); a narrative retextualization, not a second independent implementation",
		Coverage:         CoverageCatalogOnly}
}

// phBEC006 is a partial-overlap decision: reply-chain hijacking's
// prerequisite -- the attacker controlling the legitimate mailbox --
// is the identical compromise-detection evidence PH-AUTH-010 now
// covers (SuspiciousDelegatedMailboxAccessExpectation). What stays a
// genuine, separate gap is the reply-chain-SPECIFIC part: detecting
// that a reply injected into an existing thread is anomalous relative
// to that thread's own history. No email-threading/content-anomaly
// capability exists anywhere in this codebase to test that
// independently -- building one would be new scope, not a translation
// of something that already exists, so it stays named here rather
// than faked by reusing the compromise signal alone.
func phBEC006() Scenario {
	return Scenario{ID: "PH-BEC-006", Version: 1, Area: AreaBEC, Name: "Reply-chain hijacking",
		PrimaryObjective: "Detect suspicious activity in an existing conversation",
		Limitations:      "partial overlap: the account-compromise precondition is the same evidence as PH-AUTH-010; detecting an anomalous reply within an existing thread (the reply-chain-specific part) is a genuine, separate gap -- no email-threading/content-anomaly capability exists anywhere in this codebase",
		Coverage:         CoverageCatalogOnly}
}

func phBEC008() Scenario {
	return Scenario{ID: "PH-BEC-008", Version: 1, Area: AreaBEC, Name: "Customer or partner impersonation",
		PrimaryObjective: "Test trusted external relationship abuse",
		Limitations:      "overlap decision: the same control evidence as PH-BEC-002 (SupplierPaymentDiversionExpectation's domain-reputation heuristic); a narrative retextualization (customer/partner pretext rather than supplier), not a second independent implementation",
		Coverage:         CoverageCatalogOnly}
}

// phURL001 wraps emailgwefficacy.CredentialHarvestingURLExpectation.
func phURL001() Scenario {
	return Scenario{
		ID: "PH-URL-001", Version: 1, Area: AreaURLCredentialIdentity, Name: "Known malicious URL",
		PrimaryObjective:     "Validate reputation-based blocking",
		Expectation:          phishval.Expectation{ScenarioID: "PH-URL-001", Enforcement: ptrEnforcement(phishval.EnforcementBlocked), Delivery: ptrDelivery(phishval.DeliveryQuarantined)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.002"}},
		MappedImplementation: "emailgwefficacy.CredentialHarvestingURLExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phURL005 wraps emailgwefficacy.URLRewriteExpectation (the
// CredentialPhishingURLChainTemplate's own click-time-bypass-probe
// stage).
func phURL005() Scenario {
	return Scenario{
		ID: "PH-URL-005", Version: 1, Area: AreaURLCredentialIdentity, Name: "Time-of-click protection",
		PrimaryObjective:     "Verify enforcement when the verdict changes after delivery",
		Expectation:          phishval.Expectation{ScenarioID: "PH-URL-005", Enforcement: ptrEnforcement(phishval.EnforcementChallenged), Delivery: ptrDelivery(phishval.DeliveryDelivered)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.002"}},
		MappedImplementation: "emailgwefficacy.URLRewriteExpectation",
		Coverage:             CoverageAdapterTested,
		FalsePositiveRisk:    "over-aggressive time-of-click re-evaluation risks treating a benign URL as malicious. Phase 8's business-continuity pairing proof: TestPHURL005_BusinessContinuity_BenignURLNotRewritten (phishbridge/phase8_test.go) wires URLRewriteExpectation(false), dispatch.go's own \"known-good\" half of this control's pair, never bridged before Phase 8.",
	}
}

// phEVA005 is an overlap decision: "delayed or modified destination" is
// the same click-time re-evaluation PH-URL-005 already proves.
func phEVA005() Scenario {
	return Scenario{ID: "PH-EVA-005", Version: 1, Area: AreaEvasionDetectionIR, Name: "Delayed or modified destination",
		PrimaryObjective: "Test post-delivery and time-of-click inspection",
		Limitations:      "overlap decision: the same control evidence as PH-URL-005 (URLRewriteExpectation); not a second independent implementation",
		Coverage:         CoverageCatalogOnly}
}

// phEVA001/phEVA002 are, respectively, an overlap decision and a genuine
// gap. PH-EVA-001 (allowlist bypass) is the same real evidence PH-AUTH-008
// already proves (AuthenticationExceptionScopeExpectation); PH-EVA-002
// (inbound relay-path bypass) shares PH-AUTH-007's unbuilt internal-relay
// gap.
func phEVA001() Scenario {
	return Scenario{ID: "PH-EVA-001", Version: 1, Area: AreaEvasionDetectionIR, Name: "Allowlist policy bypass",
		PrimaryObjective: "Find overly broad trusted-sender exceptions",
		Limitations:      "overlap decision: the same control evidence as PH-AUTH-008 (AuthenticationExceptionScopeExpectation); not a second independent implementation",
		Coverage:         CoverageCatalogOnly}
}

// phEVA002 is an overlap decision, corrected now that PH-AUTH-007 is
// built: InjectionTarget.RelayHost vs. TargetMX is purely a dispatch-
// target configuration choice (which wire path
// exercise.SpoofableSMTPInjector connects to), not a different
// verification mechanism -- VerifyMailExpectation evaluates identical
// enforcement/detection evidence either way. Testing whether an
// alternate relay path meaningfully bypasses inspection (vs. direct
// MX) would need a second, differently-configured real gateway to
// show an actual difference, which doesn't exist in this environment
// -- a real infrastructure gap, not an evaluation-logic one.
func phEVA002() Scenario {
	return Scenario{ID: "PH-EVA-002", Version: 1, Area: AreaEvasionDetectionIR, Name: "Inbound relay-path bypass",
		PrimaryObjective: "Validate inspection across alternate delivery paths",
		Limitations:      "overlap decision: the same VerifyMailExpectation evidence/verification as PH-AUTH-007; RelayHost vs. TargetMX is a dispatch-target configuration choice, not a distinct verification mechanism -- showing a genuine relay-path bypass needs a second, differently-configured real gateway, which doesn't exist in this environment",
		Coverage:         CoverageCatalogOnly}
}

// phID002 wraps the Phase 5 phishidentity.Client's real Microsoft Graph
// oauth2PermissionGrants listing -- an httptest-proven real OAuth+HTTP+
// JSON code path (phishidentity/client_test.go), the same adapter-tested
// discipline as the Phase 3 email scenarios. CoverageAdapterTested, not
// CoverageLiveValidated: no real tenant has run this, and per the Azure
// Real Discovery Integration project's own precedent, a real call would
// likely hit the same tenant-permission blocker (no subscription, no
// admin-consented app role) rather than a code blocker.
func phID002() Scenario {
	return Scenario{
		ID: "PH-ID-002", Version: 1, Area: AreaURLCredentialIdentity, Name: "OAuth consent abuse",
		PrimaryObjective:     "Validate consent restrictions and risky application detection",
		Expectation:          phishval.Expectation{ScenarioID: "PH-ID-002", Enforcement: ptrEnforcement(phishval.EnforcementBlocked)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1528"}}, // Steal Application Access Token
		MappedImplementation: "phishidentity.Client.ListOAuthConsentGrants",
		Coverage:             CoverageAdapterTested,
	}
}

// phID003/004/005: genuine, unbuilt gaps -- no Graph call against
// conditional-access, authentication-methods, or sign-in-log endpoints
// exists yet. phishidentity.Client (Phase 5) now proves the exact
// adapter pattern (EntraTokenSource + httptest-overridable BaseURL +
// real OAuth/HTTP/JSON) each of these would reuse -- the remaining work
// is a new Graph endpoint per scenario, not a new pattern.
func phID003() Scenario {
	return Scenario{ID: "PH-ID-003", Version: 1, Area: AreaURLCredentialIdentity, Name: "Device-code phishing defense",
		PrimaryObjective: "Validate identity-side protections and relevant alerts",
		Limitations:      "genuine gap: no Graph call against /identity/conditionalAccess/policies or sign-in logs for device-code grant-type usage exists yet; phishidentity.Client proves the reusable adapter pattern",
		Coverage:         CoverageCatalogOnly}
}

func phID004() Scenario {
	return Scenario{ID: "PH-ID-004", Version: 1, Area: AreaURLCredentialIdentity, Name: "MFA fatigue defense",
		PrimaryObjective: "Test relevant identity detections and conditional access",
		Limitations:      "genuine gap: no Graph call against /identity/conditionalAccess/policies or authentication-methods/sign-in-log endpoints exists yet; phishidentity.Client proves the reusable adapter pattern",
		Coverage:         CoverageCatalogOnly}
}

func phID005() Scenario {
	return Scenario{ID: "PH-ID-005", Version: 1, Area: AreaURLCredentialIdentity, Name: "Session-theft defense",
		PrimaryObjective: "Validate token/session protections using controlled test signals",
		Limitations:      "genuine gap: no Graph call against sign-in-risk or Continuous Access Evaluation endpoints exists yet; phishidentity.Client proves the reusable adapter pattern",
		Coverage:         CoverageCatalogOnly}
}

// phID001 is a genuine gap AT THIS BRIDGE LAYER only: exercise/tracker's
// HandleCredSubmit/HandleReport genuinely capture this evidence today
// (real, DB-backed), but as write-only DB events via the Recorder
// interface, not a typed in-memory value phishbridge's current
// I/O-free design can read back. A read-side query (e.g. an
// exercise.Store accessor returning typed evidence for an execution ID)
// does not exist yet -- a real, named gap, not a silent omission.
// phID001 wraps phishbridge.FromExerciseInteractionEvidence reading
// exercise.Store.ListEvidence -- corrected from an earlier pass's own
// note ("no typed read-side accessor yet"), which was stale:
// ListEvidence already exists and already returns everything needed
// (EvidenceType, Payload, CreatedAt per execution); the actual gap was
// the missing phishval translation, not new exercise.Store plumbing.
// exercise/tracker/credential.go records only the fact of submission,
// never credential values, matching this scenario's own objective
// exactly. Expectation deliberately targets InteractionClicked, not
// InteractionNone: this scenario's pass/fail boundary is specifically
// submission vs. non-submission AFTER the target reaches the
// credential-harvest page, not whether they clicked at all (that is
// PH-URL-*'s own concern) -- phishval's dimension evaluator is a
// strict equality match with no severity ordering, so the single
// expected value must be the exact terminal state this scenario's own
// objective cares about.
func phID001() Scenario {
	return Scenario{
		ID: "PH-ID-001", Version: 1, Area: AreaURLCredentialIdentity, Name: "Credential-harvesting simulation",
		PrimaryObjective:     "Measure controls without collecting real credentials",
		Expectation:          phishval.Expectation{ScenarioID: "PH-ID-001", UserInteraction: ptrInteraction(phishval.InteractionClicked)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.002"}},
		MappedImplementation: "phishbridge.FromExerciseInteractionEvidence",
		Coverage:             CoverageAdapterTested,
	}
}

// --- Phase 6: SOC, incident response, and containment proof -------------

// phDET001 wraps emailgwefficacy.CorrelateWithSIEM, strengthening or
// weakening an already-computed EfficacyResult's DetectionVerdict using
// independent SIEM telemetry -- never treating the email product's own
// alert as sufficient proof it reached the SOC's detection surface.
// CoverageFixtureTested: no real SIEM connector call happens in
// emailgwefficacy's own siemcorrelation.go yet (FixtureSIEMProvider
// only); internal/detectverify has 7 real vendor connectors but is not
// yet bridged to this correlation function (Phase 0's own flagged
// reconciliation, deferred).
func phDET001() Scenario {
	return Scenario{
		ID: "PH-DET-001", Version: 1, Area: AreaEvasionDetectionIR, Name: "SIEM ingestion and correlation",
		PrimaryObjective:     "Verify normalized alerts reach the SOC",
		Limitations:          "emailgwefficacy.CorrelateWithSIEM is fixture-only (FixtureSIEMProvider); internal/detectverify's 7 real connectors are not yet bridged to it",
		Expectation:          phishval.Expectation{ScenarioID: "PH-DET-001", Detection: ptrDetection(phishval.DetectionDetected)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566"}},
		MappedImplementation: "emailgwefficacy.CorrelateWithSIEM",
		Coverage:             CoverageFixtureTested,
	}
}

// phDET002: the "phishing_reported" event is real (exercise/tracker's
// handleReport, per PH-ID-001's own gap note) and ticketcorrelation.go's
// CorrelateWithTicketing proves the exact SOC-side escalation PATTERN
// PH-DET-002 needs -- but nothing today wires the report event INTO a
// ticketing correlation call. Corrected from an earlier, less precise
// "no SOC ingestion path" note: the pattern exists, the wiring does not.
func phDET002() Scenario {
	return Scenario{ID: "PH-DET-002", Version: 1, Area: AreaEvasionDetectionIR, Name: "User-reported phishing",
		PrimaryObjective: "Validate report ingestion and triage",
		Limitations:      "event capture is real (exercise/tracker's handleReport); SOC-side triage/ticket creation from that event is not wired, though emailgwefficacy.CorrelateWithTicketing (PH-IR-004) proves the exact pattern it would reuse",
		Coverage:         CoverageCatalogOnly}
}

// phIR001 is an overlap decision: "retroactive mailbox search and purge"
// is the identical mechanism PH-ATT-010 already proves
// (PostDeliveryThreatResponseExpectation's ResponseEvidence with
// ActionRequired="purge"), just catalogued under the incident-response
// lens instead of the attachment lens. Deliberately NOT a new Defender
// client method: Microsoft's real mailbox search-and-purge action lives
// in the Security & Compliance eDiscovery/Content-Search API, a
// materially different and more complex surface (compliance-search
// creation, then a separate purge action) this phase does not have
// verified access to confirm the exact request/response shape for --
// fabricating an unverified endpoint would be worse than naming the
// honest overlap.
func phIR001() Scenario {
	return Scenario{ID: "PH-IR-001", Version: 1, Area: AreaEvasionDetectionIR, Name: "Retroactive mailbox search and purge",
		PrimaryObjective: "Verify remediation of delivered test messages",
		Limitations:      "overlap decision: the same ResponseEvidence/ActionRequired=\"purge\" mechanism as PH-ATT-010 (PostDeliveryThreatResponseExpectation); the real Security & Compliance eDiscovery purge API is a separate, more complex surface not yet verified against",
		Coverage:         CoverageCatalogOnly}
}

// phIR002 wraps phishidentity.Client.RevokeAndVerifySignInSessions --
// a real, stable Graph v1.0 dispatch (RevokeSignInSessions) PLUS a
// real independent postcondition check (re-reading
// signInSessionsValidFromDateTime and comparing against a captured
// baseline, with bounded retry for propagation delay), both httptest-
// proven. This closes the verification gap this entry's own earlier
// note carried (rwevidence.ContainmentObserver's same limitation,
// fake-backed only): the verification here is real, not fake. The one
// remaining caveat, preserved explicitly in
// phishbridge.FromIdentityContainment's own Detail text: a verified
// marker advance proves the revocation marker changed server-side, not
// that every already-issued access token became unusable immediately.
func phIR002() Scenario {
	return Scenario{
		ID: "PH-IR-002", Version: 1, Area: AreaEvasionDetectionIR, Name: "Identity containment",
		PrimaryObjective:     "Validate authorized account/session containment workflows",
		Limitations:          "verification confirms the signInSessionsValidFromDateTime marker advanced server-side -- not that every already-issued access token became unusable immediately (short-lived tokens already held by a client can remain valid until their own natural expiry)",
		Expectation:          phishval.Expectation{ScenarioID: "PH-IR-002", Response: ptrResponse(phishval.ResponseContained)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1098"}}, // Account Manipulation
		MappedImplementation: "phishidentity.Client.RevokeSignInSessions",
		Coverage:             CoverageAdapterTested,
	}
}

// phIR003: the least-gapped IR scenario per Phase 0 research -- real,
// live-call-capable EPP Response Actions connectors (CrowdStrike/
// Defender/SentinelOne) plus internal/rwevidence's own verified-
// postcondition containment layer already exist and are tested
// elsewhere. Catalog-only here specifically because neither is yet
// bridged into phishval's own Outcome model -- an integration task, not
// a missing capability.
// phIR003 wraps phishbridge.FromEPPResponseAction, translating a real,
// already-dispatched internal/actions.Action (CrowdStrike/Defender/
// SentinelOne) into phishval's Response dimension. Dispatch-level
// evidence only, the same tier FromIdentityContainment started at in
// Phase 6: actions.StatusCompleted proves the EPP vendor accepted and
// completed the request, never that the host is independently
// confirmed isolated -- internal/rwevidence.ContainmentObserver (this
// codebase's one independent-verification layer) is itself fake-
// backed only, so there is no real postcondition verifier to call yet.
func phIR003() Scenario {
	return Scenario{
		ID: "PH-IR-003", Version: 1, Area: AreaEvasionDetectionIR, Name: "Endpoint follow-through",
		PrimaryObjective:     "Verify downstream endpoint alerts and investigation",
		Limitations:          "dispatch-level evidence only: actions.StatusCompleted proves the EPP vendor accepted and completed the request, not that the host is independently confirmed isolated -- rwevidence.ContainmentObserver, this codebase's one independent-verification layer, is itself fake-backed only",
		Expectation:          phishval.Expectation{ScenarioID: "PH-IR-003", Response: ptrResponse(phishval.ResponseRemediated)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.001"}},
		MappedImplementation: "phishbridge.FromEPPResponseAction",
		Coverage:             CoverageAdapterTested,
	}
}

// phIR004 wraps emailgwefficacy.CorrelateWithTicketing, mirroring
// phDET001/CorrelateWithSIEM's own structure and maturity exactly, for
// Response/escalation instead of Detection.
func phIR004() Scenario {
	return Scenario{
		ID: "PH-IR-004", Version: 1, Area: AreaEvasionDetectionIR, Name: "Incident escalation",
		PrimaryObjective:     "Validate ownership, severity, routing and escalation",
		Limitations:          "emailgwefficacy.CorrelateWithTicketing is fixture-only (FixtureTicketProvider); no real ITSM connector wired",
		Expectation:          phishval.Expectation{ScenarioID: "PH-IR-004", Response: ptrResponse(phishval.ResponseRemediated)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566"}},
		MappedImplementation: "emailgwefficacy.CorrelateWithTicketing",
		Coverage:             CoverageFixtureTested,
	}
}

// --- Phase 7: cross-channel and sector-specific coverage ---------------

// phCHN001 wraps exercise.TeamsInjector.Send -- a real incoming-webhook
// POST, httptest-proven in both exercise/injectors_test.go and
// phishbridge/crosschannel_test.go. Delivery-only per
// FromChannelInjectorResult's own documented boundary: dispatch success
// proves the lure reached Teams, never that the tenant's own Teams
// DLP/Safe-Links-for-Teams policy then caught it -- that read-back
// evidence source does not exist.
func phCHN001() Scenario {
	return Scenario{
		ID: "PH-CHN-001", Version: 1, Area: AreaCrossChannel, Name: "Teams collaboration lure",
		PrimaryObjective:     "Validate supported collaboration protections",
		Limitations:          "Delivery-only: exercise.TeamsInjector proves real webhook dispatch; no read-back of the tenant's own Teams-side DLP/Safe Links enforcement exists",
		Expectation:          phishval.Expectation{ScenarioID: "PH-CHN-001", Delivery: ptrDelivery(phishval.DeliveryDelivered)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.004"}}, // Spearphishing Voice/cross-channel services (closest covered sub-technique)
		MappedImplementation: "exercise.TeamsInjector.Send",
		Coverage:             CoverageAdapterTested,
	}
}

// phCHN002: genuine gap -- no SharePoint/OneDrive sharing-link simulation
// or sharing-invitation adapter exists anywhere in this codebase.
// phCHN002 wraps phishidentity.Client.CreateSharingInvite +
// VerifySharingInviteExists -- real, stable Graph v1.0 calls,
// httptest-proven, scoped to one explicit drive item and one explicit
// recipient list (never a tenant-wide share), with real cleanup
// (DeleteSharingInvite). Delivery-only: creation, independently
// confirmed via a separate read-back, proves the lure reached the
// sharing API -- never that the recipient saw, opened, or acted on it.
func phCHN002() Scenario {
	return Scenario{
		ID: "PH-CHN-002", Version: 1, Area: AreaCrossChannel, Name: "Malicious cloud-sharing invitation",
		PrimaryObjective:     "Test sharing-link inspection",
		Limitations:          "Delivery-only: independently-verified creation proves the invite reached the sharing API, never that the recipient saw or acted on it",
		Expectation:          phishval.Expectation{ScenarioID: "PH-CHN-002", Delivery: ptrDelivery(phishval.DeliveryDelivered)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.004"}},
		MappedImplementation: "phishidentity.Client.CreateSharingInvite",
		Coverage:             CoverageAdapterTested,
	}
}

// phCHN003 is an overlap decision, not new code: an "OAuth application
// invitation" lure and PH-ID-002's own "OAuth consent abuse" validate
// the identical control (phishidentity.Client.ListOAuthConsentGrants /
// IsTenantWideAndRisky) from two different simulation angles -- this
// entry is the lure-delivery framing, PH-ID-002 the audit framing.
func phCHN003() Scenario {
	return Scenario{ID: "PH-CHN-003", Version: 1, Area: AreaCrossChannel, Name: "OAuth application invitation",
		PrimaryObjective: "Validate application-consent controls",
		Limitations:      "overlap decision: validates the identical control as PH-ID-002 (phishidentity.Client.ListOAuthConsentGrants/IsTenantWideAndRisky), just framed as a lure-delivery scenario rather than a tenant audit",
		Coverage:         CoverageCatalogOnly}
}

// phCHN004: genuine gap -- no calendar-invite (.ics/Graph event) lure
// adapter exists.
// phCHN004 wraps phishidentity.Client.CreateCalendarEventLure +
// VerifyCalendarEventExists -- same real/httptest-proven/independently-
// verified/cleaned-up discipline as phCHN002, for a Graph calendar
// event lure instead of a sharing invite.
func phCHN004() Scenario {
	return Scenario{
		ID: "PH-CHN-004", Version: 1, Area: AreaCrossChannel, Name: "Calendar invitation lure",
		PrimaryObjective:     "Test supported calendar and mail controls",
		Limitations:          "Delivery-only: independently-verified creation proves the lure reached the calendaring API, never that the invited user saw, accepted, or clicked anything inside it",
		Expectation:          phishval.Expectation{ScenarioID: "PH-CHN-004", Delivery: ptrDelivery(phishval.DeliveryDelivered)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.004"}},
		MappedImplementation: "phishidentity.Client.CreateCalendarEventLure",
		Coverage:             CoverageAdapterTested,
	}
}

// phCHN005: partial overlap. A QR code is, at the protocol level, just
// an encoded URL -- once a victim's phone resolves it, the resulting
// browser-side chain is identical to PH-URL-001/PH-URL-005's own proven
// mechanism. The genuine gap is the QR-generation and mobile-camera
// transition itself, which has no adapter; the destination-URL leg is
// not re-proven here to avoid double-claiming PH-URL-001/005's own
// evidence.
func phCHN005() Scenario {
	return Scenario{ID: "PH-CHN-005", Version: 1, Area: AreaCrossChannel, Name: "Mobile QR-to-browser chain",
		PrimaryObjective: "Validate controls across mobile transitions",
		Limitations:      "partial overlap: the post-scan browser leg is the same mechanism as PH-URL-001/PH-URL-005; the QR-generation/mobile-camera transition itself has no adapter",
		Coverage:         CoverageCatalogOnly}
}

// phCHN006 wraps exercise.SMSInjector.Send for the SMS leg -- real,
// httptest-proven dispatch (per-recipient HTTP POST to a Twilio-
// compatible gateway). "Chain" in this scenario's own name means a
// full email<->SMS handoff: only the SMS leg is adapter-tested today:
// phishval.Chain (Phase 4) is EmailGW-stage-shaped
// (BuildCampaignChain reads emailgwcampaign.CampaignTemplate
// specifically), not yet generalized to compose an email stage with an
// SMS stage, so the two-stage claim itself stays deferred rather than
// forced.
func phCHN006() Scenario {
	return Scenario{
		ID: "PH-CHN-006", Version: 1, Area: AreaCrossChannel, Name: "SMS-to-email or email-to-SMS chain",
		PrimaryObjective:     "Validate cross-channel reporting and handoff",
		Limitations:          "the SMS leg (exercise.SMSInjector.Send) is real and adapter-tested; the full two-stage email<->SMS chain composition is deferred -- phishval.Chain is not yet generalized beyond emailgwcampaign.CampaignTemplate's own stage shape",
		Expectation:          phishval.Expectation{ScenarioID: "PH-CHN-006", Delivery: ptrDelivery(phishval.DeliveryDelivered)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.004"}},
		MappedImplementation: "exercise.SMSInjector.Send",
		Coverage:             CoverageAdapterTested,
	}
}

// phCHN007: genuine gap -- no voice/vishing adapter (call placement,
// IVR, or callback-fraud simulation) exists anywhere in this codebase.
func phCHN007() Scenario {
	return Scenario{ID: "PH-CHN-007", Version: 1, Area: AreaCrossChannel, Name: "Voice callback fraud",
		PrimaryObjective: "Test reporting and response workflows for vishing",
		Limitations:      "genuine gap: no voice/vishing adapter exists",
		Coverage:         CoverageCatalogOnly}
}

// phCHN008 wraps exercise.SlackInjector.Send -- real, httptest-proven
// incoming-webhook dispatch, the same mechanism and the same
// Delivery-only boundary as PH-CHN-001's Teams lure, applied to Slack
// as the representative "messaging platform."
func phCHN008() Scenario {
	return Scenario{
		ID: "PH-CHN-008", Version: 1, Area: AreaCrossChannel, Name: "Messaging-platform impersonation",
		PrimaryObjective:     "Test supported messaging integrations",
		Limitations:          "Delivery-only, same boundary as PH-CHN-001: exercise.SlackInjector proves real webhook dispatch to Slack as the representative messaging platform; no read-back of the destination platform's own enforcement exists",
		Expectation:          phishval.Expectation{ScenarioID: "PH-CHN-008", Delivery: ptrDelivery(phishval.DeliveryDelivered)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.004"}},
		MappedImplementation: "exercise.SlackInjector.Send",
		Coverage:             CoverageAdapterTested,
	}
}

// phATT001 wraps emailgwefficacy.EICARAttachmentExpectation -- a generic
// malicious-attachment test (an industry-standard EICAR string as a real
// MIME attachment), not HTML-specific. PH-ATT-002/003 (PDF/Office-doc
// with embedded link) have no format-specific builder, so they stay
// genuine gaps rather than being force-mapped onto this generic test.
func phATT001() Scenario {
	return Scenario{
		ID: "PH-ATT-001", Version: 1, Area: AreaAttachment, Name: "HTML attachment",
		PrimaryObjective:     "Validate file inspection and browser handoff",
		Limitations:          "EICARAttachmentExpectation is a generic malicious-MIME-attachment test, not literally HTML-formatted -- mapped here as the closest existing coverage, not an exact match",
		Expectation:          phishval.Expectation{ScenarioID: "PH-ATT-001", Enforcement: ptrEnforcement(phishval.EnforcementBlocked), Delivery: ptrDelivery(phishval.DeliveryQuarantined)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.001"}},
		MappedImplementation: "emailgwefficacy.EICARAttachmentExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phATT002 wraps phishbridge.PDFEmbeddedLinkExpectation/
// DispatchPDFEmbeddedLink: a real, valid, minimal PDF (correct
// xref table, a genuine /Link annotation with a /URI action) is
// generated, attached, and dispatched via
// exercise.SpoofableSMTPInjector's existing multipart-attachment
// path (the same mechanism EICARAttachmentExpectation uses), then
// evaluated through the unmodified VerifyMailExpectation. Closes the
// prior "genuine gap: no PDF-specific scenario builder exists" note
// -- the builder now exists, built entirely in phishbridge with zero
// changes to emailgwefficacy.
func phATT002() Scenario {
	return Scenario{
		ID: "PH-ATT-002", Version: 1, Area: AreaAttachment, Name: "PDF with embedded link",
		PrimaryObjective:     "Test content and URL inspection",
		Limitations:          "proven: the generated PDF is parsed back out of the real SMTP wire payload and confirmed to be a valid PDF carrying the expected link (not just a filename string in the raw MIME); evaluation proven against fixture evidence, no live gateway tenant has run this scenario",
		Expectation:          phishval.Expectation{ScenarioID: "PH-ATT-002", Delivery: ptrDelivery(phishval.DeliveryQuarantined), Enforcement: ptrEnforcement(phishval.EnforcementBlocked)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.001"}},
		MappedImplementation: "phishbridge.PDFEmbeddedLinkExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phATT003 wraps phishbridge.OfficeExternalLinkExpectation/
// DispatchOfficeExternalLink: a real, valid, minimal OOXML Word
// document (a genuine ZIP archive with a real external-hyperlink
// relationship part) is generated, attached, and dispatched the same
// way as phATT002. Closes the prior "genuine gap: no Office-document-
// specific scenario builder exists" note.
func phATT003() Scenario {
	return Scenario{
		ID: "PH-ATT-003", Version: 1, Area: AreaAttachment, Name: "Office document with external link",
		PrimaryObjective:     "Validate document and link controls",
		Limitations:          "proven: the generated DOCX is parsed back out of the real SMTP wire payload, opened as a zip archive, and its own relationship XML confirmed to declare the expected external hyperlink; evaluation proven against fixture evidence, no live gateway tenant has run this scenario",
		Expectation:          phishval.Expectation{ScenarioID: "PH-ATT-003", Delivery: ptrDelivery(phishval.DeliveryQuarantined), Enforcement: ptrEnforcement(phishval.EnforcementBlocked)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.001"}},
		MappedImplementation: "phishbridge.OfficeExternalLinkExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// phATT010 wraps emailgwefficacy.PostDeliveryThreatResponseExpectation
// (EG-008): a message not caught at delivery time, later re-evaluated as
// malicious, testing whether the required remediation action actually
// completed. The underlying fixture is content-generic (not literally an
// attachment), noted honestly -- same judgment call already made for
// PH-ATT-001/EICAR -- mapped here because it is the closest existing
// coverage for "retroactive remediation," phishing.txt's own objective
// for this ID. UserInteraction/Delivery/Enforcement are left nil: this
// scenario exercises Response only, exactly like emailgwefficacy's own
// EfficacyResult for it (VerifyMailExpectation always scores Prevention
// too, but this builder's own doc comment says Prevention is not the
// point here, so this catalog entry's Expectation does not assert it).
func phATT010() Scenario {
	return Scenario{
		ID: "PH-ATT-010", Version: 1, Area: AreaAttachment, Name: "Post-delivery attachment verdict change",
		PrimaryObjective:     "Verify retroactive remediation",
		Limitations:          "underlying fixture (PostDeliveryThreatResponseExpectation) is content-generic, not literally attachment-specific -- mapped as the closest existing coverage for this objective",
		Expectation:          phishval.Expectation{ScenarioID: "PH-ATT-010", Response: ptrResponse(phishval.ResponseRemediated)},
		Standards:            StandardsMapping{ATTACKTechniques: []string{"T1566.001"}},
		MappedImplementation: "emailgwefficacy.PostDeliveryThreatResponseExpectation",
		Coverage:             CoverageAdapterTested,
	}
}

// AudspectPhishingCatalog returns Audspect's current Phishing BAS Mastery
// scenario catalog, validated before being returned. Phase 1 seeded
// PH-BEC-002; Phase 2 adds the rest of areas A/B/C/D's email-relevant
// rows per the Phase 0 reuse-and-gap matrix, each either wrapping a real
// implementation (CoverageFixtureTested) or honestly named as an overlap
// decision/genuine gap (CoverageCatalogOnly).
func AudspectPhishingCatalog() ([]Scenario, error) {
	all := []Scenario{
		phBEC002(),
		phAUTH001(), phAUTH002(), phAUTH003(), phAUTH004(), phAUTH005(),
		phAUTH006(), phAUTH007(), phAUTH008(), phAUTH009(), phAUTH010(),
		phBEC001(), phBEC004(), phBEC005(), phBEC006(), phBEC008(),
		phURL001(), phURL005(), phID001(), phID002(), phID003(), phID004(), phID005(),
		phEVA001(), phEVA002(), phEVA005(),
		phDET001(), phDET002(), phIR001(), phIR002(), phIR003(), phIR004(),
		phCHN001(), phCHN002(), phCHN003(), phCHN004(), phCHN005(), phCHN006(), phCHN007(), phCHN008(),
		phATT001(), phATT002(), phATT003(), phATT010(),
	}
	if err := ValidateCatalog(all); err != nil {
		return nil, err
	}
	return all, nil
}
