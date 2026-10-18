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
		Coverage:             CoverageAdapterTested,
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

// phAUTH006 through phAUTH010: genuine, unbuilt gaps confirmed by Phase 0
// research -- no scenario builder of any kind exists for lookalike-domain
// detection, internal sender spoofing, trusted-sender exception abuse (a
// different evidence shape -- emailgwefficacy.EmailPolicyBaselineExpectation
// exists but is a config-drift claim, not a MailExpectation, and needs its
// own bridge function, not this one), forwarding/mailing-list behavior, or
// compromised-legitimate-sender detection.
func phAUTH006() Scenario {
	return Scenario{ID: "PH-AUTH-006", Version: 1, Area: AreaAuth, Name: "Lookalike-domain detection",
		PrimaryObjective: "Test similarity and impersonation controls",
		Limitations:      "genuine gap: no scenario builder exists", Coverage: CoverageCatalogOnly}
}

func phAUTH007() Scenario {
	return Scenario{ID: "PH-AUTH-007", Version: 1, Area: AreaAuth, Name: "Internal sender spoofing",
		PrimaryObjective: "Validate protection against forged internal identities",
		Limitations:      "exercise.SpoofableSMTPInjector supports relay/HELO control for this, but no emailgwefficacy scenario builder wires it into a MailExpectation yet -- a real implementation gap, not a missing underlying capability",
		Coverage:         CoverageCatalogOnly}
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
func phAUTH009() Scenario {
	return Scenario{ID: "PH-AUTH-009", Version: 1, Area: AreaAuth, Name: "Forwarding and mailing-list behavior",
		PrimaryObjective: "Verify authentication and policy behavior after forwarding",
		Limitations:      "emailgwefficacy.InboxRuleExpectation/VerifyInboxRuleExpectation (EG-007) exists and covers external auto-forwarding detection, but is a different evidence shape (mailbox configuration state, not MailExpectation/EfficacyResult) -- needs its own phishbridge translation, deferred",
		Coverage:         CoverageCatalogOnly}
}

func phAUTH010() Scenario {
	return Scenario{ID: "PH-AUTH-010", Version: 1, Area: AreaAuth, Name: "Compromised legitimate sender",
		PrimaryObjective: "Detect suspicious content from an authenticated sender",
		Limitations:      "genuine gap: no scenario builder exists; shares unbuilt plumbing with PH-BEC-006 (reply-chain hijacking)",
		Coverage:         CoverageCatalogOnly}
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

// phBEC003/phBEC007 are overlap decisions: phishing.txt's own narrative
// framing for invoice/payment diversion and urgent wire-transfer requests
// both exercise the identical control evidence PH-BEC-002 already proves
// (SupplierPaymentDiversionExpectation's domain-reputation/newly-observed-
// domain heuristic). phishing.txt's own "Adversarial variant engine"
// capability (#3, P0) is the correct home for distinguishing these by
// narrative/urgency framing without duplicating the implementation --
// deferred to Phase 4, not built here.
func phBEC003() Scenario {
	return Scenario{ID: "PH-BEC-003", Version: 1, Area: AreaBEC, Name: "Invoice and payment diversion",
		PrimaryObjective: "Test financial-fraud detection",
		Limitations:      "overlap decision: narrative variant of PH-BEC-002's underlying control test; a dedicated variant-matrix implementation is deferred to Phase 4, not yet a verified independent scenario",
		Coverage:         CoverageCatalogOnly}
}

func phBEC007() Scenario {
	return Scenario{ID: "PH-BEC-007", Version: 1, Area: AreaBEC, Name: "Urgent wire-transfer request",
		PrimaryObjective: "Validate payment-fraud signals and escalation",
		Limitations:      "overlap decision: narrative variant of PH-BEC-002's underlying control test; a dedicated variant-matrix implementation is deferred to Phase 4, not yet a verified independent scenario",
		Coverage:         CoverageCatalogOnly}
}

// phBEC004/005/006/008: genuine, unbuilt gaps confirmed by Phase 0
// research.
func phBEC004() Scenario {
	return Scenario{ID: "PH-BEC-004", Version: 1, Area: AreaBEC, Name: "Payroll and HR impersonation",
		PrimaryObjective: "Validate sensitive-data request controls",
		Limitations:      "genuine gap: no scenario builder exists", Coverage: CoverageCatalogOnly}
}

func phBEC005() Scenario {
	return Scenario{ID: "PH-BEC-005", Version: 1, Area: AreaBEC, Name: "Procurement and purchase-order fraud",
		PrimaryObjective: "Test supplier and purchasing workflows",
		Limitations:      "genuine gap: no scenario builder exists", Coverage: CoverageCatalogOnly}
}

func phBEC006() Scenario {
	return Scenario{ID: "PH-BEC-006", Version: 1, Area: AreaBEC, Name: "Reply-chain hijacking",
		PrimaryObjective: "Detect suspicious activity in an existing conversation",
		Limitations:      "genuine gap: no scenario builder exists; shares unbuilt plumbing with PH-AUTH-010",
		Coverage:         CoverageCatalogOnly}
}

func phBEC008() Scenario {
	return Scenario{ID: "PH-BEC-008", Version: 1, Area: AreaBEC, Name: "Customer or partner impersonation",
		PrimaryObjective: "Test trusted external relationship abuse",
		Limitations:      "genuine gap: no scenario builder exists", Coverage: CoverageCatalogOnly}
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

func phEVA002() Scenario {
	return Scenario{ID: "PH-EVA-002", Version: 1, Area: AreaEvasionDetectionIR, Name: "Inbound relay-path bypass",
		PrimaryObjective: "Validate inspection across alternate delivery paths",
		Limitations:      "shares PH-AUTH-007's unbuilt internal-relay/HELO scenario-builder gap",
		Coverage:         CoverageCatalogOnly}
}

// phID001 is a genuine gap AT THIS BRIDGE LAYER only: exercise/tracker's
// HandleCredSubmit/HandleReport genuinely capture this evidence today
// (real, DB-backed), but as write-only DB events via the Recorder
// interface, not a typed in-memory value phishbridge's current
// I/O-free design can read back. A read-side query (e.g. an
// exercise.Store accessor returning typed evidence for an execution ID)
// does not exist yet -- a real, named gap, not a silent omission.
func phID001() Scenario {
	return Scenario{ID: "PH-ID-001", Version: 1, Area: AreaURLCredentialIdentity, Name: "Credential-harvesting simulation",
		PrimaryObjective: "Measure controls without collecting real credentials",
		Limitations:      "exercise/tracker/credential.go already records only the fact of submission, never credential values, matching this objective -- but as a write-only DB event with no typed read-side accessor yet, phishbridge cannot translate it into phishval.Observation without new plumbing in exercise.Store. Deferred.",
		Coverage:         CoverageCatalogOnly}
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

func phATT002() Scenario {
	return Scenario{ID: "PH-ATT-002", Version: 1, Area: AreaAttachment, Name: "PDF with embedded link",
		PrimaryObjective: "Test content and URL inspection",
		Limitations:      "genuine gap: no PDF-specific scenario builder exists", Coverage: CoverageCatalogOnly}
}

func phATT003() Scenario {
	return Scenario{ID: "PH-ATT-003", Version: 1, Area: AreaAttachment, Name: "Office document with external link",
		PrimaryObjective: "Validate document and link controls",
		Limitations:      "genuine gap: no Office-document-specific scenario builder exists", Coverage: CoverageCatalogOnly}
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
		phBEC001(), phBEC003(), phBEC004(), phBEC005(), phBEC006(), phBEC007(), phBEC008(),
		phURL001(), phURL005(), phID001(),
		phEVA001(), phEVA002(), phEVA005(),
		phATT001(), phATT002(), phATT003(), phATT010(),
	}
	if err := ValidateCatalog(all); err != nil {
		return nil, err
	}
	return all, nil
}
