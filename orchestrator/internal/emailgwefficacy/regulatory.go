package emailgwefficacy

import "time"

// RegulatoryObligation is one regulatory requirement from a named
// jurisdiction's regulator, together with the single EmailGW
// capability (ControlLabel, a plain string tag -- never an imported
// type) that evidences it. This package has zero Go dependency on
// internal/regobligation; it imitates that package's PATTERN
// (immutable evidence snapshots, versioned obligations) without
// importing its types -- the same independence webgwefficacy already
// keeps, and the same independence this package keeps from
// webgwefficacy itself (its own regulatory.go is not imported here;
// this is a parallel, independent copy of the pattern, per the
// architecture spec's own "pattern not types" lock).
type RegulatoryObligation struct {
	ID              string    `json:"id"`
	Jurisdiction    string    `json:"jurisdiction"`
	Regulator       string    `json:"regulator"`
	Title           string    `json:"title"`
	SourceReference string    `json:"sourceReference"`
	Version         string    `json:"version"`
	EffectiveDate   time.Time `json:"effectiveDate"`
	ControlLabel    string    `json:"controlLabel"`
	Note            string    `json:"note,omitempty"`
}

// ObligationSnapshotStatus distinguishes a snapshot that genuinely
// captured a scenario's verdict from one that could not -- the same
// "nothing here means inconclusive, not failing" discipline this
// package already applies everywhere else.
type ObligationSnapshotStatus string

const (
	ObligationSnapshotCaptured   ObligationSnapshotStatus = "captured"
	ObligationSnapshotIncomplete ObligationSnapshotStatus = "incomplete"
)

// ObligationEvidenceSnapshot is an immutable, point-in-time record
// that a specific emailgwefficacy scenario's own verdict was captured
// as evidence for a regulatory obligation. It is never re-executed or
// re-derived -- only ever created fresh by
// MapObligationToScenarioEvidence.
type ObligationEvidenceSnapshot struct {
	ObligationID    string                   `json:"obligationId"`
	ScenarioLabel   string                   `json:"scenarioLabel"`
	CapturedVerdict EmailGWVerdict           `json:"capturedVerdict"`
	Status          ObligationSnapshotStatus `json:"status"`
	CapturedAt      time.Time                `json:"capturedAt"`
}

// MapObligationToScenarioEvidence captures one already-computed
// scenario verdict as an immutable evidence snapshot for the given
// obligation. capturedAt is an explicit parameter, never time.Now()
// read internally, matching VerifyMailExpectation's own determinism
// discipline. Inconclusive or NotTested is captured as Incomplete,
// never silently treated as if the obligation had been proven met.
// ConfirmedFailure, ConfirmedSuccess, and NotApplicable are each
// Captured -- all three are definitive conclusions (a failed control
// is a genuine finding, not missing evidence; NotApplicable is a
// deliberate, justified exclusion, not an absence of one).
func MapObligationToScenarioEvidence(
	obligation RegulatoryObligation,
	scenarioLabel string,
	verdict EmailGWVerdict,
	capturedAt time.Time,
) ObligationEvidenceSnapshot {
	status := ObligationSnapshotCaptured
	if verdict == VerdictInconclusive || verdict == VerdictNotTested {
		status = ObligationSnapshotIncomplete
	}
	return ObligationEvidenceSnapshot{
		ObligationID:    obligation.ID,
		ScenarioLabel:   scenarioLabel,
		CapturedVerdict: verdict,
		Status:          status,
		CapturedAt:      capturedAt,
	}
}

// IndiaRBISecureMailObligation is India's seed obligation (one per
// jurisdiction is this phase's own bar, matching WebGW Mastery's and
// Network BAS's identical minimal-seed precedent). Sourced from the
// RBI's current commercial-bank cybersecurity directions -- NOT the
// 2016 Cyber Security Framework circular (RBI/2015-16/418) WebGW
// Mastery's own regulatory.go cites, which multiple convergent
// secondary sources report as repealed effective 31 July 2026 by this
// newer directions document. That staleness was found during this
// package's own Phase 5 research and is flagged here for visibility;
// webgwefficacy's own entry was not revisited as part of this work.
func IndiaRBISecureMailObligation() RegulatoryObligation {
	return RegulatoryObligation{
		ID:           "rbi-cybersecurity-directions-2026-secure-mail",
		Jurisdiction: "India",
		Regulator:    "RBI (Reserve Bank of India)",
		Title:        "Secure mail and messaging systems -- DMARC/SPF/DKIM for bank email domains, anti-spoofing and anti-phishing controls",
		SourceReference: "Reserve Bank of India (Commercial Banks -- Cybersecurity, Technology: Risk, Resilience and Assurance Framework) Directions, 2026, " +
			"RBI/DoS/2026-27/410, DoS.CO.CSITEG.4/31.01.015/2026-27, dated 31 July 2026, \"Secure Mail and Messaging Systems\" section. " +
			"Secondary compliance-vendor sources place the DMARC requirement around paragraphs 116-120 but disagree on the exact number; " +
			"this session could not independently confirm the paragraph against RBI's own published PDF (a scanned document behind a " +
			"CAPTCHA gate, with no extractable text layer) -- the document's existence, title, reference number, and date are corroborated " +
			"across multiple independent secondary sources, but the specific paragraph number is not.",
		Version:       "2026",
		EffectiveDate: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
		ControlLabel:  "emailgwefficacy.SPFAlignmentExpectation/DKIMAlignmentExpectation/DMARCPolicyExpectation",
		Note: "Supersedes the 2016 RBI Cyber Security Framework circular webgwefficacy's own regulatory.go still cites -- a cross-cutting " +
			"staleness finding, not an EmailGW-specific one, surfaced here for visibility rather than silently left for that package's own review.",
	}
}

// UAECBUAEEmailSpoofingObligation is UAE's seed obligation.
func UAECBUAEEmailSpoofingObligation() RegulatoryObligation {
	return RegulatoryObligation{
		ID:           "cbuae-digital-impersonation-email-spoofing",
		Jurisdiction: "UAE",
		Regulator:    "CBUAE (Central Bank of the United Arab Emirates)",
		Title:        "Digital impersonation risk assessment -- SPF/DKIM/DMARC enforcement (reject/quarantine) for consumer-facing email domains",
		SourceReference: "CBUAE Brand Protection and Digital Impersonation guidance, issued under Article 149 of Federal Decree-Law No. 6 of 2025, " +
			"dated February 2026, requiring UAE Licensed Financial Institutions to complete a first digital impersonation risk assessment " +
			"(email spoofing among 8 named channels) before 30 June 2026 with annual updates thereafter. Secondary/vendor sources report a " +
			"clause (numbered 5.2 by one source, unconfirmed) requiring full DMARC/DKIM/SPF enforcement including reject/quarantine policies " +
			"for consumer-facing domains and hardening of non-sending domains. Neither the exact clause number nor its verbatim text was " +
			"independently verified against CBUAE's own primary publication -- not located in this session's research.",
		Version:       "2026",
		EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), // month of issuance reported; exact day unconfirmed
		ControlLabel:  "emailgwefficacy.SPFAlignmentExpectation/DKIMAlignmentExpectation/DMARCPolicyExpectation",
		Note:          "The first risk-assessment deadline (30 June 2026) has already passed as of this writing (2026-10-15) -- this obligation documents an existing, currently-binding requirement, not a future one.",
	}
}
