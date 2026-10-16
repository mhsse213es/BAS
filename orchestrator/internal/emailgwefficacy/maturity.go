package emailgwefficacy

import "slices"

// ScenarioMaturity is a scenario's own build/verification maturity --
// a different axis from EmailGWVerdict, which describes a single
// run's outcome, not whether the scenario has ever been proven to
// execute meaningfully at all. Always computed from real recorded
// ScenarioExecutionRecords (see ClassifyScenarioMaturity/
// BuildScenarioMaturityReport) -- never hand-declared. This package's
// own Coverage Matrix (docs/superpowers/specs/2026-10-15-emailgw-
// mastery-architecture-design.md §5) went stale twice already from a
// hand-maintained status; a maturity model with the same failure mode
// would be worse, since "verified" is a stronger claim than a
// coverage row.
type ScenarioMaturity string

const (
	// MaturityNotImplemented: no scenario registry entry (and
	// therefore no builder) exists for this EG-ID at all.
	MaturityNotImplemented ScenarioMaturity = "not-implemented"
	// MaturityImplementedNotExecutable: a registry entry/builder
	// exists, but no execution was ever even attempted for any of its
	// required expectation IDs -- a builder's existence alone never
	// establishes that its execution path works.
	MaturityImplementedNotExecutable ScenarioMaturity = "implemented-not-executable"
	// MaturityExecutedWithoutEvidence: at least one execution was
	// attempted, but no qualifying record exists for every required
	// expectation ID -- e.g. only fixture-backed records exist, or a
	// live attempt returned Inconclusive/NotTested, or its provenance
	// was Inferred rather than Observed.
	MaturityExecutedWithoutEvidence ScenarioMaturity = "executed-without-sufficient-evidence"
	// MaturityVerifiedThroughExecution: every required expectation ID
	// (or, for a correlation-dependent scenario, one single joint
	// execution) has a qualifying record: produced via the real
	// adapter code path (ViaLiveAdapter), a definitive verdict
	// (ConfirmedSuccess or ConfirmedFailure -- a definitive failure
	// verifies a weakness exists; it does not mean the control
	// passed), and Observed (not Inferred) provenance. This is proof
	// through the real adapter's HTTP/JSON code path (httptest-backed
	// or a real tenant) -- it is NOT proof of effectiveness against an
	// actual customer M365 tenant, which remains separately tracked
	// (docs/emailgw-mastery-qa-log.md item #1b) and is never implied
	// by this state.
	MaturityVerifiedThroughExecution ScenarioMaturity = "verified-through-execution"
)

// ScenarioExecutionRecord is one real, recorded attempt to verify a
// specific scenario expectation's dimension -- built directly from an
// actual VerifyMailExpectation (EfficacyResult) or
// VerifyInboxRuleExpectation (bare VerdictDetail) call elsewhere in
// this package's own test suite. maturity.go never synthesizes or
// invents one; a test that wants a scenario to classify as verified
// must actually run it through the real adapter and report what
// happened, not what it hoped would happen.
type ScenarioExecutionRecord struct {
	// ExpectationID matches one of the IDs in the owning
	// ScenarioRegistryEntry.ExpectationIDs.
	ExpectationID string
	// CorrelationKey groups records produced from the same underlying
	// execution event (e.g. one VerifyMailExpectation call backed by
	// one real Graph alert) -- required for a RequiresCorrelation
	// entry (EG-010: its Detection and Response records must share a
	// CorrelationKey, proving they came from the same alert rather
	// than two independently-fabricated fixtures), optional otherwise.
	CorrelationKey string
	// Verdict is the actual VerdictDetail this execution produced for
	// this expectation's relevant dimension (Prevention/
	// DetectionVerdict/ResponseVerdict, or an InboxRuleExpectation's
	// own single VerdictDetail) -- copied from the real result, never
	// constructed to make a test pass.
	Verdict VerdictDetail
	// Provenance is the backing evidence record's own Provenance
	// (e.g. the latest EnforcementEvidence/DetectionEvidence/
	// ResponseEvidence/InboxRuleEvidence that determined Verdict) --
	// Kind must be ProvenanceObserved for this record to qualify as
	// sufficient evidence; ProvenanceInferred is a weaker claim this
	// classifier never treats as proof of verification.
	Provenance Provenance
	// ViaLiveAdapter is true only when this record was produced
	// through the real adapter code path (DefenderMailEvidenceProvider
	// or equivalent) -- httptest-backed or a real tenant -- never a
	// bare FixtureMailEvidenceProvider/FixtureInboxRuleProvider, which
	// exercises no real HTTP/JSON parsing code at all.
	ViaLiveAdapter bool
}

// ScenarioRegistryEntry is one EG-ID's own build-time identity: which
// expectation variants it needs verified, and whether they must be
// jointly correlated (EG-010) rather than each independently
// sufficient. This table never declares a maturity status itself --
// only ClassifyScenarioMaturity, fed by real ScenarioExecutionRecords,
// computes that; adding or renaming an expectation here changes
// nothing about any scenario's reported maturity by itself.
type ScenarioRegistryEntry struct {
	ScenarioID string
	Name       string
	// ExpectationIDs: every expectation variant that must each
	// independently have a qualifying record (or, if
	// RequiresCorrelation, that must appear together under one
	// CorrelationKey) for this EG-ID to be MaturityVerifiedThroughExecution.
	// Both the known-good and known-bad direction of every scenario
	// builder that takes one are listed separately -- this package's
	// own scenarios.go states the underlying principle directly: "a
	// harness that can't prove both a pass and a fail is not yet
	// trustworthy." A maturity model that accepted proof of only one
	// direction would fall short of that same bar.
	ExpectationIDs []string
	// RequiresCorrelation: true only for a scenario whose own claim is
	// that two dimensions resolve from the SAME underlying evidence
	// (EG-010's detection-to-response chain) -- ExpectationIDs are
	// then combined under one CorrelationKey, not independently
	// sufficient.
	RequiresCorrelation bool
}

// EmailGWScenarioRegistry is the static EG-ID -> expectation-identity
// table for every scenario that currently has a builder. An EG-ID
// absent from this slice is MaturityNotImplemented by
// BuildScenarioMaturityReport's own construction -- see
// AllEmailGWScenarioIDs. EG-007 is registered like every other
// scenario (it is implemented), but currently has no real adapter at
// all -- only FixtureInboxRuleProvider exists, no live-backed
// InboxRuleEvidenceProvider -- so it structurally can never reach
// MaturityVerifiedThroughExecution under this classifier until a real
// adapter is built; that is this model surfacing a genuine gap, not a
// defect in the model.
func EmailGWScenarioRegistry() []ScenarioRegistryEntry {
	return []ScenarioRegistryEntry{
		{
			ScenarioID: "EG-001", Name: "Domain spoofing (SPF/DKIM/DMARC)",
			ExpectationIDs: []string{
				"EG-001.spf.known-good", "EG-001.spf.known-bad",
				"EG-001.dkim.known-good", "EG-001.dkim.known-bad",
				"EG-001.dmarc.known-good", "EG-001.dmarc.known-bad",
			},
		},
		{
			ScenarioID: "EG-002", Name: "Executive impersonation",
			ExpectationIDs: []string{"EG-002.known-good", "EG-002.known-bad"},
		},
		{
			ScenarioID: "EG-003", Name: "Credential phishing (URL harvesting + URL rewrite)",
			ExpectationIDs: []string{
				"EG-003.credential-url.known-good", "EG-003.credential-url.known-bad",
				"EG-003.url-rewrite.known-good", "EG-003.url-rewrite.known-bad",
			},
		},
		{
			ScenarioID: "EG-004", Name: "Malicious attachment (EICAR)",
			ExpectationIDs: []string{"EG-004.known-good", "EG-004.known-bad"},
		},
		{
			ScenarioID: "EG-005", Name: "Supplier payment diversion",
			ExpectationIDs: []string{"EG-005.known-good", "EG-005.known-bad"},
		},
		{
			ScenarioID: "EG-006", Name: "Sensitive-data leakage (outbound DLP)",
			ExpectationIDs: []string{"EG-006.known-good", "EG-006.known-bad"},
		},
		{
			ScenarioID: "EG-007", Name: "External auto-forwarding",
			ExpectationIDs: []string{"EG-007.known-good", "EG-007.known-bad"},
		},
		{
			ScenarioID: "EG-008", Name: "Post-delivery threat response",
			ExpectationIDs: []string{"EG-008.known-good", "EG-008.known-bad"},
		},
		{
			ScenarioID: "EG-009", Name: "Authentication exception scope",
			ExpectationIDs: []string{"EG-009.known-good", "EG-009.known-bad"},
		},
		{
			ScenarioID: "EG-010", Name: "Detection-to-response chain",
			ExpectationIDs:      []string{"EG-010.detection", "EG-010.response"},
			RequiresCorrelation: true,
		},
	}
}

// AllEmailGWScenarioIDs is the full client-facing catalogue, EG-001
// through EG-010, independent of whether a registry entry currently
// exists for each -- BuildScenarioMaturityReport iterates this list,
// not the registry, so a genuinely not-implemented scenario still
// gets a reported row instead of silently vanishing from the report.
func AllEmailGWScenarioIDs() []string {
	return []string{
		"EG-001", "EG-002", "EG-003", "EG-004", "EG-005",
		"EG-006", "EG-007", "EG-008", "EG-009", "EG-010",
	}
}

// qualifies reports whether a single record is, by itself, sufficient
// evidence of verification: produced via the real adapter, a
// definitive verdict (either ConfirmedSuccess or ConfirmedFailure --
// a definitive failure verifies that a weakness exists; it is not
// read as the control having passed), and Observed provenance. Any
// other combination -- fixture-only, Inconclusive, NotTested, or
// Inferred provenance -- fails closed.
func qualifies(r ScenarioExecutionRecord) bool {
	if !r.ViaLiveAdapter {
		return false
	}
	if r.Verdict.Verdict != VerdictConfirmedSuccess && r.Verdict.Verdict != VerdictConfirmedFailure {
		return false
	}
	return r.Provenance.Kind == ProvenanceObserved
}

// anyQualifies reports whether at least one record in records
// qualifies.
func anyQualifies(records []ScenarioExecutionRecord) bool {
	return slices.ContainsFunc(records, qualifies)
}

// correlatedDefinitive reports whether some single CorrelationKey
// groups a qualifying record for every one of ids -- EG-010's own
// requirement that Detection and Response resolve from the SAME
// underlying evidence, not two independently-fabricated fixtures that
// merely happen to both be definitive.
func correlatedDefinitive(ids []string, records []ScenarioExecutionRecord) bool {
	byKey := map[string]map[string]bool{}
	for _, r := range records {
		if r.CorrelationKey == "" || !qualifies(r) {
			continue
		}
		if byKey[r.CorrelationKey] == nil {
			byKey[r.CorrelationKey] = map[string]bool{}
		}
		byKey[r.CorrelationKey][r.ExpectationID] = true
	}
	for _, present := range byKey {
		allPresent := true
		for _, id := range ids {
			if !present[id] {
				allPresent = false
				break
			}
		}
		if allPresent {
			return true
		}
	}
	return false
}

// ClassifyScenarioMaturity computes entry's maturity from records --
// never from entry alone, and never from whether a Go test happened
// to pass. Fails closed at every step: a missing attempt, a missing
// qualifying record, or (for a correlation entry) records that
// qualify individually but were never produced together all land on
// a state short of MaturityVerifiedThroughExecution.
func ClassifyScenarioMaturity(entry ScenarioRegistryEntry, records []ScenarioExecutionRecord) ScenarioMaturity {
	byExpectation := map[string][]ScenarioExecutionRecord{}
	for _, r := range records {
		byExpectation[r.ExpectationID] = append(byExpectation[r.ExpectationID], r)
	}

	anyAttempted := false
	for _, id := range entry.ExpectationIDs {
		if len(byExpectation[id]) > 0 {
			anyAttempted = true
			break
		}
	}
	if !anyAttempted {
		return MaturityImplementedNotExecutable
	}

	if entry.RequiresCorrelation {
		if correlatedDefinitive(entry.ExpectationIDs, records) {
			return MaturityVerifiedThroughExecution
		}
		return MaturityExecutedWithoutEvidence
	}

	for _, id := range entry.ExpectationIDs {
		if !anyQualifies(byExpectation[id]) {
			return MaturityExecutedWithoutEvidence
		}
	}
	return MaturityVerifiedThroughExecution
}

// ScenarioMaturityEntry is one row of BuildScenarioMaturityReport's
// output.
type ScenarioMaturityEntry struct {
	ScenarioID string
	Name       string
	Maturity   ScenarioMaturity
}

// BuildScenarioMaturityReport classifies every EG-ID in
// AllEmailGWScenarioIDs against registry and records, in catalogue
// order. An EG-ID with no matching registry entry is reported
// MaturityNotImplemented with no Name -- it never silently vanishes
// from the report the way a row could from a hand-maintained table.
func BuildScenarioMaturityReport(registry []ScenarioRegistryEntry, records []ScenarioExecutionRecord) []ScenarioMaturityEntry {
	byID := map[string]ScenarioRegistryEntry{}
	for _, e := range registry {
		byID[e.ScenarioID] = e
	}

	out := make([]ScenarioMaturityEntry, 0, len(AllEmailGWScenarioIDs()))
	for _, id := range AllEmailGWScenarioIDs() {
		entry, ok := byID[id]
		if !ok {
			out = append(out, ScenarioMaturityEntry{ScenarioID: id, Maturity: MaturityNotImplemented})
			continue
		}
		out = append(out, ScenarioMaturityEntry{
			ScenarioID: id,
			Name:       entry.Name,
			Maturity:   ClassifyScenarioMaturity(entry, records),
		})
	}
	return out
}
