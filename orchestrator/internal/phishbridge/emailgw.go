// Package phishbridge is the one-way translation layer from already-shipped
// domain packages (internal/emailgwefficacy today; internal/exercise,
// future identity/IR adapters in later phases) into internal/phishval's
// independent outcome model. It depends on phishval and on whichever
// domain package it is translating FROM; those packages never depend on
// it -- same one-way shape internal/adcontrolval already demonstrates for
// internal/controlval, applied here per
// docs/superpowers/specs/2026-10-18-phishing-bas-mastery-phase0-roadmap-design.md
// §1.1 (corrected in internal/phishval's own package comment: the
// translation is a bridge INTO phishval's own independent taxonomy, not
// into internal/controlval).
//
// This package reads emailgwefficacy.EfficacyResult, a value already fully
// computed by emailgwefficacy.VerifyMailExpectation; it performs no I/O
// and never re-derives a verdict emailgwefficacy itself already decided.
package phishbridge

import (
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// mapAction translates emailgwefficacy's raw observed mail action (the
// ExpectedMailAction string vocabulary: "deliver" | "quarantine" |
// "reject" | "rewrite-link" | "encrypt" | "tag-warning") into phishval's
// two independent dimensions it drives for an email-gateway scenario:
// the literal transport disposition (Delivery) and the control's
// enforcement posture (Enforcement). For email specifically these two
// dimensions are driven by the SAME underlying action -- quarantining a
// message both disposes of it in transport AND is the control's
// enforcement decision -- unlike, say, a URL-rewrite, which still
// delivers the message (Delivery) while only challenging the later click
// (Enforcement).
func mapAction(action string) (phishval.DeliveryOutcome, phishval.EnforcementOutcome) {
	switch action {
	case "deliver":
		return phishval.DeliveryDelivered, phishval.EnforcementAllowed
	case "quarantine":
		return phishval.DeliveryQuarantined, phishval.EnforcementBlocked
	case "reject":
		return phishval.DeliveryRejected, phishval.EnforcementBlocked
	case "rewrite-link":
		return phishval.DeliveryDelivered, phishval.EnforcementChallenged
	case "encrypt", "tag-warning":
		return phishval.DeliveryDelivered, phishval.EnforcementAllowed
	default:
		return phishval.DeliveryUnknown, phishval.EnforcementUnknown
	}
}

// mapEvidenceQuality translates emailgwefficacy's EvidenceSource +
// Provenance.Kind into phishval's single EvidenceQuality axis.
// SourceSynthetic (test-constructed input, never a real product
// observation) maps alongside SourceFixture into EvidenceFixture --
// phishval has no separate "synthetic" value, and both are, from a
// Phishing BAS consumer's point of view, not a real control's own
// observation.
func mapEvidenceQuality(source emailgwefficacy.EvidenceSource, kind emailgwefficacy.ProvenanceKind) phishval.EvidenceQuality {
	switch {
	case source == emailgwefficacy.SourceLive && kind == emailgwefficacy.ProvenanceObserved:
		return phishval.EvidenceVerifiedTelemetry
	case source == emailgwefficacy.SourceLive && kind == emailgwefficacy.ProvenanceInferred:
		return phishval.EvidenceInferred
	case source == emailgwefficacy.SourceFixture, source == emailgwefficacy.SourceSynthetic:
		return phishval.EvidenceFixture
	default:
		return phishval.EvidenceMissing
	}
}

// mapConfidence translates emailgwefficacy.Confidence (3 values) into
// phishval.Confidence (4 values, with an explicit "insufficient_evidence"
// phishval itself can set independently -- this function only ever
// produces one of the 3 shared values).
func mapConfidence(c emailgwefficacy.Confidence) phishval.Confidence {
	switch c {
	case emailgwefficacy.ConfidenceHigh:
		return phishval.ConfidenceHigh
	case emailgwefficacy.ConfidenceMedium:
		return phishval.ConfidenceMedium
	case emailgwefficacy.ConfidenceLow:
		return phishval.ConfidenceLow
	default:
		return phishval.ConfidenceLow
	}
}

// latestEnforcement, latestDetection, latestResponse pick the
// chronologically latest record from an EfficacyResult's own evidence
// slices -- a local equivalent of emailgwefficacy's private
// latestByTimestamp helper, which this package cannot import. Every
// existing FixtureMailEvidenceProvider usage in this codebase returns at
// most one matching record per message/window, so ties never arise in
// practice today; a provider returning multiple conflicting records for
// the same message is a known limitation carried over from
// emailgwefficacy itself, not newly introduced here.
func latestEnforcement(records []emailgwefficacy.EnforcementEvidence) (emailgwefficacy.EnforcementEvidence, bool) {
	if len(records) == 0 {
		return emailgwefficacy.EnforcementEvidence{}, false
	}
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	return latest, true
}

func latestDetection(records []emailgwefficacy.DetectionEvidence) (emailgwefficacy.DetectionEvidence, bool) {
	if len(records) == 0 {
		return emailgwefficacy.DetectionEvidence{}, false
	}
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	return latest, true
}

func latestResponse(records []emailgwefficacy.ResponseEvidence) (emailgwefficacy.ResponseEvidence, bool) {
	if len(records) == 0 {
		return emailgwefficacy.ResponseEvidence{}, false
	}
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	return latest, true
}

// FromEmailGWEfficacyResult translates r into phishval's Observation
// shape. UserInteraction is always nil: emailgwefficacy models no human
// interaction dimension, and this bridge never fabricates one.
//
// Delivery/Enforcement are populated only when r.Enforcement has at
// least one record -- mirroring emailgwefficacy.VerifyMailExpectation's
// own "absence of evidence is not proof" discipline, carried into
// phishval as a nil Observation (which EvaluateDelivery/EvaluateEnforcement
// grade as NotTested, never as a fabricated Fail).
//
// Detection/Response are populated only when r.DetectionVerdict/
// r.ResponseVerdict is NOT VerdictInconclusive: emailgwefficacy's own
// Inconclusive for these two dimensions means "no evidence was found in
// the window" (verifyDetection/verifyResponse's own doc comments), the
// same condition phishval's NotTested already models -- so a nil
// Observation here is the MORE accurate translation, not a
// simplification: phishval's own DetectionInconclusive/collection-error
// case stays reserved for a provider that was actually queried and
// returned an ambiguous (not absent) answer, which emailgwefficacy's
// VerdictDetail does not currently distinguish from "nothing found" at
// this result's own granularity.
func FromEmailGWEfficacyResult(r emailgwefficacy.EfficacyResult) phishval.Observation {
	var obs phishval.Observation

	if latest, ok := latestEnforcement(r.Enforcement); ok {
		delivery, enforcement := mapAction(latest.Action)
		quality := mapEvidenceQuality(latest.Source, latest.Provenance.Kind)
		confidence := mapConfidence(latest.Provenance.Confidence)
		obs.Delivery = &phishval.DeliveryObservation{
			Outcome: delivery, Timestamp: latest.Timestamp, Source: latest.ControlProduct,
			Evidence: quality, Confidence: confidence, Detail: latest.PolicyRule,
		}
		obs.Enforcement = &phishval.EnforcementObservation{
			Outcome: enforcement, ControlProduct: latest.ControlProduct, PolicyRule: latest.PolicyRule,
			Timestamp: latest.Timestamp, Source: latest.ControlProduct, Evidence: quality, Confidence: confidence,
		}
	}

	if r.DetectionVerdict.Verdict != emailgwefficacy.VerdictInconclusive {
		if latest, ok := latestDetection(r.Detection); ok {
			outcome := phishval.DetectionNotDetectedWithinWindow
			if latest.AlertGenerated {
				outcome = phishval.DetectionDetected
			}
			obs.Detection = &phishval.DetectionObservation{
				Outcome: outcome, Product: latest.Product, Rule: latest.Rule, CorrelationID: latest.CorrelationID,
				Timestamp: latest.Timestamp, Source: latest.Product,
				Evidence:         mapEvidenceQuality(latest.Source, latest.Provenance.Kind),
				Confidence:       mapConfidence(latest.Provenance.Confidence),
				SearchedComplete: true,
			}
		}
	}

	if r.ResponseVerdict.Verdict != emailgwefficacy.VerdictInconclusive {
		if latest, ok := latestResponse(r.Response); ok {
			outcome := phishval.ResponseFailed
			if latest.Completed {
				outcome = phishval.ResponseRemediated
			}
			obs.Response = &phishval.ResponseObservation{
				Outcome: outcome, ActionRequired: latest.ActionRequired, DurationToComplete: latest.DurationToComplete,
				CorrelationID: latest.CorrelationID, Timestamp: latest.Timestamp, Source: "emailgw",
				Evidence:   mapEvidenceQuality(latest.Source, latest.Provenance.Kind),
				Confidence: mapConfidence(latest.Provenance.Confidence),
			}
		}
	}

	return obs
}
